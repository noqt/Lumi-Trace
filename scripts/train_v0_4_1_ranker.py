# SPDX-License-Identifier: Apache-2.0
"""Assemble and train the governed V0.4.1 Stage C ranker.

Raw rankings and requests come from the label-blind F: builder.  Private
training labels are revealed only in this G:-rooted trainer, after each raw
output seal verifies.  The resulting JSON model is verified before a
read-only inference copy is placed in the F: builder model store.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Any

from lumi_trace.canonical import (
    dump_json as product_dump_json,
)
from lumi_trace.canonical import (
    load_json as product_load_json,
)
from lumi_trace.canonical import (
    sha256_file as product_sha256_file,
)
from lumi_trace.learned_ranker import (
    BASE_RANKER,
    feature_vector,
    verify_model_artifact,
)
from lumi_trace.localization import (
    V041_EVIDENCE_RUNTIME_IDENTITY as RUNTIME_IDENTITY,
)
from lumi_trace.localization import (
    validate_inference_request,
    verify_raw_localization,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = PROJECT_ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import dump_json, load_json, stable_id  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.integrity_v041 import verify_scoring_labels  # noqa: E402
from trace_eval.learned_v041 import (  # noqa: E402
    LearnedTrainingConfig,
    train_integer_pairwise_ranker,
)

PARTITION = "training"
TIMESTAMP = "2026-07-26T00:00:00Z"


def _root(path: Path, drive: str, *, create: bool = False) -> Path:
    resolved = path.resolve(strict=not create)
    if resolved.drive.casefold() != drive.casefold():
        raise ValueError(f"path must remain on {drive}")
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError(f"required root is missing: {resolved}")
    return resolved


def _write_once(path: Path, value: Any) -> None:
    if path.exists():
        if load_json(path) != value:
            raise ContractError(f"append-only artifact differs: {path.name}")
        return
    dump_json(path, value)


def _target_ids(
    candidates: list[dict[str, Any]],
    labels: dict[str, Any],
) -> set[str]:
    exact = {
        (target["path"], target.get("symbol"))
        for target in labels["targets"]
        if target.get("symbol")
    }
    file_only = {target["path"] for target in labels["targets"] if not target.get("symbol")}
    return {
        candidate["candidate_id"]
        for candidate in candidates
        if (candidate["path"], candidate.get("symbol")) in exact
        or (candidate["path"] in file_only and candidate["kind"] == "file")
    }


def _select_training_candidates(
    candidates: list[dict[str, Any]],
    labels: dict[str, Any],
    *,
    maximum: int,
) -> tuple[list[dict[str, Any]], set[str]]:
    positives = _target_ids(candidates, labels)
    if not positives:
        return [], set()
    target_paths = {item["path"] for item in labels["targets"]}
    hard_paths = set(labels["hard_negative_paths"])
    by_priority = [
        [item for item in candidates if item["candidate_id"] in positives],
        [
            item
            for item in candidates
            if item["candidate_id"] not in positives and item["path"] in target_paths
        ],
        [
            item
            for item in candidates
            if item["candidate_id"] not in positives and item["path"] in hard_paths
        ],
        [item for item in candidates if item["candidate_id"] not in positives],
    ]
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lane in by_priority:
        for candidate in lane:
            if candidate["candidate_id"] in seen:
                continue
            selected.append(candidate)
            seen.add(candidate["candidate_id"])
            if len(selected) >= maximum:
                return selected, positives
    return selected, positives


def build_groups_and_train(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _root(args.private_root, "G:")
    work_root = _root(args.work_root, "F:")
    predecessor = _root(args.predecessor_root, "G:")
    manifest = load_json(predecessor / "partitions" / PARTITION / "manifest-final.json")
    allowlist = set(manifest["audit_card_ids"])
    score_root = private_root / "scorer" / "results" / PARTITION / args.base_ranker
    raw_root = work_root / "builder" / "raw" / PARTITION / args.base_ranker
    request_root = work_root / "builder" / "requests" / PARTITION
    label_root = private_root / "scorer" / "labels" / PARTITION
    if not score_root.is_dir() or not raw_root.is_dir():
        raise PolicyError("V0_4_1_REGENERATED_TRAINING_OUTPUTS_MISSING")

    groups: list[dict[str, Any]] = []
    exclusions: list[dict[str, str]] = []
    for score_path in sorted(score_root.glob("*.json")):
        score = load_json(score_path)
        if (
            score.get("runtime_identity") != RUNTIME_IDENTITY
            or score.get("audit_card_id") not in allowlist
        ):
            continue
        raw_path = raw_root / score_path.name
        request_path = request_root / score_path.name
        group_token = score_path.name.split(".", 1)[0]
        label_path = label_root / f"{group_token}.json"
        if not raw_path.is_file() or not request_path.is_file() or not label_path.is_file():
            raise ContractError("training builder/scorer join is incomplete")
        raw = verify_raw_localization(product_load_json(raw_path))
        if raw["raw_output_seal"] != score["raw_output_seal"]:
            raise ContractError("training raw output differs from scored seal")
        request = validate_inference_request(product_load_json(request_path))
        if request["request_id"] != raw["request_id"]:
            raise ContractError("training request differs from raw output")
        labels = verify_scoring_labels(load_json(label_path))
        selected, positives = _select_training_candidates(
            raw["candidates"],
            labels,
            maximum=args.maximum_candidates_per_group,
        )
        if not positives:
            exclusions.append(
                {
                    "group_id": labels["group_id"],
                    "reason": "ROLE_TARGET_OUTSIDE_EXPORTED_TRAINING_HEAD",
                }
            )
            continue
        candidates = [
            {
                "candidate_id": candidate["candidate_id"],
                "features": [list(item) for item in feature_vector(request["finding"], candidate)],
                "target": candidate["candidate_id"] in positives,
            }
            for candidate in selected
        ]
        if not any(not item["target"] for item in candidates):
            exclusions.append(
                {
                    "group_id": labels["group_id"],
                    "reason": "NO_TRAINING_NEGATIVE",
                }
            )
            continue
        group = {
            "group_id": labels["group_id"],
            "family_id": labels["family_id"],
            "audit_card_id": score["audit_card_id"],
            "partition": "TRAINING",
            "candidates": candidates,
        }
        group["feature_group_id"] = stable_id("v0.4.1-learned-feature-group", group)
        group_path = private_root / "trainer" / "feature-groups" / f"{group_token}.json"
        _write_once(group_path, group)
        groups.append({key: value for key, value in group.items() if key != "feature_group_id"})
    if len(groups) < args.minimum_groups:
        raise PolicyError("V0_4_1_LEARNED_TRAINING_GROUP_FLOOR_FAILED")
    family_count = len({item["family_id"] for item in groups})
    if family_count < args.minimum_families:
        raise PolicyError("V0_4_1_LEARNED_TRAINING_FAMILY_FLOOR_FAILED")
    training_manifest = {
        "schema_version": "lumi-trace-v0.4.1-learned-training-manifest-v1",
        "predecessor_partition_manifest_id": manifest["record_id"],
        "runtime_identity": RUNTIME_IDENTITY,
        "base_ranker": args.base_ranker,
        "raw_output_sealed_before_label_reveal": True,
        "candidate_generation_label_access": False,
        "group_count": len(groups),
        "family_count": family_count,
        "feature_group_ids": sorted(
            stable_id("v0.4.1-learned-feature-group", group) for group in groups
        ),
        "exclusions": exclusions,
        "label_derived_material_root": "G:/",
        "model_inference_copy_root": "F:/",
        "created_at": TIMESTAMP,
    }
    training_manifest["manifest_id"] = stable_id(
        "v0.4.1-learned-training-manifest",
        training_manifest,
    )
    _write_once(
        private_root / "trainer" / "training-manifest.json",
        training_manifest,
    )
    config = LearnedTrainingConfig(
        epochs=args.epochs,
        margin=args.margin,
        maximum_candidates_per_group=args.maximum_candidates_per_group,
        maximum_pairs_per_group=args.maximum_pairs_per_group,
        seed=args.seed,
    )
    first = train_integer_pairwise_ranker(
        groups,
        audit_card_allowlist=allowlist,
        training_manifest_id=training_manifest["manifest_id"],
        config=config,
    )
    second = train_integer_pairwise_ranker(
        groups,
        audit_card_allowlist=allowlist,
        training_manifest_id=training_manifest["manifest_id"],
        config=config,
    )
    if first != second:
        raise ContractError("learned ranker exact training replay failed")
    verify_model_artifact(first)
    model_token = first["artifact_id"].split(":", 1)[1][:24]
    private_model = private_root / "trainer" / "models" / f"{model_token}.json"
    if private_model.exists():
        if product_load_json(private_model) != first:
            raise ContractError("private learned model differs")
    else:
        product_dump_json(private_model, first)
    inference_model = work_root / "builder" / "models" / f"{model_token}.json"
    inference_model.parent.mkdir(parents=True, exist_ok=True)
    if inference_model.exists():
        if product_load_json(inference_model) != first:
            raise ContractError("builder learned model differs")
    else:
        shutil.copyfile(private_model, inference_model)
    model_sha256 = product_sha256_file(inference_model)
    receipt = {
        "schema_version": "lumi-trace-v0.4.1-learned-training-receipt-v1",
        "training_manifest_id": training_manifest["manifest_id"],
        "model_artifact_id": first["artifact_id"],
        "model_sha256": model_sha256,
        "active_parameters": first["active_parameters"],
        "pair_updates": first["pair_updates"],
        "exact_training_replay": True,
        "family_balanced": True,
        "foundation_model": None,
        "external_weights_downloaded": False,
        "network_required": False,
        "private_model_path": str(private_model),
        "builder_model_path": str(inference_model),
        "public_weight_release_authorised": False,
        "qualification_authorised": False,
        "created_at": TIMESTAMP,
    }
    receipt["receipt_id"] = stable_id("v0.4.1-learned-training-receipt", receipt)
    _write_once(private_root / "trainer" / "training-receipt.json", receipt)
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--predecessor-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    result.add_argument("--base-ranker", default=BASE_RANKER, choices=[BASE_RANKER])
    result.add_argument("--minimum-groups", type=int, default=400)
    result.add_argument("--minimum-families", type=int, default=25)
    result.add_argument("--maximum-candidates-per-group", type=int, default=128)
    result.add_argument("--maximum-pairs-per-group", type=int, default=256)
    result.add_argument("--epochs", type=int, default=16)
    result.add_argument("--margin", type=int, default=8)
    result.add_argument("--seed", type=int, default=41)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    receipt = build_groups_and_train(args)
    print(receipt["receipt_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
