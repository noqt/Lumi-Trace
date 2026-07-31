# SPDX-License-Identifier: Apache-2.0
"""Train an exact-replay V0.4.1 candidate from sealed private feature groups."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

from lumi_trace.canonical import (
    load_json as product_load_json,
)
from lumi_trace.canonical import (
    sha256_file as product_sha256_file,
)
from lumi_trace.learned_ranker import verify_model_artifact

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = PROJECT_ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import dump_json, load_json, stable_id  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.learned_v041 import (  # noqa: E402
    LearnedTrainingConfig,
    train_integer_pairwise_ranker,
)

TIMESTAMP = "2026-07-26T00:00:00Z"


def _root(path: Path, drive: str) -> Path:
    resolved = path.resolve(strict=True)
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"governed root must remain on {drive}")
    return resolved


def _write_once(path: Path, value: dict) -> None:
    if path.exists():
        if load_json(path) != value:
            raise ContractError(f"append-only artifact differs: {path.name}")
        return
    dump_json(path, value)


def train_variant(args: argparse.Namespace) -> dict:
    private_root = _root(args.private_root, "G:")
    work_root = _root(args.work_root, "F:")
    predecessor_root = _root(args.predecessor_root, "G:")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", args.name) is None:
        raise ValueError("candidate name must be a lowercase safe token")
    manifest = load_json(private_root / "trainer" / "training-manifest.json")
    partition = load_json(predecessor_root / "partitions" / "training" / "manifest-final.json")
    allowlist = set(partition["audit_card_ids"])
    expected_features = set(manifest["feature_group_ids"])
    groups = []
    observed_features = set()
    for path in sorted((private_root / "trainer" / "feature-groups").glob("*.json")):
        group = load_json(path)
        feature_id = group.pop("feature_group_id")
        if feature_id not in expected_features:
            continue
        observed_features.add(feature_id)
        groups.append(group)
    if observed_features != expected_features:
        raise PolicyError("V0_4_1_VARIANT_FEATURE_MEMBERSHIP_MISMATCH")
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
        training_manifest_id=manifest["manifest_id"],
        config=config,
    )
    second = train_integer_pairwise_ranker(
        groups,
        audit_card_allowlist=allowlist,
        training_manifest_id=manifest["manifest_id"],
        config=config,
    )
    if first != second:
        raise ContractError("variant training replay differs")
    verify_model_artifact(first)
    candidate_root = private_root / "trainer" / "candidates" / args.name
    candidate_root.mkdir(parents=True, exist_ok=True)
    model_path = candidate_root / "model.json"
    _write_once(model_path, first)
    builder_path = (
        work_root / "builder" / "models" / f"{first['artifact_id'].split(':', 1)[1][:24]}.json"
    )
    builder_path.parent.mkdir(parents=True, exist_ok=True)
    if builder_path.exists():
        if product_load_json(builder_path) != first:
            raise ContractError("builder variant model differs")
    else:
        shutil.copyfile(model_path, builder_path)
    receipt = {
        "schema_version": "lumi-trace-v0.4.1-learned-candidate-receipt-v1",
        "candidate_name": args.name,
        "training_manifest_id": manifest["manifest_id"],
        "model_artifact_id": first["artifact_id"],
        "model_sha256": product_sha256_file(builder_path),
        "training_config": config.as_dict(),
        "active_parameters": first["active_parameters"],
        "pair_updates": first["pair_updates"],
        "group_count": manifest["group_count"],
        "family_count": manifest["family_count"],
        "exact_training_replay": True,
        "external_weights_downloaded": False,
        "network_required": False,
        "public_weight_release_authorised": False,
        "qualification_authorised": False,
        "created_at": TIMESTAMP,
    }
    receipt["receipt_id"] = stable_id("v0.4.1-learned-candidate-receipt", receipt)
    _write_once(candidate_root / "receipt.json", receipt)
    return {
        **receipt,
        "builder_model_path": str(builder_path),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("name")
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
    result.add_argument("--epochs", type=int, default=32)
    result.add_argument("--margin", type=int, default=32)
    result.add_argument("--maximum-candidates-per-group", type=int, default=128)
    result.add_argument("--maximum-pairs-per-group", type=int, default=512)
    result.add_argument("--seed", type=int, default=41)
    return result


def main() -> int:
    try:
        result = train_variant(parser().parse_args())
    except (ContractError, PolicyError, OSError, ValueError) as exc:
        print(f"train-v0.4.1-variant: {exc}", file=sys.stderr)
        return 2
    print(result["model_artifact_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
