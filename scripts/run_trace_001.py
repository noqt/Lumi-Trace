# SPDX-License-Identifier: Apache-2.0
"""Run the bounded local TRACE-001 experiment after every V0.4 gate passes."""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
for source_path in (EVAL_SRC, ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.baselines import aggregate_v04, score_v04_group  # noqa: E402
from trace_eval.canonical import (  # noqa: E402
    canonical_bytes,
    load_json,
    sha256_file,
    stable_id,
)
from trace_eval.contracts import validate_record  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.features import CANDIDATE_CACHE_TOKEN  # noqa: E402
from trace_eval.trace001 import (  # noqa: E402
    TrainingConfig,
    quantize_int8,
    rank_with_checkpoint,
    rank_with_quantized,
    train_linear_ranker,
    verify_checkpoint,
)

from scripts.build_v0_4_assurance import _write_once  # noqa: E402
from scripts.run_v0_4_experiments import (  # noqa: E402
    _active_candidate_lock,
    _active_final_authority_paths,
    _active_training_locks,
    _confidence_intervals,
    _gate_results,
)


def _require_private_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != "g:" or not resolved.is_dir():
        raise ValueError("governed private G: root is unavailable")
    return resolved


def _load_authority(private_root: Path) -> tuple[dict[str, Any], ...]:
    gates_path, readiness_path = _active_final_authority_paths(private_root)
    readiness = load_json(readiness_path)
    validate_record(readiness)
    gates = load_json(gates_path)
    manifest = load_json(private_root / "manifests" / "training-eligibility-manifest.json")
    partition_seal = load_json(private_root / "manifests" / "final-partition-seal.json")
    candidate_lock = _active_candidate_lock(private_root)
    supply_chain, execution_lock = _active_training_locks(private_root)
    if (
        readiness["payload"]["recommendation"] != "TRACE_001_EXECUTION_AUTHORISED"
        or not all(readiness["payload"]["gates"].values())
        or readiness["payload"]["qualification_opened"] is not False
        or readiness["payload"]["holdback_opened"] is not False
        or readiness["payload"]["training_started"] is not False
        or not all(gates["gates"].values())
        or gates["evidence"]["training_manifest_id"] != manifest["record_id"]
        or gates["evidence"]["partition_seal_id"] != partition_seal["record_id"]
        or gates["evidence"]["candidate_lock_id"] != candidate_lock["candidate_lock_id"]
        or gates["evidence"]["supply_chain_id"] != supply_chain["supply_chain_id"]
        or gates["evidence"]["execution_lock_id"] != execution_lock["execution_lock_id"]
        or partition_seal["payload"]["holdback_state"] != "SEALED_UNOPENED"
        or supply_chain["downloads_required"] is not False
        or supply_chain["foundation_model"] is not None
        or supply_chain["tokenizer"] is not None
        or supply_chain["external_weights"]
    ):
        raise PolicyError("TRACE_001_EXECUTION_NOT_AUTHORISED")
    return (
        readiness,
        gates,
        manifest,
        partition_seal,
        candidate_lock,
        supply_chain,
        execution_lock,
    )


def _verify_execution_code(execution_lock: dict[str, Any]) -> None:
    expected = {
        "training_code": ROOT / execution_lock["training_code"]["path"],
        "feature_code": ROOT / execution_lock["feature_code"]["path"],
        "dependency_lock": ROOT / execution_lock["dependency_lock"]["path"],
    }
    if any(sha256_file(path) != execution_lock[name]["sha256"] for name, path in expected.items()):
        raise PolicyError("TRACE_001_EXECUTION_CODE_IDENTITY_MISMATCH")


def _training_groups(
    private_root: Path,
    *,
    manifest: dict[str, Any],
    maximum_candidates: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    allowlist = set(manifest["payload"]["audit_card_ids"])
    records = [
        load_json(path)
        for path in sorted(
            (private_root / "training-derived" / "features").glob(
                f"*.{CANDIDATE_CACHE_TOKEN}.c{maximum_candidates}.json"
            )
        )
    ]
    by_card_id = {record["audit_card_id"]: record for record in records}
    if (
        set(by_card_id) != allowlist
        or len(records) != len(by_card_id)
        or any(
            record["partition"] != "TRAINING"
            or record["maximum_candidates"] != maximum_candidates
            or record["repository_code_executed"] is not False
            or record["runner_or_model_output_used_for_labels"] is not False
            or record["network_used"] is not False
            for record in records
        )
    ):
        raise PolicyError("TRACE_001_TRAINING_FEATURE_ALLOWLIST_MISMATCH")
    groups = [
        {
            "group_id": record["group_id"],
            "family_id": record["family_id"],
            "audit_card_id": record["audit_card_id"],
            "partition": "TRAINING",
            "candidates": record["training_candidates"],
        }
        for record in sorted(records, key=lambda item: item["group_id"])
    ]
    return groups, sorted(record["record_id"] for record in records)


def _quantization_regression(
    checkpoint: dict[str, Any],
    quantized: dict[str, Any],
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    top_one_matches = 0
    compared = groups[:100]
    for group in compared:
        candidates = [
            {
                "candidate_id": candidate["candidate_id"],
                "features": candidate["features"],
            }
            for candidate in group["candidates"]
        ]
        full = rank_with_checkpoint(checkpoint, candidates)
        reduced = rank_with_quantized(quantized, candidates)
        top_one_matches += bool(
            full and reduced and full[0]["candidate_id"] == reduced[0]["candidate_id"]
        )
    return {
        "comparison_group_count": len(compared),
        "top_one_agreement": (top_one_matches / len(compared) if compared else 0.0),
        "minimum_top_one_agreement": 0.95,
        "passed": bool(compared) and top_one_matches / len(compared) >= 0.95,
    }


def train(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_private_root(args.private_root)
    (
        readiness,
        gates,
        manifest,
        _partition_seal,
        candidate_lock,
        supply_chain,
        execution_lock,
    ) = _load_authority(private_root)
    _verify_execution_code(execution_lock)
    config = TrainingConfig(**execution_lock["configuration"])
    if (
        config.maximum_candidates_per_group
        != candidate_lock["candidate_generation"]["maximum_candidates"]
    ):
        raise PolicyError("TRACE_001_CANDIDATE_LIMIT_MISMATCH")
    groups, feature_record_ids = _training_groups(
        private_root,
        manifest=manifest,
        maximum_candidates=config.maximum_candidates_per_group,
    )
    allowlist = set(manifest["payload"]["audit_card_ids"])
    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    first = train_linear_ranker(
        groups,
        audit_card_allowlist=allowlist,
        training_manifest_id=manifest["record_id"],
        config=config,
    )
    second = train_linear_ranker(
        groups,
        audit_card_allowlist=allowlist,
        training_manifest_id=manifest["record_id"],
        config=config,
    )
    cpu_seconds = time.process_time() - cpu_start
    wall_seconds = time.perf_counter() - wall_start
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if first != second:
        raise ContractError("TRACE_001_CLEAN_REPRODUCTION_MISMATCH")
    verify_checkpoint(
        first,
        training_manifest_id=manifest["record_id"],
    )
    quantized = quantize_int8(first)
    quantization = _quantization_regression(first, quantized, groups)
    checkpoint_bytes = canonical_bytes(first)
    quantized_bytes = canonical_bytes(quantized)
    receipt = {
        "schema_version": "lumi-trace-v0.4-private-trace-001-training-receipt-v1",
        "readiness_id": readiness["record_id"],
        "gate_record_id": gates["gate_record_id"],
        "training_manifest_id": manifest["record_id"],
        "candidate_lock_id": candidate_lock["candidate_lock_id"],
        "supply_chain_id": supply_chain["supply_chain_id"],
        "execution_lock_id": execution_lock["execution_lock_id"],
        "checkpoint_id": first["checkpoint_id"],
        "quantized_artifact_id": quantized["artifact_id"],
        "feature_record_ids": feature_record_ids,
        "group_count": len(groups),
        "family_count": len({group["family_id"] for group in groups}),
        "active_parameters": first["active_parameters"],
        "pair_updates": first["pair_updates"],
        "completed_epochs": first["completed_epochs"],
        "clean_reproduction_match": True,
        "quantization_regression": quantization,
        "resources": {
            "cpu_seconds_two_clean_runs": cpu_seconds,
            "wall_seconds_two_clean_runs": wall_seconds,
            "peak_python_memory_bytes": peak_memory_bytes,
            "checkpoint_bytes": len(checkpoint_bytes),
            "quantized_artifact_bytes": len(quantized_bytes),
            "local_cpu_training": True,
        },
        "checkpoint_licence": "INTERNAL_EVALUATION_ONLY_PENDING_USER_RELEASE_DECISION",
        "repository_code_executed": False,
        "network_used": False,
        "hosted_service_used": False,
        "weights_downloaded": False,
        "training_started": True,
        "qualification_opened": False,
        "holdback_opened": False,
        "public_weight_release_authorised": False,
    }
    receipt["receipt_id"] = stable_id("v0.4-trace-001-training-receipt", receipt)
    _write_once(private_root / "models" / "trace-001" / "checkpoint.json", first)
    _write_once(private_root / "models" / "trace-001" / "checkpoint-int8.json", quantized)
    _write_once(
        private_root / "manifests" / "trace-001-training-receipt.json",
        receipt,
    )
    return {
        "receipt_id": receipt["receipt_id"],
        "checkpoint_id": first["checkpoint_id"],
        "group_count": len(groups),
        "family_count": receipt["family_count"],
        "active_parameters": first["active_parameters"],
        "clean_reproduction_match": True,
        "quantization_regression_passed": quantization["passed"],
        "training_started": True,
        "qualification_opened": False,
        "holdback_opened": False,
        "public_weight_release_authorised": False,
    }


_ABLATION_FEATURES = {
    "FULL": (),
    "NATURAL_CUE_MARKED": (),
    "NO_PATH": ("path_overlap",),
    "NO_SYMBOL": ("symbol_overlap", "symbol_present"),
    "REDUCED_DESCRIPTION": ("description_overlap",),
    "IDENTIFIER_ABLATION": (
        "path_overlap",
        "symbol_overlap",
        "symbol_present",
    ),
}


def _inference_candidates(
    record: dict[str, Any],
    *,
    ablated_features: tuple[str, ...],
) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": candidate["candidate_id"],
            "features": {
                name: 0.0 if name in ablated_features else value
                for name, value in candidate["features"].items()
            },
        }
        for candidate in record["training_candidates"]
    ]


def _score_feature_record(
    checkpoint: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    labels = record["private_scoring_labels"]
    views: dict[str, Any] = {}
    for view, ablated in _ABLATION_FEATURES.items():
        ranked = rank_with_checkpoint(
            checkpoint,
            _inference_candidates(record, ablated_features=ablated),
        )
        views[view] = {
            "ranking_id": stable_id(
                "v0.4-trace-001-ranking",
                [item["candidate_id"] for item in ranked],
            ),
            "metrics": score_v04_group(
                ranked,
                file_target_candidate_ids=set(labels["file_target_candidate_ids"]),
                role_target_candidate_ids=set(labels["role_target_candidate_ids"]),
                hard_negative_candidate_ids=set(labels["hard_negative_candidate_ids"]),
                family_id=record["family_id"],
            ),
        }
    value = {
        "schema_version": "lumi-trace-v0.4-private-trace-001-group-result-v1",
        "group_id": record["group_id"],
        "family_id": record["family_id"],
        "audit_card_id": record["audit_card_id"],
        "feature_record_id": record["record_id"],
        "partition": record["partition"],
        "checkpoint_id": checkpoint["checkpoint_id"],
        "views": views,
        "labels_applied_after_ranking": True,
        "repository_code_executed": False,
        "network_used": False,
    }
    value["result_id"] = stable_id("v0.4-trace-001-group-result", value)
    return value


def _baseline_metric(
    record: dict[str, Any],
    algorithm: str,
) -> dict[str, Any]:
    matches = [
        score["metrics"] for score in record["baseline_scores"] if score["algorithm"] == algorithm
    ]
    if len(matches) != 1:
        raise PolicyError("TRACE_001_SELECTED_BASELINE_RESULT_MISSING")
    return matches[0]


def score_partition(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_private_root(args.private_root)
    if args.partition not in {"ENGINEERING_DEVELOPMENT", "MODEL_SELECTION"}:
        raise ValueError("score-partition supports development or model selection only")
    (
        _readiness,
        _gates,
        _manifest,
        partition_seal,
        candidate_lock,
        _supply_chain,
        execution_lock,
    ) = _load_authority(private_root)
    _verify_execution_code(execution_lock)
    checkpoint = load_json(private_root / "models" / "trace-001" / "checkpoint.json")
    verify_checkpoint(checkpoint)
    training_receipt = load_json(private_root / "manifests" / "trace-001-training-receipt.json")
    if (
        training_receipt["checkpoint_id"] != checkpoint["checkpoint_id"]
        or training_receipt["public_weight_release_authorised"] is not False
    ):
        raise PolicyError("TRACE_001_TRAINING_RECEIPT_MISMATCH")
    maximum_candidates = candidate_lock["candidate_generation"]["maximum_candidates"]
    slug = args.partition.casefold().replace("_", "-")
    feature_root = private_root / "runs" / "private" / "baselines" / slug
    allowed_card_ids = {
        assignment["audit_card_id"]
        for assignment in partition_seal["payload"]["assignments"]
        if assignment["partition"] == args.partition
    }
    records = [
        load_json(path)
        for path in sorted(
            feature_root.glob(f"*.{CANDIDATE_CACHE_TOKEN}.c{maximum_candidates}.json")
        )
    ]
    if (
        not records
        or {record["audit_card_id"] for record in records} != allowed_card_ids
        or len(records) != len(allowed_card_ids)
    ):
        raise PolicyError("TRACE_001_EVALUATION_FEATURE_ALLOWLIST_MISMATCH")
    output_root = private_root / "runs" / "private" / "trace-001" / slug / args.run
    results: list[dict[str, Any]] = []
    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    for record in records:
        token = record["group_id"].split(":", 1)[1][:24]
        result_path = output_root / f"{token}.json"
        if result_path.is_file():
            result = load_json(result_path)
            if (
                result["feature_record_id"] != record["record_id"]
                or result["checkpoint_id"] != checkpoint["checkpoint_id"]
            ):
                raise PolicyError("TRACE_001_CACHED_RESULT_IDENTITY_MISMATCH")
        else:
            result = _score_feature_record(checkpoint, record)
            _write_once(result_path, result)
        results.append(result)
    cpu_seconds = time.process_time() - cpu_start
    wall_seconds = time.perf_counter() - wall_start
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    views: dict[str, Any] = {}
    for view in _ABLATION_FEATURES:
        metrics = [result["views"][view]["metrics"] for result in results]
        aggregate = aggregate_v04(metrics)
        gate_results = _gate_results(aggregate)
        views[view] = {
            "aggregate": aggregate,
            "confidence_intervals": _confidence_intervals(metrics),
            "gate_results": gate_results,
            "all_gates_passed": all(gate_results.values()),
        }
    selected_baseline = candidate_lock["selected_deterministic_comparator"]
    if selected_baseline not in {"lexical", "sparse"}:
        raise PolicyError("TRACE_001_SELECTED_BASELINE_NOT_GROUP_COMPARABLE")
    learned_by_family: dict[str, list[bool]] = {}
    baseline_by_family: dict[str, list[bool]] = {}
    for result, record in zip(results, records, strict=True):
        family_id = record["family_id"]
        learned_by_family.setdefault(family_id, []).append(
            result["views"]["FULL"]["metrics"]["file_recall_at_20"]
        )
        baseline_by_family.setdefault(family_id, []).append(
            _baseline_metric(record, selected_baseline)["file_recall_at_20"]
        )
    family_deltas = {
        family_id: (
            sum(learned_by_family[family_id]) / len(learned_by_family[family_id])
            - sum(baseline_by_family[family_id]) / len(baseline_by_family[family_id])
        )
        for family_id in sorted(learned_by_family)
    }
    summary = {
        "schema_version": "lumi-trace-v0.4-private-trace-001-grouped-summary-v1",
        "run": args.run,
        "partition": args.partition,
        "checkpoint_id": checkpoint["checkpoint_id"],
        "candidate_lock_id": candidate_lock["candidate_lock_id"],
        "group_count": len(records),
        "family_count": len(learned_by_family),
        "views": views,
        "selected_deterministic_comparator": selected_baseline,
        "family_improvement_count": sum(delta > 0 for delta in family_deltas.values()),
        "family_regression_count": sum(delta < 0 for delta in family_deltas.values()),
        "family_recall_at_20_deltas": family_deltas,
        "resources": {
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_python_memory_bytes": peak_memory_bytes,
            "checkpoint_bytes": len(canonical_bytes(checkpoint)),
            "local_cpu_inference": True,
        },
        "cue_ablation_views_complete": set(views) == set(_ABLATION_FEATURES),
        "labels_applied_after_ranking": True,
        "repository_code_executed": False,
        "network_used": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }
    summary["summary_id"] = stable_id("v0.4-trace-001-grouped-summary", summary)
    _write_once(
        private_root / "manifests" / f"trace-001-{args.run}-{slug}.json",
        summary,
    )
    return {
        "summary_id": summary["summary_id"],
        "partition": args.partition,
        "group_count": summary["group_count"],
        "family_count": summary["family_count"],
        "full_all_gates_passed": views["FULL"]["all_gates_passed"],
        "family_improvement_count": summary["family_improvement_count"],
        "family_regression_count": summary["family_regression_count"],
        "qualification_opened": False,
        "holdback_opened": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    parser.add_argument("phase", choices=("train", "score-partition"))
    parser.add_argument("--partition")
    parser.add_argument("--run", default="run1")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.phase == "score-partition" and args.partition is None:
            raise ValueError("--partition is required for score-partition")
        result = {
            "train": train,
            "score-partition": score_partition,
        }[args.phase](args)
    except (ContractError, PolicyError, OSError, ValueError) as exc:
        print(f"run-trace-001: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
