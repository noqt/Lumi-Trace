# SPDX-License-Identifier: Apache-2.0
"""Seal disclosure-safe V0.4.1 integrity-recovery evidence."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from lumi_trace import __version__
from lumi_trace.canonical import dump_json, load_json, sha256_file, stable_id
from lumi_trace.learned_ranker import LEARNED_RANKER, verify_model_artifact
from lumi_trace.localization import (
    CANDIDATE_ALGORITHM,
    QUARANTINE_POLICY,
    RUNTIME_IDENTITY,
    information_flow_manifest,
    verify_raw_localization,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = PROJECT_ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.assurance import v04_metric_specification  # noqa: E402
from trace_eval.baselines import aggregate_v04, score_v04_group  # noqa: E402
from trace_eval.integrity_v041 import verify_scoring_labels  # noqa: E402

TIMESTAMP = "2026-07-26T00:00:00Z"
STARTING_REVISION = "c93d3c792190435cb82e28f01af532be97d9a06a"
STARTING_SEAL = (
    "lumi-trace-v0.4-public-evidence:"
    "d5404d104a946046cfce4439e338c8bef9223331f93057a2c3e87e47a4553c3a"
)
DETERMINISTIC_RANKER = "role-aware-sparse-v0.4.1.3"
FINAL_ROUTE_RUNS = {
    DETERMINISTIC_RANKER: "deterministic-v3-final-guarded",
    LEARNED_RANKER: "learned-hybrid-v3-final-guarded",
}


def _root(path: Path, drive: str, *, create: bool = False) -> Path:
    resolved = path.resolve(strict=not create)
    if resolved.drive.casefold() != drive.casefold():
        raise ValueError(f"governed root must remain on {drive}")
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError("governed root is not a directory")
    return resolved


def _write_once(path: Path, value: dict) -> None:
    if path.exists():
        if load_json(path) != value:
            raise ValueError(f"append-only artifact differs: {path.name}")
        return
    dump_json(path, value)


def _source_state_id() -> str:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    members = []
    for relative in sorted(completed.stdout.splitlines()):
        normalized = relative.replace("\\", "/")
        if normalized.startswith("evidence/v0.4.1/"):
            continue
        path = PROJECT_ROOT / relative
        if path.is_file():
            members.append(
                {
                    "path": normalized,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return stable_id(
        "lumi-trace-v0.4.1-source-state",
        {
            "starting_revision": STARTING_REVISION,
            "members": members,
        },
    )


def _scheduled(predecessor: Path) -> list[tuple[str, str, bool]]:
    manifest = load_json(
        predecessor / "partitions" / "engineering-development" / "manifest-final.json"
    )
    cards = {
        card["record_id"]: card
        for path in sorted(
            (predecessor / "manifests" / "audit-cards" / "engineering-development").glob("*.json")
        )
        for card in [load_json(path)]
    }
    receipts = {
        receipt["group_audit_card_id"]: receipt
        for path in sorted(
            (predecessor / "runs" / "private" / "intake" / "engineering-development").glob("*.json")
        )
        for receipt in [load_json(path)]
    }
    return [
        (
            receipts[card_id]["candidate_id"].split(":", 1)[1][:24],
            cards[card_id]["payload"]["family_id"],
            bool(receipts[card_id]["hard_negative_paths"]),
        )
        for card_id in manifest["audit_card_ids"]
    ]


def _completed_metric(
    *,
    raw: dict,
    labels: dict,
) -> tuple[dict, bool, bool, bool, bool]:
    inventory = raw["candidate_inventory"]
    ranking = raw["candidates"]
    target_paths = {item["path"] for item in labels["targets"]}
    target_symbols = {
        (item["path"], item["symbol"]) for item in labels["targets"] if item.get("symbol")
    }
    hard_paths = set(labels["hard_negative_paths"])
    file_ids = {item["candidate_id"] for item in inventory if item["path"] in target_paths}
    role_ids = {
        item["candidate_id"]
        for item in inventory
        if (item["path"], item.get("symbol")) in target_symbols
    }
    hard_ids = {item["candidate_id"] for item in inventory if item["path"] in hard_paths}
    row = score_v04_group(
        [{"candidate_id": item["candidate_id"]} for item in ranking],
        file_target_candidate_ids=file_ids,
        role_target_candidate_ids=role_ids,
        hard_negative_candidate_ids=hard_ids,
        family_id=labels["family_id"],
    )
    positions = {item["candidate_id"]: position for position, item in enumerate(ranking, 1)}
    first_role = min(
        (positions[item] for item in role_ids if item in positions),
        default=None,
    )
    return (
        row,
        bool(file_ids),
        bool(role_ids),
        bool(first_role is not None and first_role <= 5),
        bool(first_role is not None and first_role <= 10),
    )


def _failure_metric(family_id: str, has_hard_negative: bool) -> dict:
    return {
        "family_id": family_id,
        "candidate_count": 0,
        "valid_attempt": False,
        "target_indexable": False,
        "file_recall_at_5": False,
        "file_recall_at_10": False,
        "file_recall_at_20": False,
        "location_role_recall_at_20": False,
        "reciprocal_rank": 0.0,
        "no_relevant_candidate": True,
        "has_hard_negative": has_hard_negative,
        "hard_negative_outrank": has_hard_negative,
        "wrong_location_role_top_one": False,
        "disposition_emitted": False,
        "false_supported_disposition": False,
        "false_vulnerability_safe_control": False,
        "unsafe_non_abstention": False,
    }


def _route_aggregate(
    *,
    private_root: Path,
    work_root: Path,
    predecessor: Path,
    ranker: str,
    model_artifact_id: str | None,
) -> dict:
    raw_root = work_root / "builder" / "raw" / "engineering-development" / ranker
    result_root = private_root / "scorer" / "results" / "engineering-development" / ranker
    label_root = private_root / "scorer" / "labels" / "engineering-development"
    completed = {}
    telemetry = []
    generation = []
    for path in sorted(raw_root.glob("*.json")):
        raw = load_json(path)
        if (
            raw.get("runtime_identity") != RUNTIME_IDENTITY
            or raw.get("model_artifact_id") != model_artifact_id
        ):
            continue
        verify_raw_localization(raw)
        score_path = result_root / path.name
        if not score_path.is_file():
            raise ValueError("current raw ranking has no scorer record")
        score = load_json(score_path)
        group_token = path.name.split(".", 1)[0]
        labels = verify_scoring_labels(load_json(label_root / f"{group_token}.json"))
        if (
            score.get("runtime_identity") != RUNTIME_IDENTITY
            or score.get("raw_output_seal") != raw["raw_output_seal"]
            or score.get("scoring_label_id") != labels["label_id"]
            or score.get("model_artifact_id") != model_artifact_id
        ):
            raise ValueError("current scorer record is not bound to the raw ranking")
        if group_token in completed:
            raise ValueError("multiple current rankings exist for one group")
        completed[group_token] = _completed_metric(raw=raw, labels=labels)
        telemetry.append(raw["telemetry"])
        generation.append(raw["generation"])
    scheduled = _scheduled(predecessor)
    metric_rows = []
    file_indexable = 0
    role_indexable = 0
    role5 = 0
    role10 = 0
    for group_token, family_id, has_hard_negative in scheduled:
        item = completed.get(group_token)
        if item is None:
            metric_rows.append(_failure_metric(family_id, has_hard_negative))
            continue
        row, file_ok, role_ok, at5, at10 = item
        metric_rows.append(row)
        file_indexable += file_ok
        role_indexable += role_ok
        role5 += at5
        role10 += at10
    aggregate = aggregate_v04(metric_rows)
    denominator = len(scheduled)
    aggregate["file_target_indexability"] = file_indexable / denominator
    aggregate["role_target_indexability"] = role_indexable / denominator
    aggregate["location_role_correct_recall_at_5"] = role5 / denominator
    aggregate["location_role_correct_recall_at_10"] = role10 / denominator
    return {
        "ranker": ranker,
        "model_artifact_id": model_artifact_id,
        "scheduled_group_count": denominator,
        "completed_group_count": len(completed),
        "failed_attempt_count": denominator - len(completed),
        "metrics": aggregate,
        "telemetry": {
            "sum_wall_seconds": sum(item["wall_seconds"] for item in telemetry),
            "sum_cpu_seconds": sum(item["cpu_seconds"] for item in telemetry),
            "peak_memory_measurement_available": any(
                item["peak_memory_measured"] for item in telemetry
            ),
            "maximum_peak_python_bytes": max(
                (item["peak_python_bytes"] or 0 for item in telemetry),
                default=0,
            ),
        },
        "generation": {
            "candidate_count": sum(item["candidate_count"] for item in generation),
            "indexed_python_file_count": sum(
                item["indexed_python_file_count"] for item in generation
            ),
            "groups_with_truncation": sum(item["truncated"] for item in generation),
        },
    }


def _gate_results(metrics: dict) -> dict:
    gates = v04_metric_specification()["payload"]["gates"]
    return {
        "valid_attempt_completion": (
            metrics["valid_attempt_completion"] >= gates["valid_attempt_completion_minimum"]
        ),
        "file_target_indexability": (
            metrics["file_target_indexability"] >= gates["target_indexability_minimum"]
        ),
        "role_target_indexability": (
            metrics["role_target_indexability"] >= gates["target_indexability_minimum"]
        ),
        "file_recall_at_5": metrics["file_recall_at_5"] >= gates["file_recall_at_5_minimum"],
        "file_recall_at_10": metrics["file_recall_at_10"] >= gates["file_recall_at_10_minimum"],
        "file_recall_at_20": metrics["file_recall_at_20"] >= gates["file_recall_at_20_minimum"],
        "location_role_recall_at_20": (
            metrics["location_role_correct_recall_at_20"]
            >= gates["location_role_correct_recall_at_20_minimum"]
        ),
        "mean_reciprocal_rank": (
            metrics["mean_reciprocal_rank"] >= gates["mean_reciprocal_rank_minimum"]
        ),
        "no_relevant_candidate": (
            metrics["no_relevant_candidate"] <= gates["no_relevant_candidate_maximum"]
        ),
        "hard_negative_outrank": (
            metrics["hard_negative_outrank"] <= gates["hard_negative_outrank_maximum"]
        ),
        "wrong_location_role_top_one": (
            metrics["wrong_location_role_top_one"] <= gates["wrong_location_role_top_one_maximum"]
        ),
        "repository_family_macro_recall_at_20": (
            metrics["repository_family_macro_recall_at_20"]
            >= gates["repository_family_macro_recall_at_20_minimum"]
        ),
        "minimum_family_recall_at_20": (
            metrics["minimum_family_recall_at_20"] >= gates["minimum_family_recall_at_20_minimum"]
        ),
        "zero_recall_family_count": (
            metrics["zero_recall_family_count"] <= gates["zero_recall_family_count_maximum"]
        ),
        "false_supported_disposition": (
            metrics["false_supported_disposition"] <= gates["false_supported_disposition_maximum"]
        ),
        "false_vulnerability_safe_control": (
            metrics["false_vulnerability_safe_control"]
            <= gates["false_vulnerability_safe_control_maximum"]
        ),
        "unsafe_non_abstention": (
            metrics["unsafe_non_abstention"] <= gates["unsafe_non_abstention_maximum"]
        ),
    }


def _assert_public_safe(documents: dict[str, dict]) -> None:
    rendered = json.dumps(documents, ensure_ascii=True, sort_keys=True)
    forbidden_patterns = (
        r"[A-Za-z]:[/\\]",
        r"v0\.4-candidate-group:",
        r"repository-family:",
        r'"private_model_path"',
        r'"builder_model_path"',
        r'"targets"',
        r'"group_ids"',
        r'"family_ids"',
    )
    for pattern in forbidden_patterns:
        if re.search(pattern, rendered, flags=re.IGNORECASE):
            raise ValueError(f"public evidence contains forbidden substance: {pattern}")


def seal(args: argparse.Namespace) -> dict:
    private_root = _root(args.private_root, "G:")
    work_root = _root(args.work_root, "F:")
    predecessor = _root(args.predecessor_root, "G:")
    evidence_root = args.evidence_root.resolve(strict=False)
    if PROJECT_ROOT not in evidence_root.parents:
        raise ValueError("public evidence must remain inside the repository")
    evidence_root.mkdir(parents=True, exist_ok=True)
    model_path = args.model.resolve(strict=True)
    model = verify_model_artifact(load_json(model_path))
    receipt = load_json(args.model_receipt.resolve(strict=True))
    if receipt.get("model_artifact_id") != model["artifact_id"]:
        raise ValueError("model receipt does not bind the selected development artifact")
    validation = load_json(args.validation_record.resolve(strict=True))
    if (
        validation.get("schema_version") != "lumi-trace-v0.4.1-final-validation-v1"
        or validation.get("all_passed") is not True
        or validation.get("passed_command_count") != validation.get("command_count")
    ):
        raise ValueError("final validation record is incomplete or failed")
    model_screen = load_json(args.model_screen_record.resolve(strict=True))
    screen_results = model_screen.get("results", [])
    screen_model_ids = [
        item.get("model_artifact_id") for item in screen_results if isinstance(item, dict)
    ]
    if (
        model_screen.get("schema_version") != "lumi-trace-v0.4.1-private-model-screen-v1"
        or model_screen.get("runtime_identity") != RUNTIME_IDENTITY
        or model_screen.get("partition") != "ENGINEERING_DEVELOPMENT"
        or model_screen.get("model_selection_eligible") is not False
        or not 1 <= len(screen_results) <= 3
        or len(set(screen_model_ids)) != len(screen_results)
        or model["artifact_id"] not in screen_model_ids
        or model_screen.get("development_recommendation", {}).get("model_artifact_id")
        != model["artifact_id"]
        or model_screen.get("development_recommendation", {}).get("qualification_authorised")
        is not False
    ):
        raise ValueError("development model screen does not bind the selected model")
    training_manifest = load_json(private_root / "trainer" / "training-manifest.json")
    package = load_json(private_root / "manifests" / "package-qualification-final.json")
    if package.get("model_artifact_id") != model["artifact_id"]:
        raise ValueError("package qualification used a different model artifact")
    supply = load_json(private_root / "custodian" / "fresh-sample-supply-assessment.json")
    holdback = load_json(private_root / "custodian" / "holdback-non-access.json")
    if (
        supply.get("decision") != "EXTERNAL_DATA_SUPPLY_INSUFFICIENT"
        or supply.get("model_selection_opened") is not False
        or supply.get("qualification_opened") is not False
        or holdback.get("state") != "SEALED_UNOPENED"
    ):
        raise ValueError("fresh partition or holdback state is unsafe for sealing")
    deterministic = _route_aggregate(
        private_root=private_root,
        work_root=work_root,
        predecessor=predecessor,
        ranker=DETERMINISTIC_RANKER,
        model_artifact_id=None,
    )
    learned = _route_aggregate(
        private_root=private_root,
        work_root=work_root,
        predecessor=predecessor,
        ranker=LEARNED_RANKER,
        model_artifact_id=model["artifact_id"],
    )
    if (
        model_screen.get("scheduled_group_count") != deterministic["scheduled_group_count"]
        or model_screen.get("completed_base_ranking_count")
        != deterministic["completed_group_count"]
    ):
        raise ValueError("development model screen does not cover the final base rankings")
    source_state_id = _source_state_id()
    if (
        validation.get("source_state_id") != source_state_id
        or package.get("source_state_id") != source_state_id
    ):
        raise ValueError("validation or package qualification does not bind the final source state")
    loaded_route_summaries = []
    for ranker, run in FINAL_ROUTE_RUNS.items():
        path = (
            private_root / "manifests" / f"regenerated-engineering-development-{ranker}-{run}.json"
        )
        summary = load_json(path)
        if summary.get("ranker") != ranker or summary.get("run") != run:
            raise ValueError("final route execution summary identity mismatch")
        loaded_route_summaries.append(summary["summary_id"])
    aggregate_disposition = {
        "schema_version": "lumi-trace-v0.4.1-execution-aggregate-disposition-v1",
        "execution_summary_ids": sorted(loaded_route_summaries),
        "execution_summary_metrics_state": "SUPERSEDED_NON_AUTHORITATIVE",
        "reason": "RUNNING_PROCESSES_LOADED_PRE_REMEDIATION_AGGREGATOR",
        "raw_rankings_state": "VALID_CURRENT_RUNTIME_INPUT",
        "sealed_scorer_results_state": "VALID_CURRENT_RUNTIME_INPUT",
        "authoritative_aggregate_source": "ALL_SCHEDULED_GROUP_RECOMPUTATION_AT_FINAL_SEAL",
        "invalid_attempts_in_denominators": True,
    }
    aggregate_disposition["record_id"] = stable_id(
        "v0.4.1-execution-aggregate-disposition",
        aggregate_disposition,
    )
    _write_once(
        private_root / "invalidation" / "execution-aggregate-disposition.json",
        aggregate_disposition,
    )
    validation_attempts = []
    for run, expected_passed, state, reason in (
        (
            "sealed-source-a",
            False,
            "SUPERSEDED_FAILED_ORCHESTRATION_EVIDENCE",
            "HISTORICAL_VERIFIER_REQUIRED_EVIDENCE_ROOT_ARGUMENT",
        ),
        (
            "sealed-source-b",
            True,
            "SUPERSEDED_PASSED_PRIOR_SOURCE_STATE",
            "SOURCE_CHANGED_FOR_SDIST_NORMALIZATION",
        ),
        (
            "sealed-source-c",
            True,
            "SUPERSEDED_PASSED_PRIOR_SOURCE_STATE",
            "SOURCE_CHANGED_FOR_NONEMPTY_INSTALLED_LOCALIZATION_FIXTURE",
        ),
        (
            "sealed-source-d",
            False,
            "SUPERSEDED_FAILED_BOUNDARY_EVIDENCE",
            "NEW_OWNED_FIXTURE_ABSENT_FROM_PROVENANCE_MANIFEST",
        ),
    ):
        attempt = load_json(private_root / "manifests" / f"final-validation-{run}.json")
        if attempt.get("all_passed") is not expected_passed:
            raise ValueError("validation history attempt has an unexpected result")
        validation_attempts.append(
            {
                "record_id": attempt["record_id"],
                "state": state,
                "reason": reason,
                "deleted": False,
            }
        )
    validation_disposition = {
        "schema_version": "lumi-trace-v0.4.1-validation-history-disposition-v1",
        "attempts": validation_attempts,
        "final_record_id": validation["record_id"],
    }
    validation_disposition["record_id"] = stable_id(
        "v0.4.1-validation-history-disposition",
        validation_disposition,
    )
    _write_once(
        private_root / "invalidation" / "validation-history-disposition.json",
        validation_disposition,
    )
    flow = information_flow_manifest()
    _write_once(private_root / "manifests" / "information-flow-final.json", flow)
    interrupted_count = sum(
        load_json(path).get("runtime_identity") == "lumi-trace-runtime-v0.4.1-pre-release.7"
        for path in (
            work_root / "builder" / "raw" / "engineering-development" / LEARNED_RANKER
        ).glob("*.json")
    )
    interrupted = {
        "schema_version": "lumi-trace-v0.4.1-interrupted-run-disposition-v1",
        "runtime_identity": "lumi-trace-runtime-v0.4.1-pre-release.7",
        "partial_raw_output_count": interrupted_count,
        "state": "SUPERSEDED_INELIGIBLE_DEVELOPMENT_EVIDENCE",
        "reason": "STOPPED_FOR_BUILDER_RUNTIME_GUARD_REMEDIATION",
        "deleted": False,
        "model_selection_eligible": False,
        "qualification_eligible": False,
    }
    interrupted["record_id"] = stable_id(
        "v0.4.1-interrupted-run-disposition",
        interrupted,
    )
    _write_once(
        private_root / "invalidation" / "interrupted-pre-release-7.json",
        interrupted,
    )

    starting = {
        "schema_version": "lumi-trace-v0.4.1-public-starting-state-v1",
        "starting_revision": STARTING_REVISION,
        "starting_public_evidence_seal": STARTING_SEAL,
        "historical_v0_4_rewritten": False,
        "source_state_id": source_state_id,
    }
    starting["record_id"] = stable_id("v0.4.1-public-starting-state", starting)
    remediation = {
        "schema_version": "lumi-trace-v0.4.1-public-integrity-remediation-v1",
        "predecessor_defect": "GROUND_TRUTH_TARGET_ACCESS_BEFORE_RAW_RANKING_SEAL",
        "predecessor_qualification_state": "SPENT_INVALID_AUDIT_ONLY",
        "contaminated_derivatives_state": "SUPERSEDED_INVALID_EVIDENCE",
        "builder_allowed_field_projection": True,
        "target_agnostic_quarantine": True,
        "candidate_generation_label_access": False,
        "raw_output_sealed_before_scoring": True,
        "builder_filesystem_guard": True,
        "builder_network_and_subprocess_guard": True,
        "invalid_attempts_in_denominators": True,
        "final_route_metrics_recomputed_from_all_scheduled_groups": True,
        "execution_aggregate_disposition_id": aggregate_disposition["record_id"],
        "protected_holdback_opened": False,
        "information_flow_manifest_id": flow["manifest_id"],
    }
    remediation["record_id"] = stable_id(
        "v0.4.1-public-integrity-remediation",
        remediation,
    )
    data = {
        "schema_version": "lumi-trace-v0.4.1-public-data-readiness-v1",
        "eligible_raw_group_count": supply["eligible_raw_group_count"],
        "eligible_repository_count": supply["eligible_repository_count"],
        "eligible_organization_count": supply["eligible_organization_count"],
        "planned_partitions": supply["planned_partitions"],
        "decision": supply["decision"],
        "thresholds_weakened": False,
        "model_selection_opened": False,
        "qualification_opened": False,
        "protected_holdback_opened": False,
    }
    data["record_id"] = stable_id("v0.4.1-public-data-readiness", data)
    development = {
        "schema_version": "lumi-trace-v0.4.1-public-development-summary-v1",
        "runtime_identity": RUNTIME_IDENTITY,
        "candidate_algorithm": CANDIDATE_ALGORITHM,
        "quarantine_policy": QUARANTINE_POLICY,
        "routes": [deterministic, learned],
        "route_gates": {
            DETERMINISTIC_RANKER: _gate_results(deterministic["metrics"]),
            LEARNED_RANKER: _gate_results(learned["metrics"]),
        },
        "partition": "ENGINEERING_DEVELOPMENT",
        "model_selection_evidence": False,
        "qualification_evidence": False,
        "confidence_is_not_probability": True,
    }
    development["record_id"] = stable_id(
        "v0.4.1-public-development-summary",
        development,
    )
    model_summary = {
        "schema_version": "lumi-trace-v0.4.1-public-model-summary-v1",
        "model_artifact_id": model["artifact_id"],
        "status": "PRIVATE_DEVELOPMENT_CANDIDATE_NOT_QUALIFIED",
        "algorithm": model["algorithm"],
        "feature_contract": model["feature_contract"],
        "active_parameters": model["active_parameters"],
        "training_groups": receipt.get("group_count", training_manifest["group_count"]),
        "training_families": receipt.get(
            "family_count",
            training_manifest["family_count"],
        ),
        "pair_updates": model["pair_updates"],
        "completed_epochs": model["completed_epochs"],
        "bounded_classical_candidate_count": len(model_screen["results"]),
        "development_model_screen_id": model_screen["screen_id"],
        "development_selection_reason": model_screen["development_recommendation"]["reason"],
        "compact_encoder_disposition": (
            "NOT_CREDIBLE_UNDER_CURRENT_DATA_AND_SUPPLY_CHAIN_ENVELOPE"
        ),
        "exact_training_replay": receipt["exact_training_replay"],
        "foundation_model": None,
        "tokenizer": None,
        "external_weights_downloaded": False,
        "checkpoint_packaged": False,
        "public_weight_release_authorised": False,
    }
    model_summary["record_id"] = stable_id(
        "v0.4.1-public-model-summary",
        model_summary,
    )
    runtime = {
        "schema_version": "lumi-trace-v0.4.1-public-runtime-integration-v1",
        "package_version": __version__,
        "runtime_identity": RUNTIME_IDENTITY,
        "candidate_algorithm": CANDIDATE_ALGORITHM,
        "deterministic_ranker": DETERMINISTIC_RANKER,
        "learned_ranker": LEARNED_RANKER,
        "model_hash_bound": True,
        "learned_support_candidates": 1000,
        "product_cli": "localize",
        "evaluation_invokes_product_runtime": True,
        "v0_1_2_comparator_locked_by_regression_test": True,
        "installed_deterministic_replay_exact": package["installed_replay"]["deterministic"][
            "deterministic_projection_exact"
        ],
        "installed_learned_replay_exact": package["installed_replay"]["learned"][
            "deterministic_projection_exact"
        ],
        "installed_deterministic_candidate_count": package["installed_replay"]["deterministic"][
            "candidate_count"
        ],
        "installed_learned_candidate_count": package["installed_replay"]["learned"][
            "candidate_count"
        ],
        "installed_learned_nonzero_contribution": package["installed_replay"]["learned"][
            "nonzero_learned_contribution"
        ],
        "wheel_sha256": package["wheel"]["sha256"],
        "source_distribution_sha256": package["source_distribution"]["sha256"],
        "two_clean_package_builds_byte_identical": package["two_clean_builds_byte_identical"],
        "checkpoint_packaged": False,
        "final_validation_record_id": validation["record_id"],
        "final_validation_command_count": validation["command_count"],
        "final_validation_all_passed": validation["all_passed"],
    }
    runtime["record_id"] = stable_id("v0.4.1-public-runtime-integration", runtime)
    adversarial = {
        "schema_version": "lumi-trace-v0.4.1-public-adversarial-review-v1",
        "review_scope": "PREQUALIFICATION_DEVELOPMENT_STOP_THE_LINE",
        "findings": [
            {
                "id": "ADV-001",
                "severity": "CRITICAL",
                "finding": "predecessor target access before raw seal",
                "disposition": "CLOSED_BY_INVALIDATION_AND_LABEL_BLIND_REBUILD",
                "retest": "PASS",
            },
            {
                "id": "ADV-002",
                "severity": "HIGH",
                "finding": "candidate implementation changed under a stale identity",
                "disposition": "CLOSED_BY_IDENTITY_BUMP_AND_REGENERATION",
                "retest": "PASS",
            },
            {
                "id": "ADV-003",
                "severity": "HIGH",
                "finding": "builder inherited host file, socket, and process capabilities",
                "disposition": "CLOSED_BY_RUNTIME_AUDIT_GUARD",
                "retest": "PASS",
            },
            {
                "id": "ADV-004",
                "severity": "HIGH",
                "finding": "learned inference exceeded its training candidate support",
                "disposition": "CLOSED_BY_HYBRID_TOP_1000_SUPPORT_CONTRACT",
                "retest": "PASS",
            },
            {
                "id": "ADV-005",
                "severity": "HIGH",
                "finding": "failed attempts were excluded from capability denominators",
                "disposition": "CLOSED_BY_ALL_ATTEMPT_AGGREGATION",
                "retest": "PASS",
            },
        ],
        "unresolved_critical_or_high_findings": 0,
        "fresh_partition_overlap_review_completed": False,
        "reason_full_prequalification_review_incomplete": (
            "FRESH_PARTITIONS_NOT_CREATED_OR_OPENED"
        ),
        "qualification_clearance": False,
    }
    adversarial["review_id"] = stable_id(
        "v0.4.1-public-adversarial-review",
        adversarial,
    )
    qualification = {
        "schema_version": "lumi-trace-v0.4.1-public-qualification-readiness-v1",
        "decision": "QUALIFICATION_NOT_READY / CONTINUE_DEVELOPMENT",
        "integrity_restored": True,
        "product_runtime_integrated": True,
        "development_final_gates_passed": any(
            all(gate_results.values()) for gate_results in development["route_gates"].values()
        ),
        "fresh_model_selection_supply_ready": False,
        "fresh_qualification_supply_ready": False,
        "fresh_model_selection_opened": False,
        "fresh_qualification_opened": False,
        "qualification_capacity_consumed": 0,
        "confidence_bounds_available": False,
        "guard_bands_evaluated": False,
        "full_adversarial_review_complete": False,
        "protected_holdback_opened": False,
        "deterministic_route_claim_authorised": False,
        "learned_capability_claim_authorised": False,
    }
    qualification["record_id"] = stable_id(
        "v0.4.1-public-qualification-readiness",
        qualification,
    )
    resource = {
        "schema_version": "lumi-trace-v0.4.1-public-resource-summary-v1",
        "model_size_bytes": model_path.stat().st_size,
        "active_parameters": model["active_parameters"],
        "cpu_inference": True,
        "gpu_required": False,
        "installed_fixture_replay": {
            route: {
                key: value
                for key, value in package["installed_replay"][route].items()
                if key
                in {
                    "candidate_count",
                    "maximum_wall_seconds",
                    "maximum_cpu_seconds",
                    "maximum_peak_python_bytes",
                    "network_used",
                    "repository_code_executed",
                }
            }
            for route in ("deterministic", "learned")
        },
        "development_peak_memory_measured": learned["telemetry"][
            "peak_memory_measurement_available"
        ],
        "sixteen_gib_large_repository_envelope_qualified": False,
        "reason_envelope_not_qualified": "FRESH_QUALIFICATION_NOT_READY",
    }
    resource["record_id"] = stable_id("v0.4.1-public-resource-summary", resource)
    boundary = {
        "schema_version": "lumi-trace-v0.4.1-public-boundary-review-v1",
        "decision": "APPROVED_AGGREGATE_ONLY",
        "third_party_source_included": False,
        "case_or_label_substance_included": False,
        "repository_paths_or_symbols_included": False,
        "private_checkpoint_included": False,
        "customer_data_included": False,
        "protected_holdback_substance_included": False,
        "local_absolute_paths_included": False,
        "weight_publication_authorised": False,
        "repository_publication_authorised": False,
    }
    boundary["review_id"] = stable_id(
        "v0.4.1-public-boundary-review",
        boundary,
    )
    closure = {
        "schema_version": "lumi-trace-v0.4.1-public-closure-v1",
        "state": "QUALIFICATION_NOT_READY / CONTINUE_DEVELOPMENT",
        "integrity_remediation": "COMPLETE",
        "candidate_generation": "LABEL_BLIND_PRODUCT_INTEGRATED",
        "ranking": (
            "DEVELOPMENT_FINAL_GATES_PASSED_FRESH_SELECTION_BLOCKED"
            if qualification["development_final_gates_passed"]
            else "DEVELOPMENT_CANDIDATES_RETAINED_FINAL_GATES_NOT_MET"
        ),
        "data_supply": supply["decision"],
        "model_selection": "NOT_OPENED",
        "qualification": "NOT_OPENED_OR_CONSUMED",
        "protected_holdback": "SEALED_UNOPENED",
        "pilot": "NOT_READY",
        "release": "NOT_AUTHORISED",
        "public_weight_release": "NOT_AUTHORISED",
        "deterministic_route_claim": "NOT_MADE",
    }
    closure["closure_id"] = stable_id("v0.4.1-public-closure", closure)
    continuation = {
        "schema_version": "lumi-trace-v0.4.1-public-continuation-package-v1",
        "state": "READY_TO_RESUME_DEVELOPMENT",
        "required_external_data": {
            "additional_model_selection_raw_groups": max(
                0,
                supply["planned_partitions"]["MODEL_SELECTION_FRESH"]["raw_target"]
                - supply["planned_partitions"]["MODEL_SELECTION_FRESH"]["raw_group_count"],
            ),
            "additional_qualification_raw_groups": max(
                0,
                supply["planned_partitions"]["QUALIFICATION_FRESH"]["raw_target"]
                - supply["planned_partitions"]["QUALIFICATION_FRESH"]["raw_group_count"],
            ),
            "model_selection_family_gap": max(
                0,
                15 - supply["planned_partitions"]["MODEL_SELECTION_FRESH"]["family_count"],
            ),
            "qualification_family_gap": max(
                0,
                15 - supply["planned_partitions"]["QUALIFICATION_FRESH"]["family_count"],
            ),
        },
        "resume_conditions": [
            "NEW_RIGHTS_APPROVED_INDEPENDENT_PUBLIC_SOURCE_SUPPLY",
            "DEVELOPMENT_SHORTLIST_AND_SELECTION_RULE_LOCKED",
            "FRESH_PARTITION_INDEPENDENCE_GATES_PASS",
        ],
        "next_actions": [
            "ACQUIRE_ADDITIONAL_INDEPENDENT_SOURCE_FAMILIES",
            "CONTINUE_ROLE_AND_HARD_NEGATIVE_DEVELOPMENT",
            "LOCK_AT_MOST_THREE_CANDIDATES",
            "OPEN_FRESH_MODEL_SELECTION_ONLY_AFTER_SUPPLY_AND_LOCK_GATES",
        ],
        "qualification_or_holdback_action_authorised": False,
    }
    continuation["record_id"] = stable_id(
        "v0.4.1-public-continuation-package",
        continuation,
    )
    documents = {
        "starting-state.json": starting,
        "integrity-remediation.json": remediation,
        "data-readiness.json": data,
        "development-summary.json": development,
        "model-summary.json": model_summary,
        "runtime-integration.json": runtime,
        "adversarial-review.json": adversarial,
        "qualification-readiness.json": qualification,
        "resource-summary.json": resource,
        "public-boundary-review.json": boundary,
        "closure-record.json": closure,
        "continuation-package.json": continuation,
    }
    _assert_public_safe(documents)
    for name, value in documents.items():
        _write_once(evidence_root / name, value)
    members = [
        {
            "path": name,
            "sha256": sha256_file(evidence_root / name),
            "size_bytes": (evidence_root / name).stat().st_size,
        }
        for name in sorted(documents)
    ]
    manifest = {
        "schema_version": "lumi-trace-v0.4.1-public-evidence-seal-v1",
        "source_state_id": source_state_id,
        "members": members,
        "public_boundary_review_id": boundary["review_id"],
        "closure_id": closure["closure_id"],
    }
    manifest["seal_id"] = stable_id(
        "lumi-trace-v0.4.1-public-evidence",
        manifest,
    )
    _write_once(evidence_root / "seal-manifest.json", manifest)
    private_status = {
        "schema_version": "lumi-trace-v0.4.1-current-status-v1",
        "evidence_integrity": "RESTORED",
        "data_readiness": "EXTERNAL_DATA_SUPPLY_INSUFFICIENT",
        "candidate_generation_readiness": "LABEL_BLIND_MEASURED",
        "ranking_readiness": "DEVELOPMENT_CONTINUES",
        "product_runtime_readiness": "INTEGRATED_NOT_QUALIFIED",
        "model_selection_readiness": "NOT_READY_NOT_OPENED",
        "qualification_readiness": "NOT_READY_NOT_OPENED",
        "release_readiness": "NOT_READY",
        "closure": closure["state"],
        "public_evidence_seal": manifest["seal_id"],
        "qualification_consumed": False,
        "holdback_opened": False,
    }
    private_status["status_id"] = stable_id("v0.4.1-current-status", private_status)
    _write_once(private_root / "manifests" / "current-status-final.json", private_status)
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--model", type=Path, required=True)
    result.add_argument("--model-receipt", type=Path, required=True)
    result.add_argument("--validation-record", type=Path, required=True)
    result.add_argument("--model-screen-record", type=Path, required=True)
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
    result.add_argument(
        "--evidence-root",
        type=Path,
        default=PROJECT_ROOT / "evidence" / "v0.4.1",
    )
    return result


def main() -> int:
    try:
        manifest = seal(parser().parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"seal-v0.4.1: {exc}", file=sys.stderr)
        return 2
    print(manifest["seal_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
