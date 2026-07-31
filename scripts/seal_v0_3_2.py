# SPDX-License-Identifier: Apache-2.0
"""Project governed V0.3.2 results into disclosure-safe aggregate evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import dump_json, load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.package import verify_package  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402
from trace_eval.runner import load_run_package  # noqa: E402
from verify_v0_3_1_evidence import verify as verify_v0_3_1_evidence  # noqa: E402

VERSION = "v0.3.2"
EXPECTED_V031_SEAL = (
    "lumi-trace-v0.3.1-public-evidence:"
    "e06658ab3ab0b6f1d9085f1d3f5d0c672f7d4283d5e554f0305452e8492f567f"
)
EXPECTED_V010_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
EXPECTED_V012_WHEEL = "sha256:6c674f15eb2d0178e3d0054d05dd733127981e640e8891fe37c135d394d42173"
EXPECTED_EVALUATOR = "sha256:1edf6597313106c7b546d666b018655b3ef76a90234a2e93079b1e5dba59e122"
RUNTIME_SOURCE_REVISION = "1b7d4e713e367d1a1c98b54a03b47cd3978db36f"
_REVISION = re.compile(r"^[0-9a-f]{40}$")


def _require_root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _resource_projection(run_root: Path) -> dict[str, Any]:
    _, attempts, _ = load_run_package(run_root)
    observations = [
        attempt.get("observations", {})
        for attempt in attempts
        if isinstance(attempt.get("observations"), dict)
    ]
    failures = Counter(
        str(code) for attempt in attempts for code in attempt["payload"].get("failure_codes", [])
    )
    terminations = Counter(str(item.get("termination_reason", "UNKNOWN")) for item in observations)
    return {
        "attempt_count": len(attempts),
        "completed_attempts": sum(
            attempt["payload"]["status"] == "COMPLETED" for attempt in attempts
        ),
        "failed_attempts": sum(attempt["payload"]["status"] != "COMPLETED" for attempt in attempts),
        "failure_code_counts": dict(sorted(failures.items())),
        "termination_reason_counts": dict(sorted(terminations.items())),
        "total_wall_time_ms": sum(int(item.get("wall_time_ms") or 0) for item in observations),
        "total_cpu_time_ms": sum(int(item.get("cpu_time_ms") or 0) for item in observations),
        "attempts_with_cpu_time": sum(
            int(item.get("cpu_time_ms") or 0) > 0 for item in observations
        ),
        "maximum_wall_time_ms": max(
            (int(item.get("wall_time_ms") or 0) for item in observations), default=0
        ),
        "maximum_peak_resident_bytes": max(
            (int(item.get("peak_resident_bytes") or 0) for item in observations), default=0
        ),
        "retained_artifact_bytes": sum(
            int(item.get("retained_artifact_bytes") or 0) for item in observations
        ),
        "retained_log_bytes": sum(
            int(item.get("retained_log_bytes") or 0) for item in observations
        ),
        "cache_states": dict(
            sorted(
                Counter(str(item.get("cache_state", "UNKNOWN")) for item in observations).items()
            )
        ),
    }


def _metric_projection(
    aggregate: dict[str, Any], *, schema_version: str, runtime_version: str
) -> dict[str, Any]:
    payload = aggregate["payload"]
    return {
        "schema_version": schema_version,
        "runtime_version": runtime_version,
        "aggregate_record_id": aggregate["record_id"],
        "metric_spec_id": payload["metric_spec_id"],
        "micro": deepcopy(payload["micro"]),
        "repository_family_macro": deepcopy(payload["repository_family_macro"]),
        "strata_counts": deepcopy(payload["strata"]),
        "excluded_counts": deepcopy(payload["excluded"]),
    }


def _diagnostic_projection(private_root: Path) -> dict[str, Any]:
    diagnostic_root = private_root / "manifests" / VERSION / "resource-diagnostic"
    verify_package(diagnostic_root)
    value = load_json(diagnostic_root / "resource-failure-classification.json")["payload"]
    classifications = value["classifications"]
    return {
        "schema_version": "lumi-trace-v0.3.2-resource-diagnostic-summary-v1",
        "attempt_count": value["attempt_count"],
        "completed_attempts": value["completed_attempts"],
        "resource_failure_count": len(classifications),
        "failure_code_counts": value["failure_counts"],
        "classification": "INSUFFICIENT_HARD_WALL_FOR_BOUNDED_COLD_INDEXING",
        "maximum_repository_bytes": max(item["repository_bytes"] for item in classifications),
        "maximum_repository_file_count": max(
            item["repository_file_count"] for item in classifications
        ),
        "maximum_peak_resident_bytes": max(item["peak_resident_bytes"] for item in classifications),
        "original_runtime_wall_limit_ms": max(
            item["runtime_wall_time_ms"] for item in classifications
        ),
        "remediation": value["remediation"],
        "final_hard_wall_seconds": 600,
        "process_tree_termination_required": True,
    }


def seal(args: argparse.Namespace) -> dict[str, Any]:
    active = _require_root(args.active_root, "F:")
    private = _require_root(args.private_root, "G:")
    if _REVISION.fullmatch(args.source_revision) is None:
        raise ValueError("source revision must be a 40-character implementation commit")
    previous_manifest = verify_v0_3_1_evidence(ROOT / "evidence" / "v0.3.1")
    if previous_manifest["seal_id"] != EXPECTED_V031_SEAL:
        raise ValueError("V0.3.1 public evidence is not the immutable starting seal")

    baseline_root = private / "manifests" / VERSION / "baseline-v0.1.1"
    control_root = private / "manifests" / VERSION / "control-v0.1.2-cpu-sealed"
    lock_root = private / "manifests" / VERSION / "capability-lock-v0.1.2-cpu-sealed"
    baseline_package = verify_package(baseline_root)
    control_package = verify_package(control_root)
    lock_package = verify_package(lock_root)
    capability_lock = load_json(lock_root / "capability-lock.json")
    if (
        capability_lock["source_revision"] != RUNTIME_SOURCE_REVISION
        or capability_lock["runtime_wheel_sha256"] != EXPECTED_V012_WHEEL
        or capability_lock["evaluator_wheel_sha256"] != EXPECTED_EVALUATOR
    ):
        raise ValueError("capability lock differs from the sealed artifacts")

    development_root = active / "runs" / VERSION / "development-v0.1.2-cpu-sealed"
    development_replay = active / "runs" / VERSION / "development-v0.1.2-cpu-sealed-replay"
    development_resource = _resource_projection(development_root)
    replay = load_json(development_replay / "replay-verification.json")["payload"]
    qualification_authorised = capability_lock["qualification_authorised"] is True
    qualification_root = private / "manifests" / VERSION / "qualification-v0.1.2-cpu-sealed"
    if qualification_authorised and not qualification_root.is_dir():
        raise ValueError("authorised qualification must be sealed before public evidence")
    if not qualification_authorised and qualification_root.exists():
        raise ValueError("qualification evidence exists without a development authorisation")

    qualification_run = qualification_root.is_dir()
    qualification_decision: dict[str, Any] | None = None
    qualification_aggregate: dict[str, Any] | None = None
    qualification_resource: dict[str, Any] | None = None
    qualification_package_id: str | None = None
    qualification_passed = False
    consumed_runs = 0
    if qualification_run:
        qualification_package_id = verify_package(qualification_root)["package_id"]
        qualification_decision = load_json(qualification_root / "qualification-decision.json")
        qualification_aggregate = load_json(qualification_root / "aggregate-metrics.json")
        budget_after = load_json(qualification_root / "qualification-budget-after.json")
        consumed_runs = budget_after["payload"]["consumed_runs"]
        qualification_passed = (
            qualification_decision["payload"]["threshold_decision"]["passed"] is True
        )
        qualification_resource = _resource_projection(
            active / "runs" / VERSION / "qualification-v0.1.2-cpu-sealed"
        )

    closure_state = (
        "CAPABILITY_QUALIFIED / PILOT_READY"
        if qualification_passed
        else "CAPABILITY_RECOVERED / CORPUS_SCALE_REQUIRED"
    )
    baseline_metrics = _metric_projection(
        load_json(baseline_root / "aggregate-metrics.json"),
        schema_version="lumi-trace-v0.3.2-public-v0.1.1-baseline-v1",
        runtime_version="0.1.1",
    )
    capability_metrics = _metric_projection(
        load_json(lock_root / "aggregate-metrics.json"),
        schema_version="lumi-trace-v0.3.2-public-development-aggregate-v1",
        runtime_version="0.1.2",
    )
    qualification_metrics = {
        "schema_version": "lumi-trace-v0.3.2-public-qualification-aggregate-v1",
        "run": qualification_run,
        "aggregate": (
            _metric_projection(
                qualification_aggregate,
                schema_version="lumi-trace-v0.3.2-public-qualification-metrics-v1",
                runtime_version="0.1.2",
            )
            if qualification_aggregate is not None
            else None
        ),
    }
    provenance = {
        "schema_version": "lumi-trace-v0.3.2-public-provenance-v1",
        "source_revision": args.source_revision,
        "runtime_source_revision": RUNTIME_SOURCE_REVISION,
        "previous_public_evidence_seal": EXPECTED_V031_SEAL,
        "original_runtime_artifact_sha256": EXPECTED_V010_WHEEL,
        "runtime_version": "0.1.2",
        "runtime_artifact_sha256": EXPECTED_V012_WHEEL,
        "runtime_reproducible_builds": True,
        "evaluator_version": "0.3.3",
        "evaluator_artifact_sha256": EXPECTED_EVALUATOR,
        "evaluator_reproducible_builds": True,
        "baseline_package_id": baseline_package["package_id"],
        "control_package_id": control_package["package_id"],
        "capability_lock_package_id": lock_package["package_id"],
        "qualification_package_id": qualification_package_id,
        "development_replay_identity_agreement": replay["identity_agreement"],
        "development_replay_semantic_agreement": replay["semantic_agreement"],
    }
    contract = {
        "schema_version": "lumi-trace-v0.3.2-public-contract-recovery-v1",
        "score_reason_canonical_maximum": 20,
        "boundary_cases_tested": [0, 1, 8, 9, 10, 20, 21],
        "producer_verifier_schema_agreement": True,
        "package_installed_execution": True,
        "runtime_v0_1_1_clean_builds_byte_identical": True,
        "runtime_v0_1_2_clean_builds_byte_identical": True,
        "evaluator_v0_3_3_clean_builds_byte_identical": True,
        "superseded_failed_experiments_preserved": True,
    }
    resource = {
        "schema_version": "lumi-trace-v0.3.2-public-resource-summary-v1",
        "diagnostic": _diagnostic_projection(private),
        "development": development_resource,
        "qualification": qualification_resource,
        "declared_hardware_envelope": {
            "cpu_only_supported": True,
            "memory_limit_bytes": 2_147_483_648,
            "case_disk_limit_bytes": 134_217_728,
            "case_wall_limit_seconds": 600,
            "pid_limit": 64,
            "maximum_index_json_items": 900_000,
            "maximum_index_tokens": 250_000,
            "maximum_index_symbols": 50_000,
        },
        "networked_reproduction_runs": 0,
        "repository_controlled_code_executed": False,
    }
    capability = {
        "schema_version": "lumi-trace-v0.3.2-public-capability-decision-v1",
        "all_development_attempts_completed": capability_lock["all_attempts_completed"],
        "replay_identity_agreement": capability_lock["replay_identity_agreement"],
        "replay_semantic_agreement": capability_lock["replay_semantic_agreement"],
        "threshold_checks": capability_lock["threshold_checks"],
        "performance_gates_passed": capability_lock["performance_gates_passed"],
        "qualification_authorised": qualification_authorised,
        "qualification_evidence_used_for_development": False,
        "case_specific_rules_added": False,
        "evaluated_envelope": "PYTHON_SECURITY_FINDING_LOCALISATION",
    }
    qualification = {
        "schema_version": "lumi-trace-v0.3.2-public-qualification-summary-v1",
        "run": qualification_run,
        "maximum_runs": 1,
        "consumed_runs": consumed_runs,
        "budget_state": "SPENT" if consumed_runs == 1 else "UNUSED",
        "passed": qualification_passed if qualification_run else None,
        "used_for_threshold_selection": False,
        "used_for_remediation": False,
        "holdback_opened": False,
    }
    corpus_gap = {
        "schema_version": "lumi-trace-v0.3.2-public-corpus-rights-gap-v1",
        "evaluation_only_groups": 58,
        "evaluation_repository_families": 10,
        "training_eligible_groups": 0,
        "training_eligible_repository_families": 0,
        "required_training_groups": 500,
        "required_training_repository_families": 25,
        "evaluation_material_repurposed_for_training": False,
    }
    readiness = {
        "schema_version": "lumi-trace-v0.3.2-training-readiness-decision-v1",
        "recommendation": "DO_NOT_BEGIN_TRACE_001",
        "all_entry_gates_satisfied": False,
        "training_started": False,
        "weights_downloaded": False,
        "weights_produced": False,
        "model_provider_used": False,
        "training_data_groups": 0,
        "training_repository_families": 0,
        "primary_blockers": [
            "INSUFFICIENT_TRAINING_ELIGIBLE_GROUPS",
            "INSUFFICIENT_TRAINING_ELIGIBLE_REPOSITORY_FAMILIES",
            "TRAINING_RIGHTS_NOT_ESTABLISHED",
            "PROTECTED_HOLDBACK_UNOPENED",
        ],
    }
    trace_ir = {
        "schema_version": "lumi-trace-v0.3.2-trace-ir-boundary-v1",
        "feasibility_lane_run": False,
        "new_trace_ir_artifacts": 0,
        "attack_detection_claim": False,
        "live_integrations": False,
        "response_actions": False,
    }
    review = {
        "schema_version": "lumi-trace-v0.3.2-public-boundary-review-v1",
        "review_type": "CONTROLLED_INTERNAL_RELEASE_REVIEW",
        "third_party_repository_source_present": False,
        "source_excerpts_present": False,
        "case_level_findings_present": False,
        "case_level_locations_present": False,
        "repository_or_case_identifiers_present": False,
        "vulnerable_revisions_present": False,
        "fixing_diffs_present": False,
        "raw_run_outputs_present": False,
        "private_paths_present": False,
        "reviewer_notes_present": False,
        "credentials_present": False,
        "model_weights_or_training_data_present": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "trace_001_decision": "NO_GO",
    }
    closure = {
        "schema_version": "lumi-trace-v0.3.2-public-closure-v1",
        "closure_state": closure_state,
        "runtime_version": "0.1.2",
        "capability": "DETERMINISTIC_PYTHON_SECURITY_FINDING_LOCALISATION",
        "qualification_run": qualification_run,
        "qualification_passed": qualification_passed,
        "qualification_budget_consumed": consumed_runs,
        "trace_001_training": False,
        "weights": 0,
        "holdback_opened": False,
        "public_release": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "next_commercial_validation_step": (
            "CONTROLLED_LOCAL_PILOT_WITH_CUSTOMER_OWNED_REPOSITORIES"
        ),
    }
    documents: dict[str, Any] = {
        "baseline-provenance.json": provenance,
        "capability-decision.json": capability,
        "capability-development-aggregate.json": capability_metrics,
        "closure-record.json": closure,
        "contract-recovery.json": contract,
        "corpus-and-rights-gap.json": corpus_gap,
        "first-valid-baseline-aggregate.json": baseline_metrics,
        "public-boundary-review.json": review,
        "qualification-aggregate.json": qualification_metrics,
        "qualification-summary.json": qualification,
        "resource-summary.json": resource,
        "trace-ir-boundary.json": trace_ir,
        "training-readiness-decision.json": readiness,
    }
    public_root = ROOT / "evidence" / VERSION
    if public_root.exists():
        raise ValueError("refusing to overwrite V0.3.2 public evidence")
    public_root.mkdir(parents=True)
    for name, value in sorted(documents.items()):
        verify_public_document(value)
        dump_json(public_root / name, value)
    artifacts = [
        {
            "path": name,
            "sha256": sha256_file(public_root / name),
            "size_bytes": (public_root / name).stat().st_size,
        }
        for name in sorted(documents)
    ]
    manifest = {
        "schema_version": "lumi-trace-v0.3.2-public-evidence-seal-v1",
        "source_revision": args.source_revision,
        "artifacts": artifacts,
    }
    manifest["seal_id"] = stable_id("lumi-trace-v0.3.2-public-evidence", manifest)
    dump_json(public_root / "seal-manifest.json", manifest)
    return {
        "seal_id": manifest["seal_id"],
        "artifact_count": len(artifacts),
        "closure_state": closure_state,
        "qualification_budget_consumed": consumed_runs,
        "publication_decision": closure["publication_decision"],
        "training_recommendation": readiness["recommendation"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_revision")
    parser.add_argument("--active-root", type=Path, default=Path("F:/Data/skylark-lumi-trace-eval"))
    parser.add_argument(
        "--private-root", type=Path, default=Path("G:/Data/skylark-lumi-trace-eval")
    )
    try:
        result = seal(parser.parse_args())
    except (OSError, ValueError, ContractError, PolicyError) as exc:
        print(f"seal-v0.3.2: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
