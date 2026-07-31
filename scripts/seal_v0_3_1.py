# SPDX-License-Identifier: Apache-2.0
"""Project private V0.3.1 results into a disclosure-safe public evidence seal."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import dump_json, load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.contracts import make_record  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.intake import enforce_publication_decision  # noqa: E402
from trace_eval.package import verify_package  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402
from trace_eval.registry import load_registry, records_by_schema  # noqa: E402
from trace_eval.runner import load_run_package  # noqa: E402

VERSION = "v0.3.1"
EXPECTED_V03_SEAL = (
    "lumi-trace-v0.3-public-evidence:"
    "a56044b38ff78687739a9d01ea32697c57f5b45d67063e8babf9931cc2da7b70"
)
EXPECTED_V01_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
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
    failure_codes = Counter(
        str(code) for attempt in attempts for code in attempt["payload"].get("failure_codes", [])
    )
    return {
        "attempt_count": len(attempts),
        "completed_attempts": sum(
            attempt["payload"]["status"] == "COMPLETED" for attempt in attempts
        ),
        "failed_attempts": sum(attempt["payload"]["status"] != "COMPLETED" for attempt in attempts),
        "failure_code_counts": dict(sorted(failure_codes.items())),
        "total_wall_time_ms": sum(int(item.get("wall_time_ms") or 0) for item in observations),
        "maximum_wall_time_ms": max(
            (int(item.get("wall_time_ms") or 0) for item in observations),
            default=0,
        ),
        "total_cpu_time_ms": sum(int(item.get("cpu_time_ms") or 0) for item in observations),
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


def seal(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_root(args.active_root, "F:")
    private_root = _require_root(args.private_root, "G:")
    if _REVISION.fullmatch(args.source_revision) is None:
        raise ValueError("source revision must be the 40-character implementation commit")
    corpus_root = private_root / "manifests" / VERSION / "corpus"
    control_root = private_root / "manifests" / VERSION / "pre-run"
    decisions_root = private_root / "manifests" / VERSION / "decisions"
    corpus_package = verify_package(corpus_root)
    control_package = verify_package(control_root)
    verify_package(decisions_root)
    construction = load_json(corpus_root / "construction-summary.json")
    governance = load_registry(corpus_root / "governance-records.json")
    distribution = records_by_schema(governance, "corpus-distribution-v1")[0]
    pre_run = load_json(control_root / "pre-run-seal.json")
    threshold = load_json(decisions_root / "development-threshold-decision.json")
    closure = load_json(decisions_root / "v0.3.1-closure.json")
    enforce_publication_decision(closure)
    development_aggregate = load_json(decisions_root / "development-aggregate-copy.json")
    qualification_aggregate_path = decisions_root / "qualification-aggregate-copy.json"
    qualification_aggregate = (
        load_json(qualification_aggregate_path) if qualification_aggregate_path.is_file() else None
    )
    run_root = active_root / "runs" / VERSION
    development_resource = _resource_projection(run_root / "development-raw")
    qualification_resource = (
        _resource_projection(run_root / "qualification-raw")
        if closure["payload"]["qualification_run"]
        else None
    )
    replay = load_json(run_root / "development-replay" / "replay-verification.json")
    public_root = ROOT / "evidence" / VERSION
    if public_root.exists():
        raise ValueError("refusing to overwrite V0.3.1 public evidence")
    public_root.mkdir(parents=True)
    evaluator_hash = "sha256:" + pre_run["payload"]["evaluator_id"].rsplit("sha256:", 1)[1]
    provenance = {
        "schema_version": "lumi-trace-v0.3.1-public-baseline-provenance-v1",
        "source_revision": args.source_revision,
        "previous_public_evidence_seal": EXPECTED_V03_SEAL,
        "runtime_version": "0.1.0",
        "runtime_artifact_sha256": EXPECTED_V01_WHEEL,
        "runtime_changed": False,
        "evaluator_version": "0.3.1",
        "evaluator_artifact_sha256": evaluator_hash,
        "evaluator_reproducible_builds": True,
        "corpus_package_id": corpus_package["package_id"],
        "pre_run_package_id": control_package["package_id"],
        "pre_run_seal_id": pre_run["record_id"],
        "development_run_id": threshold["payload"]["development_run_id"],
        "raw_sealed_before_labels": True,
        "replay_identity_agreement": replay["payload"]["identity_agreement"],
        "replay_semantic_agreement": replay["payload"]["semantic_agreement"],
    }
    corpus_summary = {
        "schema_version": "lumi-trace-v0.3.1-public-corpus-summary-v1",
        "proposed_repository_families": 10,
        "acquired_repository_families": 10,
        "admitted_repository_families": construction["accepted_repository_families"],
        "proposed_security_pairs": 30,
        "accepted_security_pairs": construction["accepted_security_cases"],
        "rejected_security_pairs": construction["rejected_security_cases"],
        "accepted_groups": construction["accepted_groups"],
        "sufficiency": construction["sufficiency"],
        "partitions": distribution["payload"]["partitions"],
        "state_counts": distribution["payload"]["state_counts"],
        "role_counts": distribution["payload"]["role_counts"],
        "language_counts": distribution["payload"]["language_counts"],
        "weakness_counts": distribution["payload"]["weakness_counts"],
        "evidence_strength_counts": distribution["payload"]["evidence_strength_counts"],
        "safe_control_count": distribution["payload"]["safe_control_count"],
        "hard_negative_count": distribution["payload"]["hard_negative_count"],
        "missing_strata": distribution["payload"]["missing_strata"],
        "cross_partition_overlap_count": len(construction["split_audit"]["violations"]),
        "future_training_use_permitted": False,
    }
    threshold_summary = {
        "schema_version": "lumi-trace-v0.3.1-public-threshold-decision-v1",
        "decision": threshold["payload"]["decision"],
        "checks": threshold["payload"]["thresholds"],
        "integrity_floors": threshold["payload"]["integrity_floors"],
        "remediation_class": threshold["payload"]["remediation_class"],
        "qualification_authorised": threshold["payload"]["qualification_authorised"],
        "qualification_evidence_used": False,
        "decided_before_qualification": True,
        "execution_integrity": {
            "all_attempts_completed": (
                development_resource["completed_attempts"] == development_resource["attempt_count"]
            ),
            "replay_identity_agreement": replay["payload"]["identity_agreement"],
            "replay_semantic_agreement": replay["payload"]["semantic_agreement"],
        },
    }
    budget = load_json(decisions_root / "qualification-budget-final.json")
    qualification_summary = {
        "schema_version": "lumi-trace-v0.3.1-public-qualification-summary-v1",
        "run": closure["payload"]["qualification_run"],
        "maximum_runs": budget["payload"]["maximum_runs"],
        "consumed_runs": budget["payload"]["consumed_runs"],
        "budget_state": budget["payload"]["state"],
        "aggregate_present": qualification_aggregate is not None,
        "used_for_threshold_selection": False,
        "used_for_remediation": False,
    }
    qualification_envelope = {
        "schema_version": "lumi-trace-v0.3.1-public-qualification-aggregate-v1",
        "run": closure["payload"]["qualification_run"],
        "aggregate": qualification_aggregate,
    }
    readiness = make_record(
        "training-readiness-decision-v1",
        {
            "recommendation": "DO_NOT_BEGIN_TRACE_001",
            "closure_state": closure["payload"]["closure_state"],
            "gates": [
                {
                    "gate": "500_useful_labelled_groups",
                    "status": "UNMET / EVIDENCE_REQUIRED",
                    "observed": construction["accepted_groups"],
                    "required": 500,
                },
                {
                    "gate": "25_unrelated_training_repositories",
                    "status": "UNMET / EVIDENCE_REQUIRED",
                    "observed": construction["accepted_repository_families"],
                    "required": 25,
                },
                {
                    "gate": "future_training_rights",
                    "status": "UNMET / EVIDENCE_REQUIRED",
                    "observed": False,
                    "required": True,
                },
                {
                    "gate": "protected_holdback",
                    "status": "UNMET / UNOPENED",
                    "observed": "FROZEN_UNOPENED",
                    "required": "SEPARATELY_APPROVED_AND_AUDITED",
                },
                {
                    "gate": "explicit_training_authority",
                    "status": "UNMET / EVIDENCE_REQUIRED",
                    "observed": False,
                    "required": True,
                },
            ],
            "training_started": False,
            "weights_downloaded": False,
        },
    )
    resource = {
        "schema_version": "lumi-trace-v0.3.1-public-resource-summary-v1",
        "development": development_resource,
        "qualification": qualification_resource,
        "networked_reproduction_runs": 0,
        "repository_build_or_test_runs": 0,
    }
    trace_ir = {
        "schema_version": "lumi-trace-v0.3.1-trace-ir-boundary-v1",
        "state": "IR_FEASIBILITY_SUPPORTED_UNCHANGED",
        "new_trace_ir_artifacts": 0,
        "live_integrations": False,
        "response_actions": False,
        "attack_detection_claim": False,
    }
    review = {
        "schema_version": "lumi-trace-v0.3.1-public-boundary-review-v1",
        "review_type": "CONTROLLED_INTERNAL_RELEASE_REVIEW",
        "third_party_repository_source_present": False,
        "source_excerpts_present": False,
        "case_level_findings_present": False,
        "case_level_locations_present": False,
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
    documents: dict[str, Any] = {
        "baseline-provenance.json": provenance,
        "closure-record.json": closure,
        "development-aggregate-metrics.json": development_aggregate,
        "natural-corpus-summary.json": corpus_summary,
        "public-boundary-review.json": review,
        "qualification-aggregate-metrics.json": qualification_envelope,
        "qualification-summary.json": qualification_summary,
        "resource-summary.json": resource,
        "threshold-decision.json": threshold_summary,
        "trace-ir-boundary.json": trace_ir,
        "training-readiness-decision.json": readiness,
    }
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
    seal_record = {
        "schema_version": "lumi-trace-v0.3.1-public-evidence-seal-v1",
        "source_revision": args.source_revision,
        "artifacts": artifacts,
    }
    seal_record["seal_id"] = stable_id("lumi-trace-v0.3.1-public-evidence", seal_record)
    dump_json(public_root / "seal-manifest.json", seal_record)
    return {
        "seal_id": seal_record["seal_id"],
        "artifact_count": len(artifacts),
        "closure_state": closure["payload"]["closure_state"],
        "publication_decision": closure["payload"]["publication_decision"],
        "training_recommendation": closure["payload"]["training_recommendation"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_revision")
    parser.add_argument(
        "--active-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval"),
    )
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval"),
    )
    args = parser.parse_args()
    try:
        result = seal(args)
    except (OSError, ValueError, ContractError, PolicyError) as exc:
        print(f"seal-v0.3.1: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
