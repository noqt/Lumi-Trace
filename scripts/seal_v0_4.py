# SPDX-License-Identifier: Apache-2.0
"""Project governed V0.4 assurance into disclosure-safe public evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
for source_path in (EVAL_SRC, ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.canonical import dump_json, load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402

from scripts.run_v0_4_experiments import _active_final_authority_paths  # noqa: E402
from scripts.verify_v0_3_2_evidence import verify as verify_v0_3_2_evidence  # noqa: E402

VERSION = "v0.4"
EXPECTED_V032_SEAL = (
    "lumi-trace-v0.3.2-public-evidence:"
    "c2d944aa8ac9880584555c64c95063f39ef8fdc56ec7d91fffda445b41091c77"
)
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_FORBIDDEN_PUBLIC_KEYS = {
    "audit_card_id",
    "audit_card_ids",
    "candidate_id",
    "feature_record_ids",
    "family_id",
    "family_ids",
    "fixing_revision",
    "group_id",
    "group_ids",
    "labels",
    "private_targets",
    "repository",
    "repository_id",
    "repository_token",
    "source_record_id",
    "source_record_ids",
    "target_paths",
    "training_candidates",
    "vulnerable_revision",
}


def _require_private_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != "g:" or not resolved.is_dir():
        raise ValueError("governed private G: root is unavailable")
    return resolved


def _assert_disclosure_safe(value: Any) -> None:
    def visit(item: Any) -> None:
        if isinstance(item, dict):
            forbidden = set(item) & _FORBIDDEN_PUBLIC_KEYS
            if forbidden:
                raise PolicyError(
                    f"V0_4_PUBLIC_PROJECTION_FORBIDDEN_FIELDS:{','.join(sorted(forbidden))}"
                )
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    verify_public_document(value)


def _algorithm_projection(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        name: {
            "aggregate": value["aggregate"],
            "confidence_intervals": value["confidence_intervals"],
            "gate_results": value["gate_results"],
            "all_gates_passed": value["all_gates_passed"],
        }
        for name, value in sorted(summary["algorithms"].items())
    }


def _trace_projection(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return {
        "partition": summary["partition"],
        "group_count": summary["group_count"],
        "family_count": summary["family_count"],
        "views": summary["views"],
        "family_improvement_count": summary["family_improvement_count"],
        "family_regression_count": summary["family_regression_count"],
        "resources": summary["resources"],
        "cue_ablation_views_complete": summary["cue_ablation_views_complete"],
        "labels_applied_after_ranking": summary["labels_applied_after_ranking"],
        "network_used": summary["network_used"],
    }


def seal(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_private_root(args.private_root)
    if _REVISION.fullmatch(args.source_revision) is None:
        raise ValueError("source revision must be a 40-character implementation commit")
    previous = verify_v0_3_2_evidence(ROOT / "evidence" / "v0.3.2")
    if previous["seal_id"] != EXPECTED_V032_SEAL:
        raise PolicyError("V0_3_2_PUBLIC_EVIDENCE_SEAL_MISMATCH")
    corpus = load_json(private_root / "disclosure-safe" / "corpus-aggregate-final.json")
    development = load_json(
        private_root / "manifests" / "baseline-final-dev-idf-engineering-development.json"
    )
    model_selection = load_json(
        private_root / "manifests" / "baseline-final-model-idf-model-selection.json"
    )
    gates_path, readiness_path = _active_final_authority_paths(private_root)
    final_gates = load_json(gates_path)
    readiness = load_json(readiness_path)
    qualification_lock = load_json(private_root / "manifests" / "qualification-lock.json")
    qualification = load_json(private_root / "manifests" / "qualification-result.json")
    training_receipt_path = private_root / "manifests" / "trace-001-training-receipt.json"
    training_receipt = load_json(training_receipt_path) if training_receipt_path.is_file() else None
    trace_development_path = (
        private_root / "manifests" / "trace-001-final-dev-idf-engineering-development.json"
    )
    trace_model_path = private_root / "manifests" / "trace-001-final-model-idf-model-selection.json"
    trace_development = (
        load_json(trace_development_path) if trace_development_path.is_file() else None
    )
    trace_model = load_json(trace_model_path) if trace_model_path.is_file() else None
    if (
        corpus["all_corpus_floors_passed"] is not True
        or corpus["cross_partition_family_count"] != 0
        or corpus["holdback_opened"] is not False
        or development["partition"] != "ENGINEERING_DEVELOPMENT"
        or model_selection["partition"] != "MODEL_SELECTION"
        or development["qualification_consumed"] is not False
        or model_selection["qualification_consumed"] is not False
        or final_gates["holdback_opened"] is not False
        or qualification["qualification_consumed"] is not True
        or qualification["qualification_runs_consumed"] != 1
        or qualification["qualification_runs_remaining"] != 0
        or qualification["holdback_opened"] is not False
        or qualification["group_count"] < 97
        or qualification["family_count"] < 8
        or qualification["matched_safe_control_count"] < 97
    ):
        raise PolicyError("V0_4_PRIVATE_EVIDENCE_NOT_SEALABLE")
    recommendation = readiness["payload"]["recommendation"]
    trained = training_receipt is not None
    if (
        (recommendation == "TRACE_001_EXECUTION_AUTHORISED") != trained
        or (trace_development is None) != (trace_model is None)
        or (trained and (trace_development is None or trace_model is None))
    ):
        raise PolicyError("V0_4_TRAINING_EVIDENCE_INCONSISTENT")
    selected = qualification_lock["selected_candidate"]
    qualification_passed = qualification["selected_result"]["all_gates_passed"]
    if qualification_passed and selected["kind"] == "TRACE_001_LINEAR":
        closure_state = "TRACE_001_VALIDATED / CONTROLLED_PILOT_READY"
    elif qualification_passed:
        closure_state = "DETERMINISTIC_GENERALISATION_QUALIFIED / CONTROLLED_PILOT_READY"
    elif trained:
        closure_state = "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE"
    else:
        closure_state = "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION"
    starting = {
        "schema_version": "lumi-trace-v0.4-public-starting-state-v1",
        "source_revision": args.source_revision,
        "previous_public_evidence_seal": EXPECTED_V032_SEAL,
        "historical_v0_3_2_evidence_unchanged": True,
        "spent_v0_3_2_qualification_used_for_development": False,
        "cybergym_tasks_used": False,
        "historical_holdback_used": False,
    }
    corpus_public = {
        "schema_version": "lumi-trace-v0.4-public-corpus-assurance-v1",
        "group_count": corpus["group_count"],
        "family_count": corpus["family_count"],
        "state_counts": corpus["state_counts"],
        "partition_counts": corpus["partition_counts"],
        "partition_assurance_counts": corpus["partition_counts"],
        "largest_family_group_count": corpus["largest_family_group_count"],
        "corpus_floors": corpus["corpus_floors"],
        "all_corpus_floors_passed": corpus["all_corpus_floors_passed"],
        "duplicate_cluster_count": corpus["duplicate_cluster_count"],
        "cross_partition_family_count": corpus["cross_partition_family_count"],
        "training_family_group_cap": corpus["training_family_group_cap"],
        "training_family_cap_excluded_count": corpus["training_family_cap_excluded_count"],
        "policy_reconsideration_count": corpus["policy_reconsideration_count"],
        "terminalized_unselected_proposal_count": corpus["terminalized_unselected_proposal_count"],
        "quarantined_unassigned_candidate_count": corpus["quarantined_unassigned_candidate_count"],
        "contains_case_identities": False,
        "contains_source_or_labels": False,
        "contains_private_paths": False,
        "repository_code_executed_during_intake": False,
    }
    partitions = {
        "schema_version": "lumi-trace-v0.4-public-partition-assurance-v1",
        "counts": corpus["partition_counts"],
        "family_disjoint": corpus["cross_partition_family_count"] == 0,
        "sealed_before_training": True,
        "qualification_single_use": True,
        "qualification_runs_consumed": 1,
        "qualification_used_for_tuning": False,
        "protected_holdback_state": "SEALED_UNOPENED",
        "protected_holdback_opened": False,
    }
    baselines = {
        "schema_version": "lumi-trace-v0.4-public-baseline-comparators-v1",
        "metric_scope": "PYTHON_FINDING_GUIDED_CANDIDATE_RANKING_ONLY",
        "development": {
            "group_count": development["group_count"],
            "family_count": development["family_count"],
            "algorithms": _algorithm_projection(development),
        },
        "model_selection": {
            "group_count": model_selection["group_count"],
            "family_count": model_selection["family_count"],
            "algorithms": _algorithm_projection(model_selection),
        },
        "v0_1_2_frozen": True,
        "thresholds_locked_before_model_selection": True,
        "universal_abstention_can_pass": False,
    }
    training = {
        "schema_version": "lumi-trace-v0.4-public-training-readiness-v1",
        "recommendation": recommendation,
        "gates": final_gates["gates"],
        "training_group_count": readiness["payload"]["group_count"],
        "training_family_count": readiness["payload"]["family_count"],
        "training_started": trained,
        "weights_downloaded": False,
        "external_model_or_tokenizer_used": False,
        "hosted_service_used": False,
        "protected_holdback_opened": False,
    }
    trace_experiment = {
        "schema_version": "lumi-trace-v0.4-public-trace-001-experiment-v1",
        "run": trained,
        "model_origin": "FROM_SCRATCH_LINEAR" if trained else None,
        "active_parameters": (training_receipt["active_parameters"] if training_receipt else 0),
        "clean_reproduction_match": (
            training_receipt["clean_reproduction_match"] if training_receipt else None
        ),
        "quantization_regression": (
            training_receipt["quantization_regression"] if training_receipt else None
        ),
        "training_resources": (training_receipt["resources"] if training_receipt else None),
        "development": _trace_projection(trace_development),
        "model_selection": _trace_projection(trace_model),
        "model_selection_advanced": selected["kind"] == "TRACE_001_LINEAR",
        "weight_files_published": False,
        "public_weight_release_authorised": False,
    }
    qualification_public = {
        "schema_version": "lumi-trace-v0.4-public-qualification-summary-v1",
        "selected_candidate_kind": selected["kind"],
        "selection_reason": selected["reason"],
        "group_count": qualification["group_count"],
        "family_count": qualification["family_count"],
        "matched_safe_control_count": qualification["matched_safe_control_count"],
        "selected_result_name": qualification["selected_result_name"],
        "selected_result": qualification["selected_result"],
        "comparators": qualification["comparators"],
        "passed": qualification_passed,
        "maximum_runs": 1,
        "consumed_runs": 1,
        "remaining_runs": 0,
        "used_for_tuning": False,
        "thresholds_changed_after_opening": False,
        "python_network_denial_enforced": qualification["python_network_denial_enforced"],
        "protected_holdback_opened": False,
    }
    resources = {
        "schema_version": "lumi-trace-v0.4-public-resource-summary-v1",
        "training": (training_receipt["resources"] if training_receipt else None),
        "trace_development": (trace_development["resources"] if trace_development else None),
        "trace_model_selection": (trace_model["resources"] if trace_model else None),
        "qualification_wall_seconds": qualification["wall_seconds"],
        "local_cpu_capable": True,
        "networked_inference_runs": 0,
        "repository_controlled_code_executed": False,
    }
    review = {
        "schema_version": "lumi-trace-v0.4-public-boundary-review-v1",
        "review_type": "CONTROLLED_INTERNAL_RELEASE_REVIEW",
        "third_party_repository_contents_present": False,
        "case_level_source_present": False,
        "case_level_labels_present": False,
        "case_level_paths_or_locations_present": False,
        "repository_or_case_identifiers_present": False,
        "private_paths_present": False,
        "credentials_present": False,
        "customer_data_present": False,
        "cybergym_material_present": False,
        "historical_lumi_evidence_added": False,
        "protected_holdback_content_present": False,
        "model_weight_files_present": False,
        "training_data_present": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "weight_publication_decision": "NO_GO_PENDING_USER_REVIEW",
    }
    closure = {
        "schema_version": "lumi-trace-v0.4-public-closure-v1",
        "closure_state": closure_state,
        "qualification_passed": qualification_passed,
        "qualification_budget_consumed": 1,
        "training_run": trained,
        "active_parameters": (training_receipt["active_parameters"] if training_receipt else 0),
        "weight_files_published": False,
        "protected_holdback_opened": False,
        "public_release": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "next_step": (
            "CONTROLLED_CUSTOMER_OWNED_SHADOW_PILOT"
            if qualification_passed
            else "DETERMINISTIC_ROUTE_AND_NEW_INDEPENDENT_EVIDENCE"
        ),
    }
    pilot = {
        "schema_version": "lumi-trace-v0.4-public-pilot-package-v1",
        "readiness": ("CONTROLLED_PILOT_READY" if qualification_passed else "NOT_READY"),
        "supported_use": (
            "Finding-guided Python candidate ranking on authorised local repositories."
        ),
        "excluded_claims": [
            "vulnerability discovery",
            "automated repair",
            "attack detection",
            "safe-repository certification",
        ],
        "customer_data": "LOCAL_EVALUATION_ONLY",
        "hosted_inference": False,
        "api_keys_required": False,
        "protected_holdback_opened": False,
        "human_review_required": True,
    }
    documents = {
        "baseline-comparators.json": baselines,
        "closure-record.json": closure,
        "corpus-assurance.json": corpus_public,
        "partition-assurance.json": partitions,
        "pilot-package.json": pilot,
        "public-boundary-review.json": review,
        "qualification-summary.json": qualification_public,
        "resource-summary.json": resources,
        "starting-state.json": starting,
        "trace-001-experiment.json": trace_experiment,
        "training-readiness.json": training,
    }
    public_root = ROOT / "evidence" / VERSION
    if public_root.exists():
        raise ValueError("refusing to overwrite V0.4 public evidence")
    public_root.mkdir(parents=True)
    for name, value in sorted(documents.items()):
        _assert_disclosure_safe(value)
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
        "schema_version": "lumi-trace-v0.4-public-evidence-seal-v1",
        "source_revision": args.source_revision,
        "artifacts": artifacts,
    }
    manifest["seal_id"] = stable_id("lumi-trace-v0.4-public-evidence", manifest)
    dump_json(public_root / "seal-manifest.json", manifest)
    return {
        "seal_id": manifest["seal_id"],
        "artifact_count": len(artifacts),
        "closure_state": closure_state,
        "qualification_passed": qualification_passed,
        "training_run": trained,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "protected_holdback_opened": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_revision")
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    try:
        result = seal(parser.parse_args())
    except (ContractError, PolicyError, OSError, ValueError) as exc:
        print(f"seal-v0.4: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
