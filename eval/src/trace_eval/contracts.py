# SPDX-License-Identifier: Apache-2.0
"""Schema-validated canonical record contracts for Trace-Eval."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import stable_id
from .errors import ContractError

REQUIRED_PAYLOAD_FIELDS: dict[str, set[str]] = {
    "environment-qualification-v1": {
        "environment",
        "sut",
        "evaluator",
        "roots",
        "facts",
        "isolation",
    },
    "repository-rights-manifest-v1": {
        "repository_id",
        "tree_id",
        "source",
        "acquisition_method",
        "licence",
        "rights_basis",
        "redistribution_status",
        "review_status",
        "lineage_id",
        "family_id",
        "exposure_state",
        "governed_location",
        "input_hashes",
    },
    "candidate-ranking-group-v1": {
        "group_id",
        "repository_id",
        "finding_id",
        "rights_id",
        "split",
        "case_class",
        "origin",
        "taxonomy",
        "runner_inputs",
        "label_set_id",
        "repository_tree_id",
        "exposure_state",
        "input_hashes",
    },
    "label-set-v1": {
        "label_set_id",
        "group_id",
        "targets",
        "matching_rule",
        "review_receipt_ids",
        "corrections",
    },
    "split-manifest-v1": {"partitions", "repositories", "locked", "independence_method"},
    "exposure-transition-v1": {"subject_id", "from_state", "to_state", "decision_receipt_id"},
    "evaluator-configuration-v1": {
        "runtime",
        "mode",
        "limits",
        "offline",
        "k_max",
        "metric_spec_id",
    },
    "metric-specification-v1": {
        "cutoffs",
        "k_max",
        "region_overlap",
        "denominators",
        "aggregation",
        "integrity_floors",
    },
    "registry-snapshot-v1": {"repositories", "groups", "split_manifest_id", "exposure_log_ids"},
    "run-record-v1": {
        "run_id",
        "mode",
        "runtime_id",
        "registry_id",
        "configuration_id",
        "attempt_ids",
        "raw_output_seal_id",
    },
    "attempt-record-v1": {
        "attempt_id",
        "run_id",
        "group_id",
        "status",
        "failure_codes",
        "output_artifacts",
        "stage",
    },
    "case-result-v1": {
        "group_id",
        "attempt_id",
        "label_set_id",
        "indexability",
        "ranking",
        "reproduction",
        "failure_codes",
    },
    "raw-output-seal-v1": {"run_id", "artifacts", "sealed_before_labels", "runner_view_hash"},
    "replay-verification-v1": {
        "run_id",
        "replay_run_id",
        "identity_agreement",
        "semantic_agreement",
        "mismatches",
    },
    "aggregate-metrics-v1": {
        "run_id",
        "metric_spec_id",
        "case_result_ids",
        "micro",
        "repository_macro",
        "strata",
        "failures",
    },
    "controlled-review-receipt-v1": {
        "role",
        "method",
        "input_hashes",
        "decision",
        "disagreements",
        "corrections",
    },
    "qualification-decision-v1": {
        "closure_state",
        "runtime_id",
        "evaluator_id",
        "evidence_ids",
        "threshold_decision",
        "holdback_opened",
    },
    "training-readiness-decision-v1": {
        "recommendation",
        "closure_state",
        "gates",
        "training_started",
        "weights_downloaded",
    },
    "programme-boundary-v1": {
        "version",
        "authority",
        "permitted_activities",
        "prohibited_sources",
        "training_authorised",
        "weights_acquired",
        "holdback_state",
    },
    "natural-corpus-registry-v1": {
        "repositories",
        "groups",
        "accepted_group_count",
        "accepted_repository_count",
        "sufficiency",
        "private_evidence_location",
    },
    "trace-code-location-label-v1": {
        "group_id",
        "label_state",
        "repository_id",
        "repository_family",
        "expected_disposition",
        "targets",
        "primary_role",
        "hard_negatives",
        "safe_control",
        "review_receipt_ids",
        "corrections",
        "constructed_without_runner_output",
    },
    "trace-code-metric-specification-v1": {
        "cutoffs",
        "matching",
        "denominators",
        "primary_metrics",
        "aggregation",
        "integrity_floors",
    },
    "trace-code-metric-specification-v2": {
        "cutoffs",
        "matching",
        "denominators",
        "primary_metrics",
        "aggregation",
        "integrity_floors",
    },
    "trace-code-case-result-v1": {
        "group_id",
        "repository_id",
        "repository_family",
        "label_state",
        "safe_control",
        "expected_disposition",
        "observed_disposition",
        "ranking",
        "indexability",
        "failures",
        "taxonomy",
    },
    "trace-code-aggregate-metrics-v1": {
        "metric_spec_id",
        "case_result_ids",
        "micro",
        "repository_macro",
        "repository_family_macro",
        "strata",
        "excluded",
    },
    "repository-lineage-audit-v1": {
        "repository_count",
        "partitions",
        "cross_partition_overlap_count",
        "methods",
        "holdback_opened",
    },
    "trace-ir-event-v1": {
        "episode_id",
        "order",
        "source_type",
        "source_id",
        "action",
        "outcome",
        "references",
        "redaction_status",
        "provenance",
        "rights",
    },
    "trace-ir-episode-v1": {
        "episode_id",
        "scenario_family",
        "generator_lineage",
        "partition",
        "event_ids",
        "provenance",
        "rights",
    },
    "trace-ir-label-v1": {
        "episode_id",
        "label_state",
        "relevant_event_ids",
        "chain_edges",
        "review_receipt_ids",
    },
    "trace-ir-result-v1": {
        "episode_id",
        "ranked_events",
        "proposed_chain",
        "supporting_fields",
        "missing_evidence",
        "disposition",
        "abstention_reason",
        "action_available",
    },
    "trace-ir-metrics-v1": {
        "episode_count",
        "event_metrics",
        "episode_metrics",
        "chain_metrics",
        "safety",
        "replay",
        "resources",
    },
    "trace-ir-feasibility-decision-v1": {
        "lane_state",
        "evidence_ids",
        "live_integrations",
        "response_actions",
        "performance_claim",
    },
    "v0.3-closure-v1": {
        "programme_state",
        "ir_lane_state",
        "natural_corpus",
        "threshold_decision",
        "qualification_run",
        "holdback_opened",
        "training_recommendation",
        "training_started",
        "weights_acquired",
        "publication_decision",
        "evidence_ids",
    },
    "intake-proposal-v1": {
        "proposed_repository_id",
        "canonical_upstream_url",
        "hosting_provider",
        "requested_revisions",
        "licence_evidence_location",
        "security_evidence_references",
        "expected_language",
        "expected_weakness_classes",
        "project_family",
        "known_fork_lineage",
        "proposed_use",
        "expected_retention",
        "operator_id",
        "decision_identity",
        "acquisition_state",
    },
    "acquisition-decision-v1": {
        "proposal_id",
        "decision",
        "from_state",
        "to_state",
        "reviewer_role",
        "rights_precheck",
        "decided_before_fetch",
        "rationale",
    },
    "rights-dimensions-v1": {
        "proposal_id",
        "exact_revision",
        "licence_identifier",
        "licence_file_hash",
        "source_access",
        "private_evaluation",
        "source_redistribution",
        "finding_use",
        "label_use",
        "future_training_use_reviewed",
        "future_training_use_permitted",
        "weight_licence",
        "review_status",
    },
    "acquisition-receipt-v1": {
        "proposal_id",
        "decision_id",
        "canonical_upstream_url",
        "requested_revision",
        "resolved_revision",
        "commit_object_hash",
        "tree_object_hash",
        "transport",
        "transport_hashes",
        "snapshot_tree_id",
        "licence_file_hash",
        "lineage_id",
        "family_id",
        "state",
        "retention_location",
        "safety_controls",
        "scan",
        "repository_code_executed",
    },
    "revision-pair-v1": {
        "pair_id",
        "repository_id",
        "vulnerability_lineage_id",
        "security_evidence_ids",
        "vulnerable_revision",
        "fixed_revision",
        "vulnerable_tree_id",
        "fixed_tree_id",
        "label_construction_state",
    },
    "finding-cue-profile-v1": {
        "group_id",
        "finding_id",
        "available_cues",
        "withheld_cues",
        "fixing_diff_in_runner_input",
        "label_fields_in_runner_input",
        "ablation_of_group_id",
        "counts_toward_natural_total",
    },
    "natural-group-review-v1": {
        "group_id",
        "label_id",
        "reviewer_role",
        "security_evidence_verified",
        "licence_revision_verified",
        "roles_verified",
        "ambiguity_state",
        "ranking_output_available",
        "fixing_diff_available",
        "decision",
        "corrections",
    },
    "corpus-distribution-v1": {
        "accepted_groups",
        "rejected_groups",
        "repositories",
        "partitions",
        "state_counts",
        "role_counts",
        "language_counts",
        "weakness_counts",
        "evidence_strength_counts",
        "safe_control_count",
        "hard_negative_count",
        "missing_strata",
    },
    "pre-run-seal-v1": {
        "runtime_id",
        "runtime_artifact_hash",
        "evaluator_id",
        "registry_id",
        "split_manifest_id",
        "metric_spec_id",
        "threshold_policy",
        "runner_blindness_verified",
        "qualification_budget_id",
        "sealed_artifact_hashes",
        "sealed_before_execution",
    },
    "qualification-budget-v1": {
        "split_manifest_id",
        "maximum_runs",
        "consumed_runs",
        "state",
        "consumption_receipt_ids",
    },
    "natural-threshold-decision-v1": {
        "development_run_id",
        "decision",
        "thresholds",
        "integrity_floors",
        "remediation_class",
        "qualification_authorised",
        "qualification_evidence_used",
        "decided_before_qualification",
    },
    "v0.3.1-closure-v1": {
        "closure_state",
        "natural_corpus_state",
        "development_run",
        "qualification_run",
        "qualification_budget_consumed",
        "holdback_opened",
        "trace_ir_state",
        "training_recommendation",
        "training_started",
        "weights_acquired",
        "publication_decision",
        "evidence_ids",
    },
    "starting-state-verification-v1": {
        "source_revision",
        "v0_3_1_evidence_seal",
        "v0_1_0_runtime_hash",
        "v0_3_1_evaluator_hash",
        "governed_roots",
        "verified",
    },
    "runtime-contract-decision-v1": {
        "runtime_version",
        "candidate_schema",
        "ranking_algorithm",
        "score_reason_match_limit",
        "producer_verifier_schema_agreement",
        "ranking_behavior_preserved",
        "regression_manifest_id",
    },
    "resource-failure-classification-v1": {
        "runtime_version",
        "configuration_id",
        "attempt_count",
        "completed_attempts",
        "failure_counts",
        "classifications",
        "remediation",
    },
    "deterministic-experiment-v1": {
        "experiment_id",
        "runtime_version",
        "algorithm",
        "development_only",
        "hypothesis",
        "configuration_id",
        "result_id",
        "decision",
    },
    "v0.3.2-closure-v1": {
        "closure_state",
        "supported_envelope",
        "runtime_version",
        "evaluator_version",
        "development_run",
        "qualification_run",
        "qualification_budget_consumed",
        "training_run",
        "weights_acquired",
        "holdback_opened",
        "publication_decision",
        "training_recommendation",
        "evidence_ids",
    },
}

_SCHEMA = json.loads(
    files("trace_eval.schemas")
    .joinpath("trace-eval-contract-v0.3.3.json")
    .read_text(encoding="utf-8")
)
_VALIDATOR = Draft202012Validator(_SCHEMA)


def _identity_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in {"record_id", "observations"}}


def make_record(
    schema_version: str, payload: dict[str, Any], *, observations: dict[str, Any] | None = None
) -> dict[str, Any]:
    prefix = schema_version.removesuffix("-v1")
    record: dict[str, Any] = {
        "schema_version": schema_version,
        "record_id": "",
        "identity_exclusions": ["observations"],
        "payload": payload,
    }
    if observations is not None:
        record["observations"] = observations
    record["record_id"] = stable_id(prefix, _identity_payload(record))
    validate_record(record)
    return record


def validate_record(value: Any) -> dict[str, Any]:
    errors = sorted(_VALIDATOR.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        raise ContractError(f"record schema rejected input: {errors[0].message}")
    assert isinstance(value, dict)
    schema_version = value["schema_version"]
    payload = value["payload"]
    required = REQUIRED_PAYLOAD_FIELDS[schema_version]
    missing = sorted(required - set(payload))
    if missing:
        raise ContractError(f"{schema_version} payload is missing: {', '.join(missing)}")
    expected = stable_id(schema_version.removesuffix("-v1"), _identity_payload(value))
    if value["record_id"] != expected:
        raise ContractError(f"{schema_version} identity mismatch")
    return value


def verify_records(values: list[Any]) -> list[dict[str, Any]]:
    records = [validate_record(value) for value in values]
    ids = [record["record_id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ContractError("record collection contains duplicate identities")
    return records
