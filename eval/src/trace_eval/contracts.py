# SPDX-License-Identifier: Apache-2.0
"""Schema-validated canonical record contracts for Trace-Eval V0.2."""

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
}

_SCHEMA = json.loads(
    files("trace_eval.schemas")
    .joinpath("trace-eval-contract-v0.2.json")
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
