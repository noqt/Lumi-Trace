# SPDX-License-Identifier: Apache-2.0
"""Immutable registry loading, validation, and label separation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, dump_json, load_json, stable_id
from .contracts import validate_record, verify_records
from .errors import ContractError, PolicyError
from .policy import (
    RUN_MODES,
    assert_runner_blind,
    audit_repository_independence,
    safe_relative_path,
    verify_rights,
    verify_transition,
)


def registry_identity(records: list[dict[str, Any]]) -> str:
    return stable_id("trace-eval-registry", {"records": records})


def write_registry(path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    verify_records(records)
    document = {
        "schema_version": "trace-eval-registry-file-v1",
        "records": records,
        "registry_id": registry_identity(records),
    }
    dump_json(path, document)
    return document


def load_registry(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict) or set(value) != {"schema_version", "records", "registry_id"}:
        raise ContractError("registry file fields are invalid")
    if value["schema_version"] != "trace-eval-registry-file-v1" or not isinstance(
        value["records"], list
    ):
        raise ContractError("registry file schema is invalid")
    records = verify_records(value["records"])
    if value["registry_id"] != registry_identity(records):
        raise ContractError("registry identity mismatch")
    return value


def records_by_schema(registry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    return [record for record in registry["records"] if record["schema_version"] == schema_version]


def validate_registry(registry: dict[str, Any], *, mode: str) -> dict[str, Any]:
    if mode not in RUN_MODES:
        raise PolicyError("ordinary runner modes exclude frozen holdback")
    repositories = records_by_schema(registry, "repository-rights-manifest-v1")
    groups = records_by_schema(registry, "candidate-ranking-group-v1")
    splits = records_by_schema(registry, "split-manifest-v1")
    transitions = records_by_schema(registry, "exposure-transition-v1")
    if len(splits) != 1:
        raise ContractError("registry must contain exactly one split manifest")
    for repository in repositories:
        verify_rights(repository, mode=mode)
    audit = audit_repository_independence(repositories, splits[0])
    for transition in transitions:
        verify_transition(transition)
    rights_ids = {record["record_id"] for record in repositories}
    rights_by_id = {record["record_id"]: record for record in repositories}
    repository_ids = {record["payload"]["repository_id"] for record in repositories}
    expected_partition = {
        "public-fixture": "public_regression",
        "development": "development",
        "qualification": "qualification",
    }[mode]
    schedulable = 0
    for group in groups:
        validate_record(group)
        payload = group["payload"]
        if payload["rights_id"] not in rights_ids or payload["repository_id"] not in repository_ids:
            raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: group has no governed repository")
        rights = rights_by_id[payload["rights_id"]]["payload"]
        if (
            payload["repository_id"] != rights["repository_id"]
            or payload["repository_tree_id"] != rights["tree_id"]
            or payload["exposure_state"] != rights["exposure_state"]
        ):
            raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: group and repository identity differ")
        input_hashes = payload["input_hashes"]
        if (
            not isinstance(input_hashes, list)
            or payload["repository_tree_id"] not in input_hashes
            or any(
                not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                for item in input_hashes
            )
        ):
            raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: group input hashes are incomplete")
        if payload["exposure_state"] == "FROZEN_UNOPENED":
            raise PolicyError("EXPOSURE_POLICY_VIOLATION: frozen group cannot be scheduled")
        if payload["split"] != expected_partition:
            continue
        runner_inputs = payload["runner_inputs"]
        if not isinstance(runner_inputs, dict):
            raise ContractError("group runner_inputs must be an object")
        assert_runner_blind(runner_inputs)
        for key in ("repository", "finding"):
            if not isinstance(runner_inputs.get(key), str):
                raise ContractError(f"group runner_inputs.{key} is required")
            safe_relative_path(runner_inputs[key])
        schedulable += 1
    if schedulable == 0:
        raise PolicyError(f"registry has no schedulable groups for {mode}")
    canonical_bytes(registry)
    return {"valid": True, "mode": mode, "groups": schedulable, "independence": audit}
