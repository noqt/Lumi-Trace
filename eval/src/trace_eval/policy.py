# SPDX-License-Identifier: Apache-2.0
"""Fail-closed rights, split, exposure, leakage, and holdback policy."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import validate_record
from .errors import PolicyError

EXPOSURE_STATES = {
    "CONSTRUCTION_VISIBLE",
    "DEVELOPMENT_VISIBLE",
    "EVALUATOR_ONLY",
    "FROZEN_UNOPENED",
    "EXPOSED_AFTER_SEALED_RUN",
    "RETIRED",
}
PARTITIONS = {
    "public_regression",
    "future_training_candidate",
    "development",
    "qualification",
    "frozen_holdback",
}
RUN_MODES = {"public-fixture", "development", "qualification"}
FAILURE_CODES = {
    "RIGHTS_OR_PROVENANCE_REJECTED",
    "SPLIT_OR_LINEAGE_VIOLATION",
    "EXPOSURE_POLICY_VIOLATION",
    "INPUT_OR_LABEL_INVALID",
    "SNAPSHOT_FAILED",
    "TARGET_NOT_INDEXABLE",
    "INDEX_BUDGET_EXHAUSTED",
    "TARGET_NOT_GENERATED",
    "TARGET_RANKED_BELOW_CUTOFF",
    "HARD_NEGATIVE_OUTRANKED_TARGET",
    "REPRODUCTION_UNSUPPORTED",
    "REPRODUCTION_INFRASTRUCTURE_FAILURE",
    "WITNESS_NOT_OBSERVED",
    "FALSE_CONFIRMATION",
    "DETERMINISM_MISMATCH",
    "REPLAY_MISMATCH",
    "RESOURCE_LIMIT_REACHED",
    "RUNNER_OR_SCHEMA_FAILURE",
    "METRIC_OR_REPORT_INCONSISTENCY",
}

_TRANSITIONS = {
    "CONSTRUCTION_VISIBLE": {"DEVELOPMENT_VISIBLE", "EVALUATOR_ONLY", "RETIRED"},
    "DEVELOPMENT_VISIBLE": {"EVALUATOR_ONLY", "RETIRED"},
    "EVALUATOR_ONLY": {"EXPOSED_AFTER_SEALED_RUN", "RETIRED"},
    "FROZEN_UNOPENED": set(),
    "EXPOSED_AFTER_SEALED_RUN": {"RETIRED"},
    "RETIRED": set(),
}
_LABEL_WORD = re.compile(r"(?i)(?:^|_)(?:accepted_target|ground_truth|label|witness_truth)(?:_|$)")
_SECRET_WORD = re.compile(
    r"(?i)(?:^|_)(?:api_key|auth|credential|password|private_key|secret|session|token)(?:_|$)"
)
_ABSOLUTE_PATH = re.compile(r"(?i)(?:[A-Z]:[\\/]|/(?:home|Users|var|private)/)")


def verify_rights(record: dict[str, Any], *, mode: str) -> None:
    validate_record(record)
    if record["schema_version"] != "repository-rights-manifest-v1":
        raise PolicyError("rights verification requires repository-rights-manifest-v1")
    payload = record["payload"]
    required_strings = (
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
    )
    if any(
        not isinstance(payload.get(key), str) or not payload[key].strip()
        for key in required_strings
    ):
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: incomplete rights metadata")
    if payload["exposure_state"] not in EXPOSURE_STATES:
        raise PolicyError("EXPOSURE_POLICY_VIOLATION: unknown exposure state")
    hashes = payload.get("input_hashes")
    if (
        not isinstance(hashes, list)
        or not hashes
        or any(
            not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
            for item in hashes
        )
    ):
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: immutable input hashes are required")
    if payload["review_status"] not in {"CONTROLLED_REVIEWED", "SKYLARK_AUTHORED"}:
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: rights review is not complete")
    if mode == "public-fixture" and (
        payload["redistribution_status"] != "PUBLIC_REDISTRIBUTION_PERMITTED"
        or payload["exposure_state"] not in {"CONSTRUCTION_VISIBLE", "DEVELOPMENT_VISIBLE"}
    ):
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED: material is not a public fixture")
    if payload["exposure_state"] == "FROZEN_UNOPENED":
        raise PolicyError("EXPOSURE_POLICY_VIOLATION: frozen holdback cannot be scheduled")


def verify_transition(record: dict[str, Any]) -> None:
    validate_record(record)
    if record["schema_version"] != "exposure-transition-v1":
        raise PolicyError("transition record has the wrong schema")
    payload = record["payload"]
    source = payload["from_state"]
    target = payload["to_state"]
    if source not in EXPOSURE_STATES or target not in EXPOSURE_STATES:
        raise PolicyError("EXPOSURE_POLICY_VIOLATION: unknown transition state")
    if source == "FROZEN_UNOPENED":
        raise PolicyError("EXPOSURE_POLICY_VIOLATION: this build cannot open frozen holdback")
    if target not in _TRANSITIONS[source]:
        raise PolicyError(f"EXPOSURE_POLICY_VIOLATION: invalid transition {source} -> {target}")


def _fingerprints(payload: dict[str, Any]) -> set[str]:
    values = payload.get("content_fingerprints", [])
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise PolicyError("SPLIT_OR_LINEAGE_VIOLATION: content fingerprints are malformed")
    return set(values)


def audit_repository_independence(
    repositories: list[dict[str, Any]], split_record: dict[str, Any], *, near_duplicate: float = 0.8
) -> dict[str, Any]:
    validate_record(split_record)
    if split_record["schema_version"] != "split-manifest-v1":
        raise PolicyError("split audit requires split-manifest-v1")
    split_payload = split_record["payload"]
    if split_payload["locked"] is not True:
        raise PolicyError("SPLIT_OR_LINEAGE_VIOLATION: split manifest is not locked")
    assignments = split_payload["repositories"]
    if not isinstance(assignments, dict):
        raise PolicyError("SPLIT_OR_LINEAGE_VIOLATION: repository assignments are malformed")
    violations: list[dict[str, str]] = []
    seen: dict[str, tuple[str, str]] = {}
    parsed: list[tuple[dict[str, Any], str]] = []
    for record in repositories:
        validate_record(record)
        if record["schema_version"] != "repository-rights-manifest-v1":
            raise PolicyError("split audit received a non-repository record")
        payload = record["payload"]
        repository_id = payload["repository_id"]
        split = assignments.get(repository_id)
        if split not in PARTITIONS:
            raise PolicyError(f"SPLIT_OR_LINEAGE_VIOLATION: {repository_id} has no valid split")
        parsed.append((payload, split))
        for kind, value in (
            ("tree", payload["tree_id"]),
            ("lineage", payload["lineage_id"]),
            ("family", payload["family_id"]),
            ("history", payload.get("shared_history_root", "")),
        ):
            if not value:
                continue
            previous = seen.get(f"{kind}:{value}")
            if previous is not None and previous[1] != split:
                violations.append({"kind": kind, "first": previous[0], "second": repository_id})
            seen[f"{kind}:{value}"] = (repository_id, split)
    for index, (left, left_split) in enumerate(parsed):
        left_values = _fingerprints(left)
        for right, right_split in parsed[index + 1 :]:
            if left_split == right_split:
                continue
            right_values = _fingerprints(right)
            union = left_values | right_values
            similarity = len(left_values & right_values) / len(union) if union else 0.0
            if similarity >= near_duplicate:
                violations.append(
                    {
                        "kind": "near-duplicate",
                        "first": left["repository_id"],
                        "second": right["repository_id"],
                    }
                )
    if violations:
        raise PolicyError(f"SPLIT_OR_LINEAGE_VIOLATION: {violations}")
    return {"repository_count": len(parsed), "violations": [], "disjoint": True}


def assert_runner_blind(value: Any, *, location: str = "runner input") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _LABEL_WORD.search(key):
                raise PolicyError(f"INPUT_OR_LABEL_INVALID: label field reached {location}")
            assert_runner_blind(item, location=location)
    elif isinstance(value, list):
        for item in value:
            assert_runner_blind(item, location=location)


def sanitize_environment(source: Mapping[str, str], *, temp_root: Path) -> dict[str, str]:
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "TZ",
    }
    result = {key: value for key, value in source.items() if key.upper() in allowed}
    for key in source:
        if _LABEL_WORD.search(key) or _SECRET_WORD.search(key):
            continue
    result.update(
        {
            "HOME": str(temp_root),
            "TMP": str(temp_root),
            "TEMP": str(temp_root),
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
            "TZ": "UTC",
        }
    )
    assert_runner_blind(result, location="runner environment")
    return result


def verify_public_document(value: Any) -> None:
    def visit(item: Any, path: tuple[str, ...]) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {"source_text", "finding_text", "private_path", "accepted_targets"}:
                    raise PolicyError(
                        f"public output contains protected field: {'.'.join((*path, key))}"
                    )
                visit(child, (*path, key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, (*path, str(index)))
        elif isinstance(item, str) and _ABSOLUTE_PATH.search(item):
            raise PolicyError(f"public output contains an absolute private path: {'.'.join(path)}")

    visit(value, ())


def safe_relative_path(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if not value or path.is_absolute() or ".." in path.parts:
        raise PolicyError("runner path must be safe and repository-relative")
    return path.as_posix()
