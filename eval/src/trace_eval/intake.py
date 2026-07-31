# SPDX-License-Identifier: Apache-2.0
"""Fail-closed V0.3.1 natural-corpus intake and admission controls.

This module deliberately contains no repository catalogue.  It validates
private intake records and produces a fixed, inert Git transport plan; an
operator must execute that plan only after a separate approval record exists.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .canonical import sha256_bytes
from .contracts import validate_record
from .errors import ContractError, PolicyError

APPROVED_CODE_LICENCES = frozenset({"Apache-2.0", "MIT", "BSD-3-Clause"})
INTAKE_STATES = (
    "PROPOSED",
    "RIGHTS_PRECHECK_PASSED",
    "ACQUISITION_APPROVED",
    "ACQUIRED_UNADMITTED",
    "ADMITTED_FOR_EVALUATION",
    "REJECTED",
    "RETIRED",
)
STATE_TRANSITIONS = frozenset(
    {
        ("PROPOSED", "RIGHTS_PRECHECK_PASSED"),
        ("PROPOSED", "REJECTED"),
        ("RIGHTS_PRECHECK_PASSED", "ACQUISITION_APPROVED"),
        ("RIGHTS_PRECHECK_PASSED", "REJECTED"),
        ("ACQUISITION_APPROVED", "ACQUIRED_UNADMITTED"),
        ("ACQUISITION_APPROVED", "REJECTED"),
        ("ACQUIRED_UNADMITTED", "ADMITTED_FOR_EVALUATION"),
        ("ACQUIRED_UNADMITTED", "REJECTED"),
        ("ADMITTED_FOR_EVALUATION", "RETIRED"),
        ("REJECTED", "RETIRED"),
    }
)

_REVISION = re.compile(r"^[0-9a-f]{40}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_SLUG = re.compile(r"^[A-Za-z0-9_.-]+$")
_WINDOWS_RESERVED = {
    "aux",
    "clock$",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "con",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
    "nul",
    "prn",
}
_LICENCE_MARKERS = {
    "Apache-2.0": ("apache license", "version 2.0"),
    "MIT": ("permission is hereby granted, free of charge",),
    "BSD-3-Clause": (
        "redistribution and use in source and binary forms",
        "neither the name",
    ),
}
_COPYLEFT_LICENCE_MARKERS = (
    "affero general public license",
    "eclipse public license",
    "gnu general public license",
    "lesser general public license",
    "mozilla public license",
)


@dataclass(frozen=True)
class TreeEntry:
    """One entry reported by ``git ls-tree`` before materialisation."""

    mode: str
    object_type: str
    object_id: str
    path: str
    size_bytes: int | None


@dataclass(frozen=True)
class AcquisitionLimits:
    """Bounds applied before any repository blob is materialised."""

    maximum_files: int = 50_000
    maximum_total_bytes: int = 512 * 1024 * 1024
    maximum_file_bytes: int = 32 * 1024 * 1024
    maximum_path_bytes: int = 512


@dataclass(frozen=True)
class QualificationBudget:
    """In-memory guard for the single governed qualification run."""

    budget_id: str
    maximum_runs: int = 1
    consumed_runs: int = 0

    def consume(self) -> QualificationBudget:
        if self.maximum_runs != 1 or self.consumed_runs >= self.maximum_runs:
            raise PolicyError("QUALIFICATION_BUDGET_EXHAUSTED")
        return replace(self, consumed_runs=self.consumed_runs + 1)


def canonical_upstream_url(value: str) -> str:
    """Return the one accepted public GitHub URL form.

    Credentials, mutable query parameters, fragments, ports, encoded path
    syntax, and non-HTTPS transports are rejected.
    """

    if not isinstance(value, str) or value != value.strip() or "\\" in value:
        raise PolicyError("UPSTREAM_URL_REJECTED")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != unquote(parsed.path)
    ):
        raise PolicyError("UPSTREAM_URL_REJECTED")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise PolicyError("UPSTREAM_URL_REJECTED")
    owner, repository = parts
    repository = repository.removesuffix(".git")
    if (
        not owner
        or not repository
        or _REPOSITORY_SLUG.fullmatch(owner) is None
        or _REPOSITORY_SLUG.fullmatch(repository) is None
    ):
        raise PolicyError("UPSTREAM_URL_REJECTED")
    return f"https://github.com/{owner}/{repository}.git"


def validate_revision(value: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise PolicyError("IMMUTABLE_REVISION_REQUIRED")
    return value


def validate_intake_proposal(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "intake-proposal-v1":
        raise ContractError("expected intake-proposal-v1")
    payload = record["payload"]
    if payload["acquisition_state"] != "PROPOSED":
        raise PolicyError("INTAKE_PROPOSAL_MUST_START_PROPOSED")
    if (
        canonical_upstream_url(payload["canonical_upstream_url"])
        != payload["canonical_upstream_url"]
    ):
        raise PolicyError("UPSTREAM_URL_NOT_CANONICAL")
    revisions = payload["requested_revisions"]
    if (
        not isinstance(revisions, list)
        or not revisions
        or len(revisions) > 12
        or len(set(revisions)) != len(revisions)
    ):
        raise PolicyError("REQUESTED_REVISIONS_REJECTED")
    for revision in revisions:
        validate_revision(revision)
    if payload["hosting_provider"] != "GITHUB_PUBLIC":
        raise PolicyError("HOSTING_PROVIDER_REJECTED")
    if payload["proposed_use"] != "PRIVATE_EVALUATION_ONLY":
        raise PolicyError("PROPOSED_USE_REJECTED")
    if not payload["licence_evidence_location"] or not payload["security_evidence_references"]:
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED")
    return record


def validate_acquisition_decision(
    record: dict[str, Any], *, proposal: dict[str, Any]
) -> dict[str, Any]:
    validate_record(record)
    validate_intake_proposal(proposal)
    if record["schema_version"] != "acquisition-decision-v1":
        raise ContractError("expected acquisition-decision-v1")
    payload = record["payload"]
    if payload["proposal_id"] != proposal["record_id"]:
        raise PolicyError("ACQUISITION_DECISION_PROPOSAL_MISMATCH")
    transition = (payload["from_state"], payload["to_state"])
    if transition not in STATE_TRANSITIONS:
        raise PolicyError("INVALID_INTAKE_STATE_TRANSITION")
    if payload["decision"] == "APPROVE":
        if (
            transition != ("RIGHTS_PRECHECK_PASSED", "ACQUISITION_APPROVED")
            or payload["rights_precheck"] != "PASSED"
            or payload["decided_before_fetch"] is not True
        ):
            raise PolicyError("ACQUISITION_APPROVAL_INCOMPLETE")
    elif payload["decision"] == "REJECT":
        if payload["to_state"] != "REJECTED":
            raise PolicyError("ACQUISITION_REJECTION_STATE_INVALID")
    else:
        raise PolicyError("ACQUISITION_DECISION_INVALID")
    return record


def assert_acquisition_authorised(proposal: dict[str, Any], decision: dict[str, Any]) -> None:
    validate_acquisition_decision(decision, proposal=proposal)
    if decision["payload"]["to_state"] != "ACQUISITION_APPROVED":
        raise PolicyError("UNAPPROVED_REPOSITORY_FETCH_BLOCKED")


def acquisition_plan(
    proposal: dict[str, Any],
    decision: dict[str, Any],
    *,
    bare_repository: str,
    empty_hooks_directory: str,
    isolated_config_root: str,
) -> dict[str, Any]:
    """Create a fixed inert transport plan after approval.

    The returned commands are data for a controlled operator.  This function
    never starts a process and never reads repository configuration.
    """

    assert_acquisition_authorised(proposal, decision)
    payload = proposal["payload"]
    revisions = payload["requested_revisions"]
    url = payload["canonical_upstream_url"]
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_CONFIG_GLOBAL": f"{isolated_config_root}/empty.gitconfig",
        "XDG_CONFIG_HOME": f"{isolated_config_root}/xdg",
    }
    global_configuration = [
        "-c",
        f"core.hooksPath={empty_hooks_directory}",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.required=false",
    ]
    return {
        "environment": environment,
        "commands": [
            ["git", *global_configuration, "init", "--bare", bare_repository],
            [
                "git",
                *global_configuration,
                f"--git-dir={bare_repository}",
                "fetch",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=2",
                url,
                *revisions,
            ],
        ],
        "repository_code_execution": False,
        "checkout": False,
        "submodules": False,
        "lfs_smudge": False,
        "hooks": False,
        "remote_includes": False,
    }


def reject_remote_git_configuration(entries: Mapping[str, str]) -> None:
    """Reject configuration capable of loading or executing remote material."""

    prohibited = (
        "include.",
        "includeif.",
        "credential.",
        "url.",
        "http.",
        "remote.",
        "submodule.",
        "filter.",
        "core.fsmonitor",
        "core.sshcommand",
    )
    for key in entries:
        lowered = key.casefold()
        if lowered == "include.path" or any(lowered.startswith(item) for item in prohibited):
            raise PolicyError("REMOTE_GIT_CONFIGURATION_REJECTED")


def _portable_path(value: str, *, maximum_path_bytes: int) -> str:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum_path_bytes
        or any(ord(character) < 32 for character in value)
    ):
        raise PolicyError("UNSAFE_REPOSITORY_PATH")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PolicyError("UNSAFE_REPOSITORY_PATH")
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if part.endswith((" ", ".")) or ":" in part or stem in _WINDOWS_RESERVED:
            raise PolicyError("UNSAFE_REPOSITORY_PATH")
    return path.as_posix()


def scan_tree_entries(
    entries: Iterable[TreeEntry],
    *,
    limits: AcquisitionLimits | None = None,
) -> dict[str, Any]:
    """Validate a Git tree before materialisation.

    Symlinks and Gitlinks are retained only as inert identifiers and are never
    resolved or materialised.  Other special files fail closed.
    """

    limits = limits or AcquisitionLimits()
    regular: list[TreeEntry] = []
    inert_gitlinks: list[dict[str, str]] = []
    inert_symlinks: list[dict[str, str]] = []
    identities: set[str] = set()
    total_bytes = 0
    for entry in entries:
        path = _portable_path(entry.path, maximum_path_bytes=limits.maximum_path_bytes)
        portable_identity = path.casefold()
        if portable_identity in identities:
            raise PolicyError("PORTABLE_PATH_COLLISION")
        identities.add(portable_identity)
        if _OBJECT_ID.fullmatch(entry.object_id) is None:
            raise PolicyError("GIT_OBJECT_ID_REJECTED")
        if entry.mode == "160000" and entry.object_type == "commit":
            inert_gitlinks.append({"path": path, "object_id": entry.object_id})
            continue
        if entry.mode == "120000" and entry.object_type == "blob":
            inert_symlinks.append({"path": path, "object_id": entry.object_id})
            continue
        if entry.mode not in {"100644", "100755"} or entry.object_type != "blob":
            raise PolicyError("SPECIAL_FILE_REJECTED")
        if (
            entry.size_bytes is None
            or isinstance(entry.size_bytes, bool)
            or entry.size_bytes < 0
            or entry.size_bytes > limits.maximum_file_bytes
        ):
            raise PolicyError("REPOSITORY_FILE_SIZE_LIMIT")
        regular.append(entry)
        total_bytes += entry.size_bytes
        if len(regular) > limits.maximum_files or total_bytes > limits.maximum_total_bytes:
            raise PolicyError("REPOSITORY_SIZE_OR_COUNT_LIMIT")
    return {
        "regular_entries": regular,
        "inert_gitlinks": inert_gitlinks,
        "inert_symlinks": inert_symlinks,
        "regular_file_count": len(regular),
        "inert_gitlink_count": len(inert_gitlinks),
        "inert_symlink_count": len(inert_symlinks),
        "total_bytes": total_bytes,
    }


def detect_code_licence(text: str) -> str:
    lowered = text.casefold()
    if any(marker in lowered for marker in _COPYLEFT_LICENCE_MARKERS):
        raise PolicyError("COPYLEFT_OR_MIXED_CODE_LICENCE")
    matches = [
        identifier
        for identifier, markers in _LICENCE_MARKERS.items()
        if all(marker in lowered for marker in markers)
    ]
    if not matches:
        raise PolicyError("MISSING_OR_AMBIGUOUS_CODE_LICENCE")
    if len(matches) == 1:
        return matches[0]
    # Some projects append complete MIT/BSD notices for bundled components
    # after their primary Apache/MIT/BSD-3 grant.  All recognised grants are
    # permissive; bind the earliest complete grant while continuing to reject
    # any file containing a copyleft grant.
    positions = {
        identifier: min(lowered.find(marker) for marker in _LICENCE_MARKERS[identifier])
        for identifier in matches
    }
    earliest = min(positions.values())
    primary = [identifier for identifier, position in positions.items() if position == earliest]
    if len(primary) != 1:
        raise PolicyError("MISSING_OR_AMBIGUOUS_CODE_LICENCE")
    return primary[0]


def verify_licence_evidence(
    *,
    text: str,
    exact_revision: str,
    expected_revision: str,
    expected_identifier: str,
    expected_file_hash: str,
) -> None:
    validate_revision(exact_revision)
    validate_revision(expected_revision)
    if exact_revision != expected_revision:
        raise PolicyError("LICENCE_REVISION_MISMATCH")
    if expected_identifier not in APPROVED_CODE_LICENCES:
        raise PolicyError("CODE_LICENCE_NOT_APPROVED")
    if detect_code_licence(text) != expected_identifier:
        raise PolicyError("LICENCE_IDENTIFIER_MISMATCH")
    if not isinstance(expected_file_hash, str) or _SHA256.fullmatch(expected_file_hash) is None:
        raise PolicyError("LICENCE_HASH_INVALID")
    if sha256_bytes(text.encode("utf-8")) != expected_file_hash:
        raise PolicyError("LICENCE_HASH_MISMATCH")


def validate_rights_dimensions(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "rights-dimensions-v1":
        raise ContractError("expected rights-dimensions-v1")
    payload = record["payload"]
    validate_revision(payload["exact_revision"])
    if (
        payload["licence_identifier"] not in APPROVED_CODE_LICENCES
        or _SHA256.fullmatch(payload["licence_file_hash"]) is None
        or payload["source_access"] != "PUBLIC_READ"
        or payload["private_evaluation"] != "PERMITTED"
        or payload["finding_use"] not in {"PERMITTED", "PERMITTED_WITH_ATTRIBUTION"}
        or payload["label_use"] not in {"PERMITTED", "PRIVATE_EVALUATION_ONLY"}
        or payload["source_redistribution"]
        not in {
            "LICENCE_PERMITS_SOURCE_REDISTRIBUTION",
            "PRIVATE_ONLY_BY_PROJECT_POLICY",
        }
        or payload["review_status"] != "APPROVED_FOR_PRIVATE_EVALUATION"
    ):
        raise PolicyError("RIGHTS_OR_PROVENANCE_REJECTED")
    if (
        payload["future_training_use_reviewed"] is not False
        or payload["future_training_use_permitted"] is not False
        or payload["weight_licence"] != "NONE"
    ):
        raise PolicyError("TRAINING_ELIGIBILITY_MUST_DEFAULT_FALSE")
    return record


def verify_acquisition_receipt(
    record: dict[str, Any],
    *,
    proposal: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    validate_record(record)
    assert_acquisition_authorised(proposal, decision)
    if record["schema_version"] != "acquisition-receipt-v1":
        raise ContractError("expected acquisition-receipt-v1")
    payload = record["payload"]
    controls = payload["safety_controls"]
    expected_controls = {
        "hooks_disabled": True,
        "submodule_recursion_disabled": True,
        "lfs_smudge_disabled": True,
        "remote_includes_disabled": True,
        "checkout_filters_disabled": True,
        "build_or_setup_execution": False,
    }
    if (
        payload["proposal_id"] != proposal["record_id"]
        or payload["decision_id"] != decision["record_id"]
        or payload["canonical_upstream_url"] != proposal["payload"]["canonical_upstream_url"]
        or payload["requested_revision"] not in proposal["payload"]["requested_revisions"]
        or payload["resolved_revision"] != payload["requested_revision"]
        or payload["state"] != "ACQUIRED_UNADMITTED"
        or payload["repository_code_executed"] is not False
        or controls != expected_controls
        or _OBJECT_ID.fullmatch(payload["commit_object_hash"]) is None
        or _OBJECT_ID.fullmatch(payload["tree_object_hash"]) is None
        or _SHA256.fullmatch(payload["snapshot_tree_id"]) is None
        or _SHA256.fullmatch(payload["licence_file_hash"]) is None
    ):
        raise PolicyError("ACQUISITION_RECEIPT_REJECTED")
    return record


def audit_revision_pairs(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    pair_ids: set[str] = set()
    lineages: set[str] = set()
    count = 0
    for record in records:
        validate_record(record)
        if record["schema_version"] != "revision-pair-v1":
            raise ContractError("expected revision-pair-v1")
        payload = record["payload"]
        for revision in (payload["vulnerable_revision"], payload["fixed_revision"]):
            validate_revision(revision)
        if payload["vulnerable_revision"] == payload["fixed_revision"]:
            raise PolicyError("REVISION_PAIR_IDENTITY_COLLISION")
        if payload["pair_id"] in pair_ids:
            raise PolicyError("DUPLICATE_REVISION_PAIR")
        if payload["vulnerability_lineage_id"] in lineages:
            raise PolicyError("DUPLICATE_VULNERABILITY_LINEAGE")
        pair_ids.add(payload["pair_id"])
        lineages.add(payload["vulnerability_lineage_id"])
        count += 1
    return {"pair_count": count, "vulnerability_lineage_count": len(lineages)}


def validate_finding_cue_profile(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "finding-cue-profile-v1":
        raise ContractError("expected finding-cue-profile-v1")
    payload = record["payload"]
    if payload["fixing_diff_in_runner_input"] or payload["label_fields_in_runner_input"]:
        raise PolicyError("RUNNER_LABEL_OR_FIXING_DIFF_LEAKAGE")
    is_ablation = payload["ablation_of_group_id"] is not None
    if is_ablation == payload["counts_toward_natural_total"]:
        raise PolicyError("CUE_ABLATION_COUNTING_INVALID")
    return record


def validate_group_review(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "natural-group-review-v1":
        raise ContractError("expected natural-group-review-v1")
    payload = record["payload"]
    if payload["ranking_output_available"]:
        raise PolicyError("CONTROLLED_REVIEW_NOT_RANKING_BLIND")
    if payload["decision"] == "ACCEPT":
        if (
            payload["security_evidence_verified"] is not True
            or payload["licence_revision_verified"] is not True
            or payload["roles_verified"] is not True
            or payload["ambiguity_state"] != "RESOLVED"
        ):
            raise PolicyError("NATURAL_GROUP_REVIEW_INCOMPLETE")
    elif payload["decision"] not in {"REJECT", "NEEDS_CORRECTION"}:
        raise PolicyError("NATURAL_GROUP_REVIEW_DECISION_INVALID")
    return record


def verify_pre_run_seal(record: dict[str, Any], *, expected_runtime_hash: str) -> None:
    validate_record(record)
    if record["schema_version"] != "pre-run-seal-v1":
        raise ContractError("expected pre-run-seal-v1")
    payload = record["payload"]
    if (
        payload["runtime_artifact_hash"] != expected_runtime_hash
        or payload["runner_blindness_verified"] is not True
        or payload["sealed_before_execution"] is not True
        or not payload["sealed_artifact_hashes"]
    ):
        raise PolicyError("PRE_RUN_SEAL_REJECTED")


def validate_threshold_decision(record: dict[str, Any]) -> None:
    validate_record(record)
    if record["schema_version"] != "natural-threshold-decision-v1":
        raise ContractError("expected natural-threshold-decision-v1")
    payload = record["payload"]
    if (
        payload["qualification_evidence_used"] is not False
        or payload["decided_before_qualification"] is not True
    ):
        raise PolicyError("THRESHOLD_DECISION_LEAKAGE")
    if payload["qualification_authorised"] and payload["decision"] != "APPROVE":
        raise PolicyError("QUALIFICATION_WITHOUT_THRESHOLD_APPROVAL")


def enforce_publication_decision(record: dict[str, Any]) -> None:
    validate_record(record)
    if record["schema_version"] != "v0.3.1-closure-v1":
        raise ContractError("expected v0.3.1-closure-v1")
    payload = record["payload"]
    if (
        payload["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or payload["holdback_opened"] is not False
        or payload["training_started"] is not False
        or payload["weights_acquired"] is not False
        or payload["training_recommendation"] != "DO_NOT_BEGIN_TRACE_001"
    ):
        raise PolicyError("V0_3_1_STOP_GATE_VIOLATION")
