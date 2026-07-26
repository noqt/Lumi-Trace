# SPDX-License-Identifier: Apache-2.0
"""Fail-closed V0.4 training-data assurance controls.

The functions in this module operate on canonical private records. They never
fetch repositories, execute repository-controlled code, open qualification or
holdback partitions, or infer a right from a directory name.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .canonical import stable_id
from .contracts import make_record, validate_record
from .errors import ContractError, PolicyError

DATA_STATES = (
    "PROPOSED",
    "QUARANTINED_ACQUIRED",
    "RIGHTS_REVIEWED",
    "PROVENANCE_VERIFIED",
    "SECURITY_SCANNED",
    "LABELLED_UNREVIEWED",
    "CONTROLLED_REVIEWED",
    "INDEPENDENCE_VERIFIED",
    "TRAINING_ELIGIBLE",
    "EVALUATION_ONLY",
    "REJECTED",
    "RETIRED",
    "SUPERSEDED",
)

PARTITIONS = (
    "TRAINING",
    "ENGINEERING_DEVELOPMENT",
    "MODEL_SELECTION",
    "QUALIFICATION",
    "PROTECTED_HOLDBACK",
)

LOCATION_ROLES = frozenset(
    {
        "VULNERABLE_IMPLEMENTATION",
        "CONTRIBUTING_IMPLEMENTATION",
        "OBSERVATION",
        "HARNESS",
        "WITNESS",
        "FIX_SITE_ONLY",
        "EXCLUDED_AMBIGUOUS",
    }
)

MATERIALS = (
    "repository_code",
    "advisory_prose",
    "vulnerability_metadata",
    "fixing_diff",
    "labels",
    "derived_features",
    "trained_weights",
)

RIGHTS_DIMENSIONS = (
    "retention",
    "evaluation",
    "transformation",
    "training",
    "redistribution",
)

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SECRET_PATTERNS = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "GENERIC_CREDENTIAL",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]"
            r"[A-Za-z0-9+/_.=-]{12,}['\"]"
        ),
    ),
)
_PERSONAL_DATA_PATTERNS = (
    ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "IPV4_ADDRESS",
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
        ),
    ),
)
_PROMPT_PATTERNS = (
    re.compile(r"(?i)\bignore (?:all |any )?(?:previous|prior) instructions\b"),
    re.compile(r"(?i)\b(?:system|developer) prompt\b"),
    re.compile(r"(?i)\b(?:chatgpt|language model|reviewer),?\s+(?:must|should|do)\b"),
)
_UNSAFE_SERIALIZED_SUFFIXES = frozenset(
    {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".onnx"}
)
_ARCHIVE_SUFFIXES = frozenset({".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"})

_TRANSITIONS = frozenset(
    {
        ("PROPOSED", "QUARANTINED_ACQUIRED"),
        ("QUARANTINED_ACQUIRED", "RIGHTS_REVIEWED"),
        ("RIGHTS_REVIEWED", "PROVENANCE_VERIFIED"),
        ("PROVENANCE_VERIFIED", "SECURITY_SCANNED"),
        ("SECURITY_SCANNED", "LABELLED_UNREVIEWED"),
        ("LABELLED_UNREVIEWED", "CONTROLLED_REVIEWED"),
        ("CONTROLLED_REVIEWED", "INDEPENDENCE_VERIFIED"),
        ("INDEPENDENCE_VERIFIED", "TRAINING_ELIGIBLE"),
        ("INDEPENDENCE_VERIFIED", "EVALUATION_ONLY"),
        ("TRAINING_ELIGIBLE", "RETIRED"),
        ("EVALUATION_ONLY", "RETIRED"),
        ("REJECTED", "RETIRED"),
        ("TRAINING_ELIGIBLE", "SUPERSEDED"),
        ("EVALUATION_ONLY", "SUPERSEDED"),
    }
)


@dataclass(frozen=True)
class QuarantineLimits:
    """Bounds enforced before untrusted material can leave quarantine."""

    maximum_files: int = 50_000
    maximum_total_bytes: int = 512 * 1024 * 1024
    maximum_file_bytes: int = 32 * 1024 * 1024
    maximum_path_bytes: int = 512
    maximum_depth: int = 32
    maximum_compression_ratio: float = 100.0


def validate_source_candidate(record: dict[str, Any]) -> dict[str, Any]:
    """Validate the collection-level record before acquisition."""

    validate_record(record)
    if record["schema_version"] != "source-candidate-v1":
        raise ContractError("expected source-candidate-v1")
    payload = record["payload"]
    rights = payload["rights"]
    required_rights = {
        "retention",
        "evaluation",
        "transformation",
        "training",
        "redistribution",
    }
    if (
        not isinstance(payload["canonical_source_url"], str)
        or not payload["canonical_source_url"].startswith("https://")
        or not isinstance(payload["immutable_revision"], str)
        or _REVISION.fullmatch(payload["immutable_revision"]) is None
        or payload["acquisition_method"] != "INERT_PINNED_FETCH"
        or not isinstance(rights, dict)
        or set(rights) != required_rights
        or any(value not in {"PERMITTED", "PROHIBITED", "UNKNOWN"} for value in rights.values())
        or payload["decision"] not in {"APPROVE_FOR_QUARANTINE", "REJECT", "PENDING"}
        or not payload["licence_evidence"]
        or not payload["security_evidence"]
        or not payload["reviewer_role"]
    ):
        raise PolicyError("SOURCE_CANDIDATE_INCOMPLETE")
    if payload["decision"] == "APPROVE_FOR_QUARANTINE" and any(
        rights[name] == "UNKNOWN" for name in ("retention", "evaluation")
    ):
        raise PolicyError("SOURCE_RIGHTS_UNKNOWN")
    return record


def validate_state_transition(
    record: dict[str, Any], *, previous: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Enforce the append-only audit-state machine."""

    _validate_transition_shape(record)
    payload = record["payload"]
    if previous is None:
        if payload["sequence"] != 1 or payload["previous_transition_id"] is not None:
            raise PolicyError("DATA_STATE_CHAIN_INVALID")
    else:
        _validate_transition_shape(previous)
        prior = previous["payload"]
        if (
            payload["item_id"] != prior["item_id"]
            or payload["from_state"] != prior["to_state"]
            or payload["sequence"] != prior["sequence"] + 1
            or payload["previous_transition_id"] != previous["record_id"]
        ):
            raise PolicyError("DATA_STATE_CHAIN_INVALID")
    return record


def _validate_transition_shape(record: dict[str, Any]) -> None:
    validate_record(record)
    if record["schema_version"] != "data-state-transition-v1":
        raise ContractError("expected data-state-transition-v1")
    payload = record["payload"]
    source = payload["from_state"]
    target = payload["to_state"]
    if source not in DATA_STATES or target not in DATA_STATES:
        raise PolicyError("UNKNOWN_DATA_STATE")
    if target == "REJECTED":
        allowed = source not in {"REJECTED", "RETIRED", "SUPERSEDED"}
    else:
        allowed = (source, target) in _TRANSITIONS
    if not allowed:
        raise PolicyError("ILLEGAL_DATA_STATE_TRANSITION")
    if (
        isinstance(payload["sequence"], bool)
        or not isinstance(payload["sequence"], int)
        or payload["sequence"] < 1
        or not payload["decision_receipt_id"]
        or not payload["actor_role"]
        or not payload["reason"]
        or _TIMESTAMP.fullmatch(payload["occurred_at"]) is None
    ):
        raise PolicyError("DATA_STATE_RECEIPT_INCOMPLETE")


def verify_transition_chain(records: Sequence[dict[str, Any]]) -> str:
    if not records:
        raise PolicyError("DATA_STATE_CHAIN_EMPTY")
    previous: dict[str, Any] | None = None
    for record in records:
        validate_state_transition(record, previous=previous)
        previous = record
    assert previous is not None
    return previous["payload"]["to_state"]


def validate_rights_matrix(record: dict[str, Any]) -> dict[str, Any]:
    """Require explicit, evidenced rights for every distinct material class."""

    validate_record(record)
    if record["schema_version"] != "rights-matrix-v1":
        raise ContractError("expected rights-matrix-v1")
    payload = record["payload"]
    materials = payload["materials"]
    if (
        _REVISION.fullmatch(payload["exact_revision"]) is None
        or set(materials) != set(MATERIALS)
        or payload["review_status"] not in {"APPROVED", "REJECTED", "QUARANTINED"}
        or not payload["reviewer_role"]
        or _TIMESTAMP.fullmatch(payload["reviewed_at"]) is None
    ):
        raise PolicyError("RIGHTS_MATRIX_INCOMPLETE")
    for name, dimensions in materials.items():
        if (
            not isinstance(dimensions, dict)
            or set(dimensions)
            != {*RIGHTS_DIMENSIONS, "evidence_ids", "basis", "included_in_model_input"}
            or any(
                dimensions[dimension]
                not in {"PERMITTED", "PROHIBITED", "UNKNOWN", "NOT_APPLICABLE"}
                for dimension in RIGHTS_DIMENSIONS
            )
            or not isinstance(dimensions["evidence_ids"], list)
            or not dimensions["evidence_ids"]
            or not dimensions["basis"]
            or not isinstance(dimensions["included_in_model_input"], bool)
        ):
            raise PolicyError(f"RIGHTS_DIMENSION_INCOMPLETE:{name}")
    return record


def assert_training_rights(record: dict[str, Any]) -> None:
    validate_rights_matrix(record)
    payload = record["payload"]
    if payload["review_status"] != "APPROVED":
        raise PolicyError("TRAINING_RIGHTS_NOT_APPROVED")
    materials = payload["materials"]
    for name in ("repository_code", "labels", "derived_features"):
        if materials[name]["training"] != "PERMITTED":
            raise PolicyError(f"TRAINING_RIGHT_NOT_VERIFIED:{name}")
    for name, dimensions in materials.items():
        if dimensions["included_in_model_input"] and dimensions["training"] != "PERMITTED":
            raise PolicyError(f"MODEL_INPUT_TRAINING_RIGHT_NOT_VERIFIED:{name}")


def _safe_path(path_text: str, limits: QuarantineLimits) -> str:
    if (
        not isinstance(path_text, str)
        or not path_text
        or "\x00" in path_text
        or "\\" in path_text
        or len(path_text.encode("utf-8")) > limits.maximum_path_bytes
    ):
        raise PolicyError("QUARANTINE_PATH_REJECTED")
    path = PurePosixPath(path_text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PolicyError("QUARANTINE_PATH_REJECTED")
    if len(path.parts) > limits.maximum_depth:
        raise PolicyError("QUARANTINE_DEPTH_LIMIT")
    return path.as_posix()


def scan_text(text: str) -> list[dict[str, str]]:
    """Return deterministic findings without interpreting untrusted instructions."""

    findings: list[dict[str, str]] = []
    if "\x00" in text:
        findings.append({"category": "NULL_BYTE", "severity": "CRITICAL"})
    for category, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append({"category": category, "severity": "CRITICAL"})
    for category, pattern in _PERSONAL_DATA_PATTERNS:
        if pattern.search(text):
            findings.append({"category": category, "severity": "REVIEW"})
    if any(pattern.search(text) for pattern in _PROMPT_PATTERNS):
        findings.append({"category": "PROMPT_INJECTION_TEXT", "severity": "REVIEW"})
    if any(
        unicodedata.category(character) == "Cf" and character not in {"\t", "\n", "\r"}
        for character in text
    ):
        findings.append({"category": "HIDDEN_UNICODE", "severity": "REVIEW"})
    return sorted(findings, key=lambda item: (item["category"], item["severity"]))


def audit_answer_leakage(
    model_input: Mapping[str, Any],
    *,
    group_id: str,
    target_paths: Sequence[str],
    target_symbols: Sequence[str],
    target_lines: Sequence[int],
) -> dict[str, Any]:
    """Separate marked natural cues from prohibited answer-bearing fields."""

    rendered = json.dumps(
        model_input,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).casefold()
    natural_cues: list[dict[str, str]] = []
    for path in sorted(set(target_paths)):
        if path and path.casefold() in rendered:
            natural_cues.append(
                {
                    "category": "EXACT_TARGET_PATH",
                    "value_identity": stable_id("cue", path),
                }
            )
    for symbol in sorted(set(target_symbols)):
        if symbol and symbol.casefold() in rendered:
            natural_cues.append(
                {"category": "EXACT_TARGET_SYMBOL", "value_identity": stable_id("cue", symbol)}
            )
    for line in sorted(set(target_lines)):
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise PolicyError("TARGET_LINE_INVALID")
        if re.search(rf"(?<!\d){line}(?!\d)", rendered):
            natural_cues.append(
                {"category": "TARGET_LINE_NUMBER", "value_identity": stable_id("cue", line)}
            )
    prohibited_keys = {
        "accepted_targets": "LABEL_TARGETS",
        "fixing_diff": "FIXING_DIFF",
        "reviewer_notes": "REVIEWER_NOTES",
        "partition": "PARTITION_FIELD",
        "outcome": "OUTCOME_FIELD",
        "label": "LABEL_FIELD",
        "safe_revision": "SAFE_REVISION_INDICATOR",
        "vulnerable_revision": "VULNERABLE_REVISION_INDICATOR",
    }
    prohibited = [
        {"category": category, "field_identity": stable_id("field", key)}
        for key, category in sorted(prohibited_keys.items())
        if key in model_input
    ]
    required_views = [
        "NATURAL_CUE_MARKED",
        "NO_PATH",
        "NO_SYMBOL",
        "REDUCED_DESCRIPTION",
        "IDENTIFIER_ABLATION",
    ]
    return make_record(
        "answer-leakage-audit-v1",
        {
            "group_id": group_id,
            "input_identity": stable_id("model-input", model_input),
            "natural_cues": natural_cues,
            "prohibited_leakage": prohibited,
            "required_views": required_views,
            "decision": "QUARANTINE" if prohibited else "PASSED_WITH_ABLATIONS",
        },
    )


def wilson_interval(successes: int, total: int) -> dict[str, float | int | None]:
    """Return the predeclared two-sided 95% Wilson score interval."""

    if (
        isinstance(successes, bool)
        or isinstance(total, bool)
        or not isinstance(successes, int)
        or not isinstance(total, int)
        or total < 0
        or successes < 0
        or successes > total
    ):
        raise PolicyError("BINOMIAL_DENOMINATOR_INVALID")
    if total == 0:
        return {"successes": successes, "total": total, "rate": None, "lower": None, "upper": None}
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    centre = (rate + z * z / (2 * total)) / denominator
    half_width = (
        z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    )
    return {
        "successes": successes,
        "total": total,
        "rate": rate,
        "lower": max(0.0, centre - half_width),
        "upper": min(1.0, centre + half_width),
    }


def v04_metric_specification() -> dict[str, Any]:
    """Return the locked finding-guided ranking gates from the V0.4 brief."""

    return make_record(
        "v0.4-metric-specification-v1",
        {
            "cutoffs": [5, 10, 20],
            "gates": {
                "valid_attempt_completion_minimum": 1.00,
                "target_indexability_minimum": 0.95,
                "file_recall_at_5_minimum": 0.65,
                "file_recall_at_10_minimum": 0.75,
                "file_recall_at_20_minimum": 0.85,
                "location_role_correct_recall_at_20_minimum": 0.70,
                "mean_reciprocal_rank_minimum": 0.35,
                "no_relevant_candidate_maximum": 0.15,
                "hard_negative_outrank_maximum": 0.20,
                "wrong_location_role_top_one_maximum": 0.15,
                "repository_family_macro_recall_at_20_minimum": 0.80,
                "minimum_family_recall_at_20_minimum": 0.60,
                "zero_recall_family_count_maximum": 0,
                "false_supported_disposition_maximum": 0,
                "false_vulnerability_safe_control_maximum": 0,
                "unsafe_non_abstention_maximum": 0,
            },
            "aggregation": {
                "micro": True,
                "repository_family_macro": True,
                "minimum_and_maximum_family": True,
                "language_and_size_strata": True,
                "cue_ablation_strata": True,
                "post_design_temporal_stratum": True,
            },
            "confidence_intervals": {
                "method": "WILSON_95_PERCENT",
                "zero_observed_safety_upper_bound_required": True,
            },
            "positive_coverage_scope": {
                "claim": "CANDIDATE_RANKING_ONLY",
                "disposition_claim_excluded": True,
                "universal_abstention_cannot_qualify_disposition": True,
            },
            "qualification_policy": {
                "single_use": True,
                "blind": True,
                "thresholds_sealed_before_model_selection": True,
                "protected_holdback_opened": False,
            },
        },
    )


def scan_quarantine_entries(
    entries: Iterable[Mapping[str, Any]],
    *,
    subject_id: str,
    limits: QuarantineLimits | None = None,
) -> dict[str, Any]:
    """Scan inert entry metadata and optional decoded text under hard bounds."""

    limits = limits or QuarantineLimits()
    count = 0
    total_bytes = 0
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for entry in entries:
        path = _safe_path(entry.get("path"), limits)
        portable = unicodedata.normalize("NFC", path).casefold()
        if portable in seen_paths:
            raise PolicyError("QUARANTINE_PORTABLE_PATH_COLLISION")
        seen_paths.add(portable)
        kind = entry.get("kind")
        size = entry.get("size_bytes")
        compressed = entry.get("compressed_bytes")
        if kind not in {"REGULAR", "SYMLINK", "GITLINK", "DIRECTORY"}:
            raise PolicyError("QUARANTINE_SPECIAL_FILE_REJECTED")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PolicyError("QUARANTINE_SIZE_INVALID")
        if size > limits.maximum_file_bytes:
            raise PolicyError("QUARANTINE_FILE_SIZE_LIMIT")
        if compressed is not None:
            if isinstance(compressed, bool) or not isinstance(compressed, int) or compressed < 1:
                raise PolicyError("QUARANTINE_COMPRESSION_INVALID")
            if size / compressed > limits.maximum_compression_ratio:
                raise PolicyError("QUARANTINE_COMPRESSION_RATIO_LIMIT")
        count += 1
        total_bytes += size
        if count > limits.maximum_files or total_bytes > limits.maximum_total_bytes:
            raise PolicyError("QUARANTINE_TOTAL_LIMIT")
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix in _UNSAFE_SERIALIZED_SUFFIXES:
            findings.append(
                {"path": path, "category": "UNSAFE_SERIALIZATION", "severity": "CRITICAL"}
            )
        if suffix in _ARCHIVE_SUFFIXES and entry.get("archive_depth", 0) > 0:
            findings.append({"path": path, "category": "RECURSIVE_ARCHIVE", "severity": "CRITICAL"})
        if kind in {"SYMLINK", "GITLINK"}:
            findings.append(
                {"path": path, "category": f"INERT_{kind}", "severity": "INFORMATIONAL"}
            )
        text = entry.get("text")
        if text is not None:
            if not isinstance(text, str):
                raise PolicyError("QUARANTINE_TEXT_INVALID")
            findings.extend({"path": path, **finding} for finding in scan_text(text))
    critical = sum(finding["severity"] == "CRITICAL" for finding in findings)
    payload = {
        "subject_id": subject_id,
        "limits": {
            "maximum_files": limits.maximum_files,
            "maximum_total_bytes": limits.maximum_total_bytes,
            "maximum_file_bytes": limits.maximum_file_bytes,
            "maximum_path_bytes": limits.maximum_path_bytes,
            "maximum_depth": limits.maximum_depth,
            "maximum_compression_ratio": limits.maximum_compression_ratio,
        },
        "counts": {
            "entries": count,
            "bytes": total_bytes,
            "findings": len(findings),
            "critical_findings": critical,
        },
        "findings": sorted(
            findings,
            key=lambda item: (item["path"], item["category"], item["severity"]),
        ),
        "repository_code_executed": False,
        "network_policy": "ACQUISITION_ONLY_PINNED_HTTPS_THEN_DENIED",
        "decision": "QUARANTINE" if critical else "SCAN_PASSED",
    }
    return make_record("quarantine-scan-v1", payload)


def validate_label_review_pass(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "label-review-pass-v1":
        raise ContractError("expected label-review-pass-v1")
    payload = record["payload"]
    targets = payload["targets"]
    if (
        payload["pass_number"] not in {1, 2}
        or not payload["workspace_id"]
        or not payload["reviewer_role"]
        or not payload["input_hashes"]
        or payload["other_pass_visible"] is not False
        or payload["candidate_output_visible"] is not False
        or payload["model_output_visible"] is not False
        or payload["conclusion"] not in {"ACCEPT", "REJECT", "AMBIGUOUS"}
        or not isinstance(targets, list)
        or _TIMESTAMP.fullmatch(payload["created_at"]) is None
    ):
        raise PolicyError("BLIND_LABEL_PASS_INVALID")
    for target in targets:
        if (
            not isinstance(target, dict)
            or set(target) != {"file_identity", "symbol_identity", "region_identity", "role"}
            or target["role"] not in LOCATION_ROLES
        ):
            raise PolicyError("LABEL_TARGET_INVALID")
    return record


def validate_label_resolution(
    record: dict[str, Any], *, first: dict[str, Any], second: dict[str, Any]
) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "label-review-resolution-v1":
        raise ContractError("expected label-review-resolution-v1")
    validate_label_review_pass(first)
    validate_label_review_pass(second)
    payload = record["payload"]
    first_payload = first["payload"]
    second_payload = second["payload"]
    if (
        first_payload["pass_number"] != 1
        or second_payload["pass_number"] != 2
        or first_payload["group_id"] != second_payload["group_id"]
        or first_payload["workspace_id"] == second_payload["workspace_id"]
        or payload["group_id"] != first_payload["group_id"]
        or payload["pass_record_ids"] != [first["record_id"], second["record_id"]]
        or payload["candidate_output_visible"] is not False
        or payload["resolution"] not in {"ACCEPT", "REJECT", "EXCLUDE_AMBIGUOUS"}
        or not payload["adjudicator_role"]
        or _TIMESTAMP.fullmatch(payload["resolved_at"]) is None
    ):
        raise PolicyError("CONTROLLED_LABEL_REVIEW_INVALID")
    target_agreement = first_payload["targets"] == second_payload["targets"]
    conclusion_agreement = first_payload["conclusion"] == second_payload["conclusion"]
    expected = {
        "target_agreement": target_agreement,
        "conclusion_agreement": conclusion_agreement,
    }
    if payload["comparison"] != expected:
        raise PolicyError("LABEL_COMPARISON_MISMATCH")
    if (not all(expected.values())) != bool(payload["disagreements"]):
        raise PolicyError("LABEL_DISAGREEMENT_RECORD_INVALID")
    return record


def validate_group_audit_card(
    record: dict[str, Any], *, rights_matrix: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Validate an item-level card; training admission adds corpus-wide checks."""

    validate_record(record)
    if record["schema_version"] != "group-audit-card-v1":
        raise ContractError("expected group-audit-card-v1")
    payload = record["payload"]
    label = payload["label"]
    audits = payload["audits"]
    fingerprints = payload["fingerprints"]
    if (
        payload["partition"] not in PARTITIONS
        or payload["final_state"] not in {"TRAINING_ELIGIBLE", "EVALUATION_ONLY", "REJECTED"}
        or not payload["source_identities"]
        or not payload["revision_identities"]
        or not payload["security_evidence_ids"]
        or not payload["review_receipt_ids"]
        or not payload["admission_reasons"]
        or set(audits)
        != {
            "provenance",
            "target_resolution",
            "lineage",
            "duplicates",
            "answer_leakage",
            "poisoning",
            "secrets",
            "privacy",
            "controlled_review",
        }
        or any(value not in {"PASSED", "FAILED", "QUARANTINED"} for value in audits.values())
        or set(fingerprints)
        != {
            "source_exact",
            "source_near",
            "fixing_diff",
            "advisory",
            "target",
            "vulnerability_lineage",
        }
        or not all(isinstance(value, str) and value for value in fingerprints.values())
        or not isinstance(label, dict)
        or label.get("primary_role") != "VULNERABLE_IMPLEMENTATION"
        or not label.get("target_exists")
        or not label.get("symbols_and_regions_resolve")
        or label.get("constructed_without_runner_or_model_output") is not True
        or not isinstance(payload["hard_negatives"], list)
        or not isinstance(payload["controls"], list)
        or not isinstance(payload["correction_history"], list)
    ):
        raise PolicyError("GROUP_AUDIT_CARD_INCOMPLETE")
    if payload["final_state"] in {"TRAINING_ELIGIBLE", "EVALUATION_ONLY"} and any(
        value != "PASSED" for value in audits.values()
    ):
        raise PolicyError("GROUP_AUDIT_NOT_PASSED")
    if payload["final_state"] == "TRAINING_ELIGIBLE":
        if payload["partition"] != "TRAINING" or "TRAINING" not in payload["permitted_uses"]:
            raise PolicyError("TRAINING_CARD_PARTITION_OR_USE_INVALID")
        if rights_matrix is not None:
            if payload["rights_matrix_id"] != rights_matrix["record_id"]:
                raise PolicyError("TRAINING_CARD_RIGHTS_MISMATCH")
            assert_training_rights(rights_matrix)
    return record


def audit_partition_independence(cards: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Fail on any family, lineage, or duplicate fingerprint crossing partitions."""

    if not cards:
        raise PolicyError("PARTITION_AUDIT_EMPTY")
    family_partitions: dict[str, set[str]] = defaultdict(set)
    fingerprint_partitions: dict[tuple[str, str], set[str]] = defaultdict(set)
    group_ids: set[str] = set()
    for card in cards:
        validate_group_audit_card(card)
        payload = card["payload"]
        if payload["group_id"] in group_ids:
            raise PolicyError("DUPLICATE_GROUP_ID")
        group_ids.add(payload["group_id"])
        family_partitions[payload["family_id"]].add(payload["partition"])
        for fingerprint_type, value in payload["fingerprints"].items():
            fingerprint_partitions[(fingerprint_type, value)].add(payload["partition"])
    family_overlap = {
        family: sorted(partitions)
        for family, partitions in family_partitions.items()
        if len(partitions) > 1
    }
    duplicate_overlap = {
        f"{fingerprint_type}:{value}": sorted(partitions)
        for (fingerprint_type, value), partitions in fingerprint_partitions.items()
        if len(partitions) > 1
    }
    if family_overlap:
        raise PolicyError("CROSS_PARTITION_FAMILY_OVERLAP")
    if duplicate_overlap:
        raise PolicyError("CROSS_PARTITION_DUPLICATE_OVERLAP")
    return {
        "group_count": len(cards),
        "family_count": len(family_partitions),
        "partition_counts": dict(
            sorted(Counter(card["payload"]["partition"] for card in cards).items())
        ),
        "methods": [
            "repository_metadata",
            "exact_source_hash",
            "near_source_fingerprint",
            "fixing_diff_fingerprint",
            "advisory_fingerprint",
            "target_fingerprint",
            "vulnerability_lineage",
        ],
        "cross_partition_family_overlap": 0,
        "cross_partition_duplicate_overlap": 0,
    }


def seal_partitions(
    cards: Sequence[dict[str, Any]],
    *,
    independence_audit_id: str,
    duplicate_audit_id: str,
) -> dict[str, Any]:
    audit_partition_independence(cards)
    assignments = sorted(
        (
            {
                "group_id": card["payload"]["group_id"],
                "family_id": card["payload"]["family_id"],
                "partition": card["payload"]["partition"],
                "audit_card_id": card["record_id"],
            }
            for card in cards
        ),
        key=lambda item: (item["partition"], item["family_id"], item["group_id"]),
    )
    return make_record(
        "partition-seal-v1",
        {
            "assignments": assignments,
            "family_count": len({item["family_id"] for item in assignments}),
            "group_count": len(assignments),
            "independence_audit_id": independence_audit_id,
            "duplicate_audit_id": duplicate_audit_id,
            "sealed_before_training": True,
            "sealed_before_feature_design": True,
            "holdback_state": "SEALED_UNOPENED",
        },
    )


def build_sample_plan(
    *,
    confidence_level: float = 0.95,
    qualification_margin: float = 0.10,
    assumed_rate: float = 0.50,
) -> dict[str, Any]:
    """Build the pre-intake sample plan using a conservative Wald planning bound."""

    if confidence_level != 0.95 or not 0 < qualification_margin < 0.5 or not 0 < assumed_rate < 1:
        raise PolicyError("SAMPLE_PLAN_PARAMETERS_REJECTED")
    z = 1.959963984540054
    calculated = math.ceil(z * z * assumed_rate * (1.0 - assumed_rate) / (qualification_margin**2))
    qualification_targets = max(50, calculated)
    return make_record(
        "corpus-sample-plan-v1",
        {
            "confidence_level": confidence_level,
            "qualification_margin": qualification_margin,
            "assumed_rate": assumed_rate,
            "training": {
                "minimum_groups": 500,
                "minimum_families": 25,
                "useful_groups_only": True,
            },
            "engineering_development": {
                "minimum_primary_targets": 100,
                "minimum_families": 8,
            },
            "model_selection": {
                "minimum_primary_targets": 100,
                "minimum_families": 8,
            },
            "qualification": {
                "minimum_primary_targets": qualification_targets,
                "minimum_matched_safe_controls": qualification_targets,
                "minimum_families": 8,
                "single_use": True,
                "planned_worst_case_half_width": qualification_margin,
            },
            "protected_holdback": {
                "minimum_primary_targets": qualification_targets,
                "minimum_families": 8,
                "state": "SEALED_UNOPENED",
            },
            "primary_metrics": [
                "file_recall_at_5",
                "file_recall_at_10",
                "file_recall_at_20",
                "location_role_correct_recall_at_20",
                "mean_reciprocal_rank",
                "hard_negative_outrank",
                "family_macro_recall_at_20",
                "minimum_family_recall_at_20",
                "safety_floors",
            ],
            "locked_before_intake_close": True,
        },
    )


def build_training_manifest(
    cards: Sequence[dict[str, Any]],
    rights_by_id: Mapping[str, dict[str, Any]],
    *,
    partition_seal: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    validate_record(partition_seal)
    if (
        partition_seal["schema_version"] != "partition-seal-v1"
        or partition_seal["payload"]["holdback_state"] != "SEALED_UNOPENED"
        or _TIMESTAMP.fullmatch(created_at) is None
    ):
        raise PolicyError("PARTITION_SEAL_INVALID")
    admitted: list[dict[str, Any]] = []
    for card in cards:
        rights = rights_by_id.get(card["payload"]["rights_matrix_id"])
        if rights is None:
            raise PolicyError("TRAINING_CARD_RIGHTS_MISSING")
        validate_group_audit_card(card, rights_matrix=rights)
        if card["payload"]["final_state"] != "TRAINING_ELIGIBLE":
            raise PolicyError("NON_TRAINING_STATE_IN_PREPROCESSING")
        admitted.append(card)
    seal_ids = {item["audit_card_id"] for item in partition_seal["payload"]["assignments"]}
    card_ids = {card["record_id"] for card in admitted}
    if card_ids - seal_ids:
        raise PolicyError("TRAINING_CARD_NOT_IN_PARTITION_SEAL")
    return make_record(
        "training-eligibility-manifest-v1",
        {
            "audit_card_ids": sorted(card_ids),
            "group_count": len(admitted),
            "family_count": len({card["payload"]["family_id"] for card in admitted}),
            "partition_seal_id": partition_seal["record_id"],
            "preprocessing_policy": "AUDIT_CARD_IDENTITY_ALLOWLIST_ONLY",
            "rejected_states": [state for state in DATA_STATES if state != "TRAINING_ELIGIBLE"],
            "created_at": created_at,
        },
    )


def evaluate_training_readiness(
    manifest: dict[str, Any],
    *,
    gates: Mapping[str, bool],
    qualification_opened: bool = False,
    holdback_opened: bool = False,
) -> dict[str, Any]:
    """Issue conditional authority only when every section-17 gate is evidenced."""

    validate_record(manifest)
    if manifest["schema_version"] != "training-eligibility-manifest-v1":
        raise ContractError("expected training-eligibility-manifest-v1")
    required_gates = {
        "item_audits",
        "training_rights",
        "lineage_and_duplicate_audit",
        "controlled_labels",
        "poison_secret_privacy_provenance",
        "target_indexability",
        "candidate_presence",
        "ordering_gap",
        "baselines_locked",
        "objective_and_metrics_locked",
        "partitions_sealed_disjoint",
        "model_supply_chain",
        "training_code_and_resources",
        "qualification_holdback_blind",
    }
    if set(gates) != required_gates or not all(isinstance(value, bool) for value in gates.values()):
        raise PolicyError("TRAINING_READINESS_GATES_INCOMPLETE")
    payload = manifest["payload"]
    count_gates = payload["group_count"] >= 500 and payload["family_count"] >= 25
    passed = (
        count_gates and all(gates.values()) and not qualification_opened and not holdback_opened
    )
    return make_record(
        "v0.4-training-readiness-v1",
        {
            "recommendation": (
                "TRACE_001_EXECUTION_AUTHORISED" if passed else "DO_NOT_BEGIN_TRACE_001"
            ),
            "gates": {
                "minimum_500_groups": payload["group_count"] >= 500,
                "minimum_25_families": payload["family_count"] >= 25,
                **dict(sorted(gates.items())),
            },
            "group_count": payload["group_count"],
            "family_count": payload["family_count"],
            "training_started": False,
            "weights_downloaded": False,
            "qualification_opened": qualification_opened,
            "holdback_opened": holdback_opened,
        },
    )


def disclosure_safe_projection(cards: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Return aggregates only; do not expose identities, source, labels, or paths."""

    state_counts = Counter(card["payload"]["final_state"] for card in cards)
    partition_counts = Counter(card["payload"]["partition"] for card in cards)
    family_counts = Counter(card["payload"]["family_id"] for card in cards)
    return {
        "schema_version": "lumi-trace-v0.4-public-corpus-aggregate-v1",
        "group_count": len(cards),
        "family_count": len(family_counts),
        "state_counts": dict(sorted(state_counts.items())),
        "partition_counts": dict(sorted(partition_counts.items())),
        "largest_family_group_count": max(family_counts.values(), default=0),
        "contains_case_identities": False,
        "contains_source_or_labels": False,
        "contains_private_paths": False,
    }


def verify_record_identity(record: dict[str, Any]) -> str:
    """Small public helper used by preprocessing and regression tests."""

    validate_record(record)
    expected = stable_id(
        record["schema_version"].removesuffix("-v1"),
        {key: value for key, value in record.items() if key not in {"record_id", "observations"}},
    )
    if record["record_id"] != expected:
        raise ContractError("record identity mismatch")
    return expected
