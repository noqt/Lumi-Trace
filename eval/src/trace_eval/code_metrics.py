# SPDX-License-Identifier: Apache-2.0
"""V0.3 Trace Code location-role, disposition, and safety metrics."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .contracts import make_record, validate_record
from .errors import ContractError

LOCATION_ROLES = {
    "OBSERVATION",
    "HARNESS",
    "WITNESS",
    "VULNERABLE_IMPLEMENTATION",
    "CONTRIBUTING_IMPLEMENTATION",
    "FIX_SITE_ONLY",
}
DISPOSITIONS = {
    "SUPPORTED",
    "SUSPICIOUS",
    "BENIGN_CONTROL",
    "INSUFFICIENT_EVIDENCE",
    "UNSUPPORTED_INPUT",
}
LABEL_STATES = {
    "ACCEPTED",
    "ACCEPTED_WITH_MULTIPLE_TARGETS",
    "AMBIGUOUS_EXCLUDED_FROM_PRIMARY_METRICS",
    "RIGHTS_REJECTED",
    "PROVENANCE_REJECTED",
    "INDEPENDENCE_REJECTED",
    "LABEL_EVIDENCE_INSUFFICIENT",
    "RETIRED_AFTER_CORRECTION",
}
PRIMARY_LABEL_STATES = {"ACCEPTED", "ACCEPTED_WITH_MULTIPLE_TARGETS"}
DEFAULT_DENOMINATORS = {
    "safety": "all primary-metric groups eligible for the named safety control",
    "retrieval": "all primary-metric groups with an accepted target at the named level",
    "indexability": "all primary-metric groups with an accepted target",
    "disposition": "all primary-metric groups",
}
DEFAULT_PRIMARY_METRICS = [
    "false_vulnerability_rate",
    "false_supported_disposition",
    "wrong_location_role_top_one",
    "hard_negative_outrank",
    "unsafe_non_abstention",
    "unsupported_input_acceptance",
]
DEFAULT_INTEGRITY_FLOORS = {
    "protected_holdback_exposure": 0,
    "unauthorised_corpus_access": 0,
    "manifest_verification_failure": 0,
    "cross_split_lineage_overlap": 0,
    "malformed_input_false_supported": 0,
    "negative_control_false_confirmed": 0,
    "same_host_identity_rate": 1,
}


def default_metric_specification() -> dict[str, Any]:
    """Return the locked V0.3 metric contract."""
    return make_record(
        "trace-code-metric-specification-v1",
        {
            "cutoffs": [1, 5, 10, 20],
            "matching": {
                "file": "EXACT_REPOSITORY_RELATIVE_PATH",
                "symbol": "EXACT_PATH_AND_NAME_OR_QUALIFIED_NAME",
                "region": "EXACT_PATH_AND_ANY_ONE_BASED_LINE_OVERLAP",
                "role": "MATCHED_LOCATION_HAS_DECLARED_PRIMARY_ROLE",
            },
            "denominators": DEFAULT_DENOMINATORS,
            "primary_metrics": DEFAULT_PRIMARY_METRICS,
            "aggregation": ["GROUP_MICRO", "REPOSITORY_MACRO", "REPOSITORY_FAMILY_MACRO"],
            "integrity_floors": DEFAULT_INTEGRITY_FLOORS,
        },
    )


def validate_metric_specification(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    if record["schema_version"] != "trace-code-metric-specification-v1":
        raise ContractError("Trace Code metric specification has the wrong schema")
    payload = record["payload"]
    if payload["cutoffs"] != [1, 5, 10, 20]:
        raise ContractError("Trace Code retrieval cutoffs are not locked to 1, 5, 10, and 20")
    if payload["denominators"] != DEFAULT_DENOMINATORS:
        raise ContractError("Trace Code metric denominators differ from the locked definition")
    if payload["primary_metrics"] != DEFAULT_PRIMARY_METRICS:
        raise ContractError("Trace Code primary safety metrics differ from the locked definition")
    if payload["integrity_floors"] != DEFAULT_INTEGRITY_FLOORS:
        raise ContractError("Trace Code integrity floors were weakened")
    return record


def _validate_region(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"start_line", "end_line"}
        or not all(
            isinstance(value[key], int) and not isinstance(value[key], bool) for key in value
        )
        or value["start_line"] < 1
        or value["end_line"] < value["start_line"]
    ):
        raise ContractError("location region is malformed")


def _validate_location(value: Any, *, hard_negative: bool = False) -> None:
    if not isinstance(value, dict):
        raise ContractError("location label must be an object")
    required = {"path", "role"}
    if hard_negative:
        required.add("family")
    if not required.issubset(value):
        raise ContractError("location label is missing required fields")
    path = value["path"]
    if (
        not isinstance(path, str)
        or not path
        or path.startswith(("/", "\\"))
        or ".." in path.replace("\\", "/").split("/")
    ):
        raise ContractError("location path must be repository-relative")
    if value["role"] not in LOCATION_ROLES:
        raise ContractError("location role is invalid")
    if "symbol" in value and (not isinstance(value["symbol"], str) or not value["symbol"]):
        raise ContractError("location symbol is malformed")
    if "region" in value:
        _validate_region(value["region"])
    if hard_negative and (not isinstance(value["family"], str) or not value["family"]):
        raise ContractError("hard-negative family is required")


def validate_location_label(record: dict[str, Any]) -> dict[str, Any]:
    """Validate a controlled-reviewed V0.3 location label."""
    validate_record(record)
    if record["schema_version"] != "trace-code-location-label-v1":
        raise ContractError("Trace Code label has the wrong schema")
    payload = record["payload"]
    if payload["label_state"] not in LABEL_STATES:
        raise ContractError("Trace Code label state is invalid")
    if payload["primary_role"] not in LOCATION_ROLES:
        raise ContractError("Trace Code primary location role is invalid")
    if not isinstance(payload["safe_control"], bool):
        raise ContractError("safe_control must be boolean")
    if payload["expected_disposition"] not in DISPOSITIONS:
        raise ContractError("expected disposition is invalid")
    targets = payload["targets"]
    negatives = payload["hard_negatives"]
    if not isinstance(targets, list) or not isinstance(negatives, list):
        raise ContractError("targets and hard negatives must be arrays")
    for target in targets:
        _validate_location(target)
    for negative in negatives:
        _validate_location(negative, hard_negative=True)
    if payload["label_state"] == "ACCEPTED" and not payload["safe_control"] and len(targets) != 1:
        raise ContractError("ACCEPTED vulnerable label must have exactly one target")
    if payload["label_state"] == "ACCEPTED_WITH_MULTIPLE_TARGETS" and len(targets) < 2:
        raise ContractError("multiple-target label must have at least two targets")
    if targets and not any(target["role"] == payload["primary_role"] for target in targets):
        raise ContractError("no accepted target has the declared primary role")
    if payload["constructed_without_runner_output"] is not True:
        raise ContractError("labels must be constructed without Trace candidate output")
    reviews = payload["review_receipt_ids"]
    if payload["label_state"] in PRIMARY_LABEL_STATES and (
        not isinstance(reviews, list) or not reviews or not all(isinstance(x, str) for x in reviews)
    ):
        raise ContractError("primary label has no controlled-review receipt")
    corrections = payload["corrections"]
    if not isinstance(corrections, list):
        raise ContractError("label corrections must be an array")
    expected_sequence = list(range(1, len(corrections) + 1))
    if [
        item.get("sequence") for item in corrections if isinstance(item, dict)
    ] != expected_sequence:
        raise ContractError("label correction history is not append-only and contiguous")
    return record


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def _region_match(candidate: dict[str, Any], target: dict[str, Any]) -> bool:
    if candidate.get("path") != target.get("path"):
        return False
    observed = candidate.get("region")
    expected = target.get("region")
    if not isinstance(observed, dict) or not isinstance(expected, dict):
        return False
    return int(observed["start_line"]) <= int(expected["end_line"]) and int(
        expected["start_line"]
    ) <= int(observed["end_line"])


def _matches(candidate: dict[str, Any], target: dict[str, Any], level: str) -> bool:
    if candidate.get("path") != target.get("path"):
        return False
    if level == "file":
        return True
    if level == "symbol":
        expected = target.get("symbol")
        observed = candidate.get("symbol")
        if isinstance(observed, dict):
            names = {observed.get("name"), observed.get("qualified_name")}
        else:
            names = {observed}
        return isinstance(expected, str) and expected in names
    if level == "region":
        return _region_match(candidate, target)
    raise ContractError(f"unknown matching level: {level}")


def _first_rank(
    candidates: list[dict[str, Any]], targets: list[dict[str, Any]], level: str
) -> int | None:
    ranks = [
        int(candidate["rank"])
        for candidate in candidates
        for target in targets
        if _matches(candidate, target, level)
    ]
    return min(ranks) if ranks else None


def _location_match(candidate: dict[str, Any], location: dict[str, Any]) -> bool:
    if "region" in location:
        return _matches(candidate, location, "region")
    if "symbol" in location:
        return _matches(candidate, location, "symbol")
    return _matches(candidate, location, "file")


def _role_first_rank(candidates: list[dict[str, Any]], targets: list[dict[str, Any]]) -> int | None:
    ranks = [
        int(candidate["rank"])
        for candidate in candidates
        for target in targets
        if _location_match(candidate, target)
    ]
    return min(ranks) if ranks else None


def _top_role(
    candidate: dict[str, Any],
    targets: list[dict[str, Any]],
    negatives: list[dict[str, Any]],
) -> str | None:
    roles = [
        location["role"]
        for location in [*targets, *negatives]
        if _location_match(candidate, location)
    ]
    return roles[0] if len(set(roles)) == 1 else None


def score_trace_code_case(
    label: dict[str, Any],
    *,
    candidates: list[dict[str, Any]],
    indexed_files: list[str],
    indexed_symbols: list[dict[str, str]],
    observed_disposition: str,
    taxonomy: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Score one label-separated Trace Code case."""
    validate_location_label(label)
    if observed_disposition not in DISPOSITIONS:
        raise ContractError("observed disposition is invalid")
    payload = label["payload"]
    targets = payload["targets"]
    primary_targets = [item for item in targets if item["role"] == payload["primary_role"]]
    candidates = sorted(candidates, key=lambda item: int(item["rank"]))
    if [int(item["rank"]) for item in candidates] != list(range(1, len(candidates) + 1)):
        raise ContractError("candidate ranks must be contiguous and one-based")
    file_rank = _first_rank(candidates, primary_targets, "file")
    symbol_targets = [item for item in primary_targets if "symbol" in item]
    region_targets = [item for item in primary_targets if "region" in item]
    symbol_rank = _first_rank(candidates, symbol_targets, "symbol") if symbol_targets else None
    region_rank = _first_rank(candidates, region_targets, "region") if region_targets else None
    role_rank = _role_first_rank(candidates, primary_targets)
    hard_negative_rank = _first_rank(candidates, payload["hard_negatives"], "file")
    top_role = _top_role(candidates[0], targets, payload["hard_negatives"]) if candidates else None
    wrong_role_top_one = bool(
        candidates and top_role is not None and top_role != payload["primary_role"]
    )
    hard_negative_outranked = hard_negative_rank is not None and (
        file_rank is None or hard_negative_rank < file_rank
    )
    indexed_file_set = set(indexed_files)
    indexed_symbol_set = {
        (item.get("path"), item.get("symbol")) for item in indexed_symbols if isinstance(item, dict)
    }
    target_indexability = bool(primary_targets) and all(
        target["path"] in indexed_file_set
        and ("symbol" not in target or (target["path"], target["symbol"]) in indexed_symbol_set)
        for target in primary_targets
    )
    expected = payload["expected_disposition"]
    unsafe_expected = expected in {
        "BENIGN_CONTROL",
        "INSUFFICIENT_EVIDENCE",
        "UNSUPPORTED_INPUT",
    }
    false_supported = observed_disposition == "SUPPORTED" and expected != "SUPPORTED"
    false_vulnerability = payload["safe_control"] and observed_disposition in {
        "SUPPORTED",
        "SUSPICIOUS",
    }
    unsafe_non_abstention = unsafe_expected and observed_disposition in {
        "SUPPORTED",
        "SUSPICIOUS",
    }
    unsupported_acceptance = expected == "UNSUPPORTED_INPUT" and observed_disposition not in {
        "UNSUPPORTED_INPUT",
        "INSUFFICIENT_EVIDENCE",
    }
    failures: list[str] = []
    if false_supported:
        failures.append("FALSE_SUPPORTED_DISPOSITION")
    if false_vulnerability:
        failures.append("FALSE_VULNERABILITY")
    if unsafe_non_abstention:
        failures.append("UNSAFE_NON_ABSTENTION")
    if unsupported_acceptance:
        failures.append("UNSUPPORTED_INPUT_ACCEPTED")
    if wrong_role_top_one:
        failures.append("WRONG_LOCATION_ROLE_TOP_ONE")
    if hard_negative_outranked:
        failures.append("HARD_NEGATIVE_OUTRANKED_TARGET")
    case = make_record(
        "trace-code-case-result-v1",
        {
            "group_id": payload["group_id"],
            "repository_id": payload["repository_id"],
            "repository_family": payload["repository_family"],
            "label_state": payload["label_state"],
            "safe_control": payload["safe_control"],
            "expected_disposition": expected,
            "observed_disposition": observed_disposition,
            "ranking": {
                "file_first_rank": file_rank,
                "symbol_first_rank": symbol_rank,
                "region_first_rank": region_rank,
                "role_correct_first_rank": role_rank,
                "top_one_role": top_role,
                "wrong_location_role_top_one": wrong_role_top_one,
                "hard_negative_first_rank": hard_negative_rank,
                "hard_negative_outranked": hard_negative_outranked,
                "candidate_count": len(candidates),
            },
            "indexability": {
                "target_eligible": bool(primary_targets),
                "target_indexable": target_indexability,
                "file_eligible": bool(primary_targets),
                "symbol_eligible": bool(symbol_targets),
                "region_eligible": bool(region_targets),
            },
            "failures": sorted(failures),
            "taxonomy": dict(sorted((taxonomy or {}).items())),
        },
    )
    return case


def _macro(rows: list[dict[str, Any]], key: str, cutoffs: list[int]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row[key]].append(row)
    result: dict[str, Any] = {"count": len(grouped), "file_recall": {}, "false_supported": {}}
    for cutoff in cutoffs:
        values = [
            sum(
                item["ranking"]["file_first_rank"] is not None
                and item["ranking"]["file_first_rank"] <= cutoff
                for item in group
                if item["indexability"]["file_eligible"]
            )
            / sum(item["indexability"]["file_eligible"] for item in group)
            for group in grouped.values()
            if any(item["indexability"]["file_eligible"] for item in group)
        ]
        result["file_recall"][str(cutoff)] = {
            "units": len(values),
            "mean": sum(values) / len(values) if values else None,
        }
    safety_values = [
        sum(
            item["observed_disposition"] == "SUPPORTED"
            and item["expected_disposition"] != "SUPPORTED"
            for item in group
        )
        / len(group)
        for group in grouped.values()
    ]
    result["false_supported"] = {
        "units": len(safety_values),
        "mean": sum(safety_values) / len(safety_values) if safety_values else None,
    }
    return result


def aggregate_trace_code_metrics(
    cases: list[dict[str, Any]], metric_spec: dict[str, Any]
) -> dict[str, Any]:
    """Aggregate V0.3 metrics without forcing ambiguous labels into denominators."""
    validate_metric_specification(metric_spec)
    for case in cases:
        validate_record(case)
        if case["schema_version"] != "trace-code-case-result-v1":
            raise ContractError("Trace Code aggregate received the wrong case schema")
    excluded = Counter(
        case["payload"]["label_state"]
        for case in cases
        if case["payload"]["label_state"] not in PRIMARY_LABEL_STATES
    )
    rows = [
        case["payload"] for case in cases if case["payload"]["label_state"] in PRIMARY_LABEL_STATES
    ]
    cutoffs = metric_spec["payload"]["cutoffs"]
    eligible = [row for row in rows if row["indexability"]["file_eligible"]]
    symbol_eligible = [row for row in rows if row["indexability"]["symbol_eligible"]]
    region_eligible = [row for row in rows if row["indexability"]["region_eligible"]]
    safe = [row for row in rows if row["safe_control"]]
    unsupported = [row for row in rows if row["expected_disposition"] == "UNSUPPORTED_INPUT"]
    unsafe_expected = [
        row
        for row in rows
        if row["expected_disposition"]
        in {"BENIGN_CONTROL", "INSUFFICIENT_EVIDENCE", "UNSUPPORTED_INPUT"}
    ]
    hard_negative = [row for row in rows if row["ranking"]["hard_negative_first_rank"] is not None]
    false_supported_count = sum(
        row["observed_disposition"] == "SUPPORTED" and row["expected_disposition"] != "SUPPORTED"
        for row in rows
    )
    false_vulnerability_count = sum(
        row["observed_disposition"] in {"SUPPORTED", "SUSPICIOUS"} for row in safe
    )
    unsafe_non_abstention_count = sum(
        row["observed_disposition"] in {"SUPPORTED", "SUSPICIOUS"} for row in unsafe_expected
    )
    unsupported_acceptance_count = sum(
        row["observed_disposition"] not in {"UNSUPPORTED_INPUT", "INSUFFICIENT_EVIDENCE"}
        for row in unsupported
    )
    micro: dict[str, Any] = {
        "group_count": len(rows),
        "target_indexability": _ratio(
            sum(row["indexability"]["target_indexable"] for row in eligible), len(eligible)
        ),
        "file_recall": {},
        "symbol_recall": {},
        "region_recall": {},
        "location_role_correct_recall": {},
        "mean_reciprocal_rank": {
            "sum": sum(
                1 / row["ranking"]["file_first_rank"]
                for row in eligible
                if row["ranking"]["file_first_rank"] is not None
            ),
            "denominator": len(eligible),
            "mean": (
                sum(
                    1 / row["ranking"]["file_first_rank"]
                    for row in eligible
                    if row["ranking"]["file_first_rank"] is not None
                )
                / len(eligible)
                if eligible
                else None
            ),
        },
        "no_relevant_candidate": _ratio(
            sum(row["ranking"]["file_first_rank"] is None for row in eligible), len(eligible)
        ),
        "false_vulnerability_rate": _ratio(false_vulnerability_count, len(safe)),
        "false_supported_disposition": {
            "count": false_supported_count,
            "rate": _ratio(false_supported_count, len(rows)),
        },
        "wrong_location_role_top_one": _ratio(
            sum(row["ranking"]["wrong_location_role_top_one"] for row in eligible),
            len(eligible),
        ),
        "hard_negative_outrank": _ratio(
            sum(row["ranking"]["hard_negative_outranked"] for row in hard_negative),
            len(hard_negative),
        ),
        "unsafe_non_abstention": _ratio(unsafe_non_abstention_count, len(unsafe_expected)),
        "unsupported_input_acceptance": _ratio(unsupported_acceptance_count, len(unsupported)),
        "disposition_confusion": dict(
            sorted(
                Counter(
                    f"{row['expected_disposition']}->{row['observed_disposition']}" for row in rows
                ).items()
            )
        ),
        "abstention_coverage": _ratio(
            sum(
                row["observed_disposition"] in {"INSUFFICIENT_EVIDENCE", "UNSUPPORTED_INPUT"}
                for row in rows
            ),
            len(rows),
        ),
    }
    for cutoff in cutoffs:
        micro["file_recall"][str(cutoff)] = _ratio(
            sum(
                row["ranking"]["file_first_rank"] is not None
                and row["ranking"]["file_first_rank"] <= cutoff
                for row in eligible
            ),
            len(eligible),
        )
        micro["symbol_recall"][str(cutoff)] = _ratio(
            sum(
                row["ranking"]["symbol_first_rank"] is not None
                and row["ranking"]["symbol_first_rank"] <= cutoff
                for row in symbol_eligible
            ),
            len(symbol_eligible),
        )
        micro["region_recall"][str(cutoff)] = _ratio(
            sum(
                row["ranking"]["region_first_rank"] is not None
                and row["ranking"]["region_first_rank"] <= cutoff
                for row in region_eligible
            ),
            len(region_eligible),
        )
        micro["location_role_correct_recall"][str(cutoff)] = _ratio(
            sum(
                row["ranking"]["role_correct_first_rank"] is not None
                and row["ranking"]["role_correct_first_rank"] <= cutoff
                for row in eligible
            ),
            len(eligible),
        )
    strata: dict[str, int] = Counter()
    for row in rows:
        for dimension in (
            "language",
            "cwe",
            "repository_size_band",
            "finding_format",
            "label_source",
            "hard_negative_family",
            "direct_cue",
        ):
            strata[f"{dimension}={row['taxonomy'].get(dimension, 'UNKNOWN')}"] += 1
    return make_record(
        "trace-code-aggregate-metrics-v1",
        {
            "metric_spec_id": metric_spec["record_id"],
            "case_result_ids": [case["record_id"] for case in cases],
            "micro": micro,
            "repository_macro": _macro(rows, "repository_id", cutoffs),
            "repository_family_macro": _macro(rows, "repository_family", cutoffs),
            "strata": dict(sorted(strata.items())),
            "excluded": dict(sorted(excluded.items())),
        },
    )
