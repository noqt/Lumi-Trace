# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

import pytest

from trace_eval.code_metrics import (
    aggregate_trace_code_metrics,
    default_metric_specification,
    score_trace_code_case,
    validate_location_label,
    validate_metric_specification,
)
from trace_eval.contracts import make_record
from trace_eval.errors import ContractError


def _label(
    name: str,
    *,
    state: str = "ACCEPTED",
    expected: str = "SUPPORTED",
    safe: bool = False,
    targets: list[dict[str, object]] | None = None,
    negatives: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    selected_targets = (
        targets
        if targets is not None
        else (
            []
            if safe
            else [
                {
                    "path": f"src/{name}.py",
                    "symbol": "unsafe_parse",
                    "region": {"start_line": 10, "end_line": 14},
                    "role": "VULNERABLE_IMPLEMENTATION",
                }
            ]
        )
    )
    return make_record(
        "trace-code-location-label-v1",
        {
            "group_id": f"group:{name}",
            "label_state": state,
            "repository_id": f"repository:{name}",
            "repository_family": f"family:{name[0]}",
            "expected_disposition": expected,
            "targets": selected_targets,
            "primary_role": "VULNERABLE_IMPLEMENTATION",
            "hard_negatives": negatives or [],
            "safe_control": safe,
            "review_receipt_ids": (
                [] if state not in {"ACCEPTED", "ACCEPTED_WITH_MULTIPLE_TARGETS"} else ["review:1"]
            ),
            "corrections": [],
            "constructed_without_runner_output": True,
        },
    )


def test_harness_outranking_implementation_is_counted_separately() -> None:
    label = _label(
        "parser",
        negatives=[
            {
                "path": "tests/test_parser.py",
                "role": "HARNESS",
                "family": "REPORTED_HARNESS_VS_IMPLEMENTATION",
            }
        ],
    )
    case = score_trace_code_case(
        label,
        candidates=[
            {"rank": 1, "path": "tests/test_parser.py"},
            {
                "rank": 2,
                "path": "src/parser.py",
                "symbol": {"name": "unsafe_parse"},
                "region": {"start_line": 12, "end_line": 12},
            },
        ],
        indexed_files=["tests/test_parser.py", "src/parser.py"],
        indexed_symbols=[{"path": "src/parser.py", "symbol": "unsafe_parse"}],
        observed_disposition="SUPPORTED",
    )
    ranking = case["payload"]["ranking"]
    assert ranking["file_first_rank"] == 2
    assert ranking["symbol_first_rank"] == 2
    assert ranking["region_first_rank"] == 2
    assert ranking["top_one_role"] == "HARNESS"
    assert ranking["wrong_location_role_top_one"] is True
    assert ranking["hard_negative_eligible"] is True
    assert ranking["hard_negative_outranked"] is True


def test_hard_negative_denominator_requires_an_accepted_target() -> None:
    safe_label = _label(
        "safe-negative",
        expected="INSUFFICIENT_EVIDENCE",
        safe=True,
        negatives=[
            {
                "path": "tests/witness.py",
                "role": "WITNESS",
                "family": "SAFE_CONTROL_WITNESS",
            }
        ],
    )
    safe_case = score_trace_code_case(
        safe_label,
        candidates=[{"rank": 1, "path": "tests/witness.py"}],
        indexed_files=["tests/witness.py"],
        indexed_symbols=[],
        observed_disposition="INSUFFICIENT_EVIDENCE",
    )
    assert safe_case["payload"]["ranking"]["hard_negative_eligible"] is False
    aggregate = aggregate_trace_code_metrics([safe_case], default_metric_specification())
    assert aggregate["payload"]["micro"]["hard_negative_outrank"] == {
        "numerator": 0,
        "denominator": 0,
        "rate": None,
    }


def test_labelled_hard_negative_remains_in_denominator_when_not_retrieved() -> None:
    label = _label(
        "unretrieved-negative",
        negatives=[
            {
                "path": "tests/witness.py",
                "role": "WITNESS",
                "family": "UNRETRIEVED_WITNESS",
            }
        ],
    )
    case = score_trace_code_case(
        label,
        candidates=[{"rank": 1, "path": "src/unretrieved-negative.py"}],
        indexed_files=["src/unretrieved-negative.py", "tests/witness.py"],
        indexed_symbols=[],
        observed_disposition="INSUFFICIENT_EVIDENCE",
    )
    assert case["payload"]["ranking"]["hard_negative_eligible"] is True
    assert case["payload"]["ranking"]["hard_negative_first_rank"] is None
    aggregate = aggregate_trace_code_metrics([case], default_metric_specification())
    assert aggregate["payload"]["micro"]["hard_negative_outrank"] == {
        "numerator": 0,
        "denominator": 1,
        "rate": 0.0,
    }


def test_observation_is_not_accepted_as_vulnerable_implementation() -> None:
    label = _label(
        "sink",
        negatives=[
            {
                "path": "src/sink.py",
                "role": "OBSERVATION",
                "family": "OBSERVATION_VS_UPSTREAM_SOURCE",
            }
        ],
    )
    case = score_trace_code_case(
        label,
        candidates=[
            {"rank": 1, "path": "src/sink.py"},
            {
                "rank": 2,
                "path": "src/sink.py",
                "symbol": {"name": "unsafe_parse"},
                "region": {"start_line": 10, "end_line": 14},
            },
        ],
        indexed_files=["src/sink.py"],
        indexed_symbols=[{"path": "src/sink.py", "symbol": "unsafe_parse"}],
        observed_disposition="SUPPORTED",
    )
    assert case["payload"]["ranking"]["file_first_rank"] == 1
    assert case["payload"]["ranking"]["role_correct_first_rank"] == 2
    assert case["payload"]["ranking"]["top_one_role"] == "OBSERVATION"
    assert case["payload"]["ranking"]["wrong_location_role_top_one"] is True


def test_multiple_accepted_targets_and_exact_levels() -> None:
    label = _label(
        "multi",
        state="ACCEPTED_WITH_MULTIPLE_TARGETS",
        targets=[
            {
                "path": "src/a.py",
                "symbol": "decode",
                "role": "VULNERABLE_IMPLEMENTATION",
            },
            {
                "path": "src/b.py",
                "region": {"start_line": 30, "end_line": 33},
                "role": "VULNERABLE_IMPLEMENTATION",
            },
        ],
    )
    case = score_trace_code_case(
        label,
        candidates=[
            {"rank": 1, "path": "src/a.py", "symbol": {"qualified_name": "decode"}},
            {"rank": 2, "path": "src/b.py", "region": {"start_line": 33, "end_line": 35}},
        ],
        indexed_files=["src/a.py", "src/b.py"],
        indexed_symbols=[{"path": "src/a.py", "symbol": "decode"}],
        observed_disposition="SUPPORTED",
    )
    assert case["payload"]["ranking"]["file_first_rank"] == 1
    assert case["payload"]["ranking"]["symbol_first_rank"] == 1
    assert case["payload"]["ranking"]["region_first_rank"] == 2
    assert case["payload"]["indexability"]["target_indexable"] is True


@pytest.mark.parametrize(
    ("expected", "observed", "failure"),
    [
        ("BENIGN_CONTROL", "SUPPORTED", "FALSE_VULNERABILITY"),
        ("INSUFFICIENT_EVIDENCE", "SUSPICIOUS", "UNSAFE_NON_ABSTENTION"),
        ("UNSUPPORTED_INPUT", "SUSPICIOUS", "UNSUPPORTED_INPUT_ACCEPTED"),
    ],
)
def test_safety_failures_are_absolute_and_rate_bearing(
    expected: str, observed: str, failure: str
) -> None:
    label = _label("safe", expected=expected, safe=True)
    case = score_trace_code_case(
        label,
        candidates=[],
        indexed_files=[],
        indexed_symbols=[],
        observed_disposition=observed,
    )
    assert failure in case["payload"]["failures"]
    aggregate = aggregate_trace_code_metrics([case], default_metric_specification())
    assert aggregate["payload"]["micro"]["unsafe_non_abstention"]["denominator"] == 1


def test_ambiguous_labels_are_excluded_from_primary_denominators() -> None:
    label = _label(
        "ambiguous",
        state="AMBIGUOUS_EXCLUDED_FROM_PRIMARY_METRICS",
    )
    case = score_trace_code_case(
        label,
        candidates=[{"rank": 1, "path": "src/ambiguous.py"}],
        indexed_files=["src/ambiguous.py"],
        indexed_symbols=[],
        observed_disposition="SUSPICIOUS",
    )
    aggregate = aggregate_trace_code_metrics([case], default_metric_specification())
    assert aggregate["payload"]["micro"]["group_count"] == 0
    assert aggregate["payload"]["excluded"] == {"AMBIGUOUS_EXCLUDED_FROM_PRIMARY_METRICS": 1}


def test_micro_repository_and_family_macro_denominators_are_distinct() -> None:
    cases = []
    for name, rank in (("a1", 1), ("a2", None), ("b1", 5)):
        label = _label(name)
        candidates = (
            []
            if rank is None
            else [
                {
                    "rank": 1,
                    "path": f"src/{name}.py" if rank == 1 else "src/other.py",
                },
                *(
                    [
                        {"rank": 2, "path": "src/other2.py"},
                        {"rank": 3, "path": "src/other3.py"},
                        {"rank": 4, "path": "src/other4.py"},
                        {"rank": 5, "path": f"src/{name}.py"},
                    ]
                    if rank == 5
                    else []
                ),
            ]
        )
        cases.append(
            score_trace_code_case(
                label,
                candidates=candidates,
                indexed_files=[f"src/{name}.py"],
                indexed_symbols=[{"path": f"src/{name}.py", "symbol": "unsafe_parse"}],
                observed_disposition="SUPPORTED",
            )
        )
    aggregate = aggregate_trace_code_metrics(cases, default_metric_specification())
    assert aggregate["payload"]["micro"]["file_recall"]["1"]["rate"] == pytest.approx(1 / 3)
    assert aggregate["payload"]["repository_macro"]["count"] == 3
    assert aggregate["payload"]["repository_family_macro"]["count"] == 2
    family_recall = aggregate["payload"]["repository_family_macro"]["file_recall"]["20"]
    assert family_recall["minimum"] == 0.5
    assert family_recall["maximum"] == 1.0
    assert family_recall["zero_unit_count"] == 0


def test_label_validation_rejects_unknown_role_and_non_append_only_correction() -> None:
    wrong_role = _label("bad")
    wrong_role["payload"]["targets"][0]["role"] = "STACK_FRAME"
    wrong_role = make_record("trace-code-location-label-v1", wrong_role["payload"])
    with pytest.raises(ContractError, match="role"):
        validate_location_label(wrong_role)
    correction = _label("correction")
    correction["payload"]["corrections"] = [{"sequence": 2}]
    correction = make_record("trace-code-location-label-v1", correction["payload"])
    with pytest.raises(ContractError, match="append-only"):
        validate_location_label(correction)


def test_fix_only_site_cannot_stand_in_for_vulnerable_implementation() -> None:
    fix_only = _label("fix-only")
    fix_only["payload"]["targets"] = [{"path": "src/fixed.py", "role": "FIX_SITE_ONLY"}]
    fix_only = make_record("trace-code-location-label-v1", fix_only["payload"])
    with pytest.raises(ContractError, match="declared primary role"):
        validate_location_label(fix_only)


def test_metric_definition_is_locked_against_safety_denominator_changes() -> None:
    changed = deepcopy(default_metric_specification())
    changed["payload"]["denominators"]["safety"] = "only successful cases"
    changed = make_record("trace-code-metric-specification-v2", changed["payload"])
    with pytest.raises(ContractError, match="denominators"):
        validate_metric_specification(changed)
