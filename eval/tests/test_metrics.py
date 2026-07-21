# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

import pytest

from trace_eval.contracts import make_record
from trace_eval.errors import ContractError
from trace_eval.metrics import _target_coverage, aggregate_metrics


def _metric() -> dict[str, object]:
    return make_record(
        "metric-specification-v1",
        {
            "cutoffs": [1, 5],
            "k_max": 5,
            "region_overlap": "ANY_ONE_BASED_LINE_OVERLAP",
            "denominators": {
                "principal_recall": "all file-eligible scheduled groups",
                "conditional_recall": "labelled-target file-indexable groups",
                "symbol_recall": "symbol-eligible groups",
                "region_hit_rate": "region-eligible groups",
            },
            "aggregation": ["GROUP_MICRO", "REPOSITORY_MACRO"],
            "integrity_floors": {
                "unauthorised_access": 0,
                "holdback_exposure": 0,
                "false_confirmations": 0,
                "manifest_verification_rate": 1,
                "same_host_identity_rate": 1,
            },
        },
    )


def _case(
    name: str,
    repository: str,
    rank: int | None,
    *,
    indexable: bool = True,
    symbol_rank: int | None = None,
    region_rank: int | None = None,
    case_class: str = "positive",
    false_confirmation: bool = False,
) -> dict[str, object]:
    return make_record(
        "case-result-v1",
        {
            "group_id": f"group:{name}",
            "attempt_id": f"attempt:{name}",
            "label_set_id": f"label:{name}",
            "indexability": {
                "file_eligible": True,
                "file_indexable": indexable,
                "symbol_eligible": symbol_rank is not None,
                "symbol_indexable": symbol_rank is not None,
                "region_eligible": region_rank is not None,
            },
            "ranking": {
                "file_first_rank": rank,
                "symbol_first_rank": symbol_rank,
                "region_first_rank": region_rank,
                "hard_negative_first_rank": 1 if case_class == "hard_negative" else None,
                "hard_negative_outranked": case_class == "hard_negative",
                "candidate_count": 5,
                "target_coverage": {
                    "numerator": 1 if rank is not None else 0,
                    "denominator": 1,
                    "rate": 1.0 if rank is not None else 0.0,
                },
                "score_reason_counts": {"MESSAGE_CONTENT_MATCH": 1},
            },
            "reproduction": {
                "expected": "INSUFFICIENT_EVIDENCE",
                "observed": "CONFIRMED" if false_confirmation else "INSUFFICIENT_EVIDENCE",
                "false_confirmation": false_confirmation,
            },
            "failure_codes": ["FALSE_CONFIRMATION"] if false_confirmation else [],
            "repository_id": repository,
            "taxonomy": {
                "language": "python",
                "cwe": "CWE-22",
                "finding_format": "manual",
                "target_kind": "file",
                "repository_size_band": "TINY",
                "origin": "constructed",
            },
            "case_class": case_class,
            "stage": "COMPLETE",
        },
    )


def test_hand_calculated_micro_macro_and_separate_location_metrics() -> None:
    cases = [
        _case("a1", "repository:a", 1, symbol_rank=1),
        _case("a2", "repository:a", None, indexable=False),
        _case("b1", "repository:b", 5, region_rank=5, case_class="hard_negative"),
    ]
    aggregate = aggregate_metrics(cases, _metric(), "run:test")
    micro = aggregate["payload"]["micro"]
    assert micro["file_recall_end_to_end"]["1"] == {
        "numerator": 1,
        "denominator": 3,
        "rate": 1 / 3,
    }
    assert micro["file_recall_indexable_only"]["1"]["denominator"] == 2
    assert micro["symbol_recall"]["1"]["rate"] == 1.0
    assert micro["region_hit_rate"]["1"]["rate"] == 0.0
    assert micro["hard_negative_outrank"]["denominator"] == 1
    assert aggregate["payload"]["repository_macro"]["file_recall"]["1"]["mean"] == 0.25
    assert micro["mean_reciprocal_rank"]["mean"] == pytest.approx(0.4)


def test_multiple_accepted_targets_use_first_hit_and_report_target_coverage() -> None:
    candidates = [
        {"kind": "file", "path": "src/a.py", "rank": 1},
        {"kind": "file", "path": "src/other.py", "rank": 2},
    ]
    targets = [
        {"kind": "file", "path": "src/a.py"},
        {"kind": "file", "path": "src/b.py"},
    ]
    assert _target_coverage(candidates, targets) == {
        "numerator": 1,
        "denominator": 2,
        "rate": 0.5,
    }


def test_empty_strata_and_denominators_are_explicit() -> None:
    aggregate = aggregate_metrics([], _metric(), "run:empty")
    assert aggregate["payload"]["micro"]["file_indexability"]["rate"] is None
    assert aggregate["payload"]["repository_macro"]["repository_count"] == 0
    assert aggregate["payload"]["strata"] == {}


def test_false_confirmation_is_absolute_and_rate_bearing() -> None:
    aggregate = aggregate_metrics(
        [_case("unsafe", "repository:a", 1, false_confirmation=True)],
        _metric(),
        "run:false-confirmation",
    )
    metric = aggregate["payload"]["micro"]["false_confirmations"]
    assert metric["count"] == 1
    assert metric["rate"]["rate"] == 1.0


def test_adversarial_denominator_change_is_rejected() -> None:
    changed = deepcopy(_metric())
    changed["payload"]["denominators"]["principal_recall"] = "successful groups only"
    changed = make_record("metric-specification-v1", changed["payload"])
    with pytest.raises(ContractError, match="denominators"):
        aggregate_metrics([_case("a", "repository:a", 1)], changed, "run:adversarial")
