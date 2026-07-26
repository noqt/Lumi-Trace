# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
from trace_eval.errors import PolicyError

from scripts.record_v0_4_status import _closure
from scripts.seal_v0_4 import _assert_disclosure_safe
from scripts.verify_v0_4_evidence import EXPECTED


def test_v04_public_projection_rejects_case_identity_fields() -> None:
    with pytest.raises(PolicyError, match="FORBIDDEN_FIELDS"):
        _assert_disclosure_safe(
            {
                "schema_version": "test-v1",
                "group_id": "private-group",
            }
        )


def test_v04_public_evidence_contract_includes_required_stop_records() -> None:
    assert {
        "closure-record.json",
        "corpus-assurance.json",
        "partition-assurance.json",
        "public-boundary-review.json",
        "qualification-summary.json",
        "training-readiness.json",
        "seal-manifest.json",
    } <= EXPECTED


def test_v04_verifier_rejects_missing_tree(tmp_path: Path) -> None:
    from scripts.verify_v0_4_evidence import verify

    with pytest.raises(ValueError, match="tree membership"):
        verify(tmp_path)


@pytest.mark.parametrize(
    ("kind", "passed", "trained", "expected"),
    [
        (
            "TRACE_001_LINEAR",
            True,
            True,
            "TRACE_001_VALIDATED / CONTROLLED_PILOT_READY",
        ),
        (
            "DETERMINISTIC",
            True,
            False,
            "DETERMINISTIC_GENERALISATION_QUALIFIED / CONTROLLED_PILOT_READY",
        ),
        (
            "TRACE_001_LINEAR",
            False,
            True,
            "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE",
        ),
        (
            "DETERMINISTIC",
            False,
            True,
            "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE",
        ),
        (
            "DETERMINISTIC",
            False,
            False,
            "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION",
        ),
    ],
)
def test_v04_final_status_uses_an_authorised_closure(
    kind: str,
    passed: bool,
    trained: bool,
    expected: str,
) -> None:
    qualification = {
        "selected_result": {
            "all_gates_passed": passed,
        }
    }
    lock = {"selected_candidate": {"kind": kind}}
    assert _closure(qualification, lock, trained=trained) == expected
