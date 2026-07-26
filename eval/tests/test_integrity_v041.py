# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from trace_eval.errors import ContractError, PolicyError
from trace_eval.integrity_v041 import (
    consume_qualification_budget,
    create_qualification_budget,
    make_scoring_labels,
    one_sided_wilson_bound,
    score_sealed_localization,
)


def _raw() -> dict:
    from lumi_trace.canonical import stable_id

    candidate = {
        "candidate_id": "localization-candidate:" + "a" * 64,
        "kind": "symbol",
        "path": "src/parser.py",
        "symbol": "parse",
        "region": {"start_line": 10, "end_line": 20},
        "role": "implementation",
        "integer_score": 100,
        "score_components": {"BM25": 100},
        "rank": 1,
    }
    inventory_candidate = {
        key: candidate[key] for key in ("candidate_id", "kind", "path", "symbol", "region", "role")
    }
    value = {
        "schema_version": "localization-raw-ranking-v0.4.1",
        "request_id": "localization-request:" + "b" * 64,
        "runtime_identity": "lumi-trace-runtime-v0.4.1-pre-release.8",
        "repository": {
            "repository_id": "repository:" + "c" * 64,
            "manifest_id": "repository-manifest:" + "d" * 64,
            "source_kind": "archive",
        },
        "quarantine_policy": "target-agnostic-source-quarantine-v0.4.1.1",
        "candidate_algorithm": "label-blind-python-role-candidates-v0.4.1.5",
        "ranker": "role-aware-sparse-v0.4.1.1",
        "model_artifact_id": None,
        "generation": {"candidate_count": 1},
        "candidate_count_ranked": 1,
        "candidate_inventory": [inventory_candidate],
        "candidates": [candidate],
        "abstention": {"abstained": False, "reason": None},
        "telemetry": {
            "wall_seconds": 0.1,
            "cpu_seconds": 0.1,
            "peak_python_bytes": 100,
            "peak_memory_measured": True,
            "network_used": False,
            "repository_code_executed": False,
        },
        "confidence_is_not_probability": True,
    }
    value["ranking_id"] = stable_id("localization-ranking", [candidate["candidate_id"]])
    value["raw_output_seal"] = stable_id("localization-raw-output", value)
    return value


def _labels() -> dict:
    return make_scoring_labels(
        group_id="group:one",
        family_id="family:one",
        targets=[
            {
                "path": "src/parser.py",
                "symbol": "parse",
                "region": {"start_line": 10, "end_line": 20},
                "role": "VULNERABLE_IMPLEMENTATION",
            }
        ],
        hard_negative_paths=["tests/test_parser.py"],
        matched_safe_control_id="control:one",
        semantic_review_resolution_id="review:one",
    )


def test_scoring_requires_a_valid_raw_output_seal() -> None:
    tampered = copy.deepcopy(_raw())
    tampered["candidates"][0]["path"] = "src/other.py"
    tampered["candidate_inventory"][0]["path"] = "src/other.py"
    with pytest.raises(Exception, match="seal"):
        score_sealed_localization(
            tampered,
            _labels(),
            metric_specification_id="metric:v0.4.1",
        )


def test_scoring_begins_after_seal_and_does_not_mutate_builder_output() -> None:
    raw = _raw()
    before = copy.deepcopy(raw)
    scored = score_sealed_localization(
        raw,
        _labels(),
        metric_specification_id="metric:v0.4.1",
    )
    assert raw == before
    assert scored["seal_verified_before_scoring"] is True
    assert scored["builder_output_mutated"] is False
    assert scored["metrics"]["location_role_recall_at_20"] is True
    assert scored["metrics"]["file_target_indexable"] is True
    assert scored["metrics"]["role_target_indexable"] is True


def test_indexability_uses_the_generated_inventory_not_only_the_exported_head() -> None:
    from lumi_trace.canonical import stable_id

    raw = _raw()
    hidden = {
        "candidate_id": "localization-candidate:" + "e" * 64,
        "kind": "symbol",
        "path": "src/hidden.py",
        "symbol": "hidden_target",
        "region": {"start_line": 1, "end_line": 2},
        "role": "implementation",
    }
    raw["candidate_inventory"].append(hidden)
    raw["candidate_inventory"].sort(key=lambda item: item["candidate_id"])
    raw["candidate_count_ranked"] = 2
    raw["generation"]["candidate_count"] = 2
    raw["raw_output_seal"] = stable_id(
        "localization-raw-output",
        raw,
        omit_keys=("raw_output_seal",),
    )
    labels = make_scoring_labels(
        group_id="group:hidden",
        family_id="family:hidden",
        targets=[
            {
                "path": "src/hidden.py",
                "symbol": "hidden_target",
                "region": {"start_line": 1, "end_line": 2},
                "role": "VULNERABLE_IMPLEMENTATION",
            }
        ],
        hard_negative_paths=[],
        matched_safe_control_id="control:hidden",
        semantic_review_resolution_id="review:hidden",
    )
    scored = score_sealed_localization(
        raw,
        labels,
        metric_specification_id="metric:v0.4.1",
    )
    assert scored["metrics"]["file_target_indexable"] is True
    assert scored["metrics"]["role_target_indexable"] is True
    assert scored["metrics"]["file_recall_at_20"] is False


def test_scoring_label_identity_fails_closed() -> None:
    labels = _labels()
    labels["targets"][0]["path"] = "src/other.py"
    with pytest.raises(ContractError, match="IDENTITY"):
        score_sealed_localization(
            _raw(),
            labels,
            metric_specification_id="metric:v0.4.1",
        )


def test_one_sided_confidence_bounds_use_explicit_denominators() -> None:
    assert one_sided_wilson_bound(90, 100, side="lower") < 0.90
    assert one_sided_wilson_bound(10, 100, side="upper") > 0.10
    assert one_sided_wilson_bound(0, 0) is None


def test_qualification_budget_is_single_use(tmp_path: Path) -> None:
    budget = create_qualification_budget(
        partition_seal_id="partition:v0.4.1",
        custodian_root=tmp_path,
    )
    consumed = consume_qualification_budget(
        budget,
        readiness_case_id="readiness:v0.4.1",
        authorization="QUALIFICATION_EXECUTION_AUTHORISED",
    )
    assert consumed["remaining"] == 0
    with pytest.raises(PolicyError, match="CONSUMPTION_REJECTED"):
        consume_qualification_budget(
            consumed,
            readiness_case_id="readiness:v0.4.1",
            authorization="QUALIFICATION_EXECUTION_AUTHORISED",
        )


def test_qualification_budget_rejects_non_ready_decision(tmp_path: Path) -> None:
    budget = create_qualification_budget(
        partition_seal_id="partition:v0.4.1",
        custodian_root=tmp_path,
    )
    with pytest.raises(PolicyError, match="CONSUMPTION_REJECTED"):
        consume_qualification_budget(
            budget,
            readiness_case_id="readiness:v0.4.1",
            authorization="QUALIFICATION_NOT_READY / CONTINUE_DEVELOPMENT",
        )
