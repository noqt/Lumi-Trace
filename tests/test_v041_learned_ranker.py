# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from lumi_trace.learned_ranker import (
    ALGORITHM,
    BASE_RANKER,
    DIMENSIONS,
    FEATURE_CONTRACT,
    LEARNED_MULTIPLIER,
    LEARNED_SUPPORT,
    MODEL_SCHEMA,
    feature_vector,
    rank_with_model,
    verify_model_artifact,
)


def _finding() -> dict:
    return {
        "rule": {"id": "GHSA-test", "name": "path traversal", "cwes": [], "tags": []},
        "message": {"title": "path traversal", "text": "unsafe archive extraction"},
        "keywords": ["archive"],
        "locations": [],
    }


def _candidate(candidate_id: str, path: str, symbol: str) -> dict:
    return {
        "candidate_id": candidate_id,
        "kind": "symbol",
        "path": path,
        "symbol": symbol,
        "region": {"start_line": 1, "end_line": 3},
        "role": "implementation",
        "integer_score": 1000,
        "score_components": {"BM25": 1000},
        "rank": 1,
    }


def _artifact(weight_index: int) -> dict:
    from lumi_trace.canonical import stable_id

    value = {
        "schema_version": MODEL_SCHEMA,
        "algorithm": ALGORITHM,
        "feature_contract": FEATURE_CONTRACT,
        "dimensions": DIMENSIONS,
        "base_ranker": BASE_RANKER,
        "weights": [{"index": weight_index, "weight": 10}],
        "active_parameters": 1,
        "training_manifest_id": "manifest:test",
        "training_data_id": "data:test",
        "training_config": {"epochs": 1},
        "completed_epochs": 1,
        "pair_updates": 1,
        "family_balanced": True,
        "foundation_model": None,
        "tokenizer": None,
        "remote_code": False,
        "hosted_service": False,
        "cpu_inference": True,
    }
    value["artifact_id"] = stable_id("lumi-trace-localization-model", value)
    return value


def test_product_feature_projection_and_integer_model_replay() -> None:
    preferred = _candidate("candidate:preferred", "src/archive.py", "safe_extract")
    other = _candidate("candidate:other", "src/view.py", "render")
    preferred_vector = dict(feature_vector(_finding(), preferred))
    other_vector = dict(feature_vector(_finding(), other))
    unique = next(
        index
        for index, value in preferred_vector.items()
        if value > 0 and index not in other_vector
    )
    artifact = _artifact(unique)
    assert verify_model_artifact(artifact) == artifact
    first = rank_with_model(_finding(), [other, preferred], artifact)
    second = rank_with_model(_finding(), [other, preferred], artifact)
    assert first == second
    assert first[0]["candidate_id"] == "candidate:preferred"
    assert first[0]["score_components"]["LEARNED_INTEGER_LINEAR"] > 0
    assert (
        first[0]["score_components"]["LEARNED_HYBRID_CONTRIBUTION"]
        == first[0]["score_components"]["LEARNED_INTEGER_LINEAR"] * LEARNED_MULTIPLIER
    )


def test_learned_ranker_rejects_candidates_outside_training_support() -> None:
    candidate = _candidate("candidate:repeated", "src/archive.py", "safe_extract")
    artifact = _artifact(0)
    with pytest.raises(Exception, match="support"):
        rank_with_model(
            _finding(),
            [
                {**candidate, "candidate_id": f"candidate:{index}"}
                for index in range(LEARNED_SUPPORT + 1)
            ],
            artifact,
        )
