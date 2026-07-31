# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from lumi_trace.learned_ranker import feature_vector, verify_model_artifact

from trace_eval.learned_v041 import LearnedTrainingConfig, train_integer_pairwise_ranker


def _candidate(candidate_id: str, symbol: str, target: bool) -> dict:
    finding = {
        "rule": {"id": "rule", "name": "path traversal", "cwes": [], "tags": []},
        "message": {"title": "path traversal", "text": "archive extraction"},
        "keywords": ["archive"],
        "locations": [],
    }
    raw = {
        "candidate_id": candidate_id,
        "kind": "symbol",
        "path": f"src/{symbol}.py",
        "symbol": symbol,
        "region": {"start_line": 1, "end_line": 2},
        "role": "implementation",
        "integer_score": 100,
        "score_components": {"BM25": 100},
        "rank": 1,
    }
    return {
        "candidate_id": candidate_id,
        "features": [list(item) for item in feature_vector(finding, raw)],
        "target": target,
    }


def test_family_balanced_integer_training_is_exactly_replayable() -> None:
    groups = [
        {
            "group_id": "group:1",
            "family_id": "family:1",
            "audit_card_id": "card:1",
            "partition": "TRAINING",
            "candidates": [
                _candidate("candidate:positive", "safe_extract", True),
                _candidate("candidate:negative", "render", False),
            ],
        }
    ]
    config = LearnedTrainingConfig(epochs=3)
    first = train_integer_pairwise_ranker(
        groups,
        audit_card_allowlist={"card:1"},
        training_manifest_id="manifest:1",
        config=config,
    )
    second = train_integer_pairwise_ranker(
        groups,
        audit_card_allowlist={"card:1"},
        training_manifest_id="manifest:1",
        config=config,
    )
    assert first == second
    assert verify_model_artifact(first) == first
    assert first["pair_updates"] > 0
