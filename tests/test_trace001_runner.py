# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
from trace_eval.errors import ContractError
from trace_eval.trace001 import FEATURE_NAMES, TrainingConfig, train_linear_ranker

from scripts.run_trace_001 import (
    _load_authority,
    _require_private_root,
    _score_feature_record,
)


def test_trace001_runner_rejects_non_governed_private_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="governed private G"):
        _require_private_root(tmp_path)


def test_trace001_runner_fails_closed_without_final_authority(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="missing|unsafe"):
        _load_authority(tmp_path)


def test_trace001_scoring_applies_private_labels_after_each_ranking() -> None:
    positive = {name: 1.0 for name in FEATURE_NAMES}
    negative = {name: 0.0 for name in FEATURE_NAMES}
    checkpoint = train_linear_ranker(
        [
            {
                "group_id": "group:1",
                "family_id": "family:1",
                "audit_card_id": "card:1",
                "partition": "TRAINING",
                "candidates": [
                    {"candidate_id": "candidate:positive", "features": positive, "target": True},
                    {"candidate_id": "candidate:negative", "features": negative, "target": False},
                ],
            }
        ],
        audit_card_allowlist={"card:1"},
        training_manifest_id="manifest:1",
        config=TrainingConfig(epochs=1),
    )
    record = {
        "group_id": "group:evaluation",
        "family_id": "family:evaluation",
        "audit_card_id": "card:evaluation",
        "record_id": "feature:evaluation",
        "partition": "MODEL_SELECTION",
        "training_candidates": [
            {"candidate_id": "candidate:positive", "features": positive, "target": True},
            {"candidate_id": "candidate:negative", "features": negative, "target": False},
        ],
        "private_scoring_labels": {
            "file_target_candidate_ids": ["candidate:positive"],
            "role_target_candidate_ids": ["candidate:positive"],
            "hard_negative_candidate_ids": ["candidate:negative"],
        },
    }
    result = _score_feature_record(checkpoint, record)
    assert result["labels_applied_after_ranking"] is True
    assert result["views"]["FULL"]["metrics"]["file_recall_at_5"] is True
    assert result["views"]["FULL"]["metrics"]["location_role_recall_at_20"] is True
    assert set(result["views"]) == {
        "FULL",
        "NATURAL_CUE_MARKED",
        "NO_PATH",
        "NO_SYMBOL",
        "REDUCED_DESCRIPTION",
        "IDENTIFIER_ABLATION",
    }
