# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

import pytest

from trace_eval.errors import ContractError, PolicyError
from trace_eval.trace001 import (
    FEATURE_NAMES,
    TrainingConfig,
    _training_data_identity,
    quantize_int8,
    rank_with_checkpoint,
    rank_with_quantized,
    train_linear_ranker,
    validate_groups,
    verify_checkpoint,
)


def _features(path: float, symbol: float, harness: float = 0.0) -> dict[str, float]:
    values = {
        "path_overlap": path,
        "symbol_overlap": symbol,
        "content_overlap": path / 2,
        "description_overlap": symbol / 2,
        "symbol_present": 1.0,
        "production_path": 1.0,
        "harness_indicator": harness,
        "path_depth_inverse": 0.5,
    }
    assert tuple(values) == FEATURE_NAMES
    return values


def _groups() -> list[dict[str, object]]:
    return [
        {
            "group_id": f"group:{number}",
            "family_id": f"family:{number % 2}",
            "audit_card_id": f"card:{number}",
            "partition": "TRAINING",
            "candidates": [
                {
                    "candidate_id": f"candidate:{number}:target",
                    "features": _features(3.0, 2.0),
                    "target": True,
                },
                {
                    "candidate_id": f"candidate:{number}:negative",
                    "features": _features(0.0, 0.0, 1.0),
                    "target": False,
                },
            ],
        }
        for number in range(4)
    ]


def _allowlist() -> set[str]:
    return {f"card:{number}" for number in range(4)}


def test_trace001_clean_training_is_deterministic_and_cpu_ranked() -> None:
    first = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
    )
    second = train_linear_ranker(
        list(reversed(_groups())),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
    )
    assert first == second
    ranked = rank_with_checkpoint(
        first,
        [
            {"candidate_id": "target", "features": _features(3.0, 2.0)},
            {
                "candidate_id": "negative",
                "features": _features(0.0, 0.0, 1.0),
            },
        ],
    )
    assert [item["candidate_id"] for item in ranked] == ["target", "negative"]


def test_trace001_training_data_identity_is_bounded_and_order_independent() -> None:
    validated = validate_groups(
        _groups(),
        audit_card_allowlist=_allowlist(),
        config=TrainingConfig(),
    )
    first = _training_data_identity(validated)
    second = _training_data_identity(list(reversed(validated)))
    assert first == second
    assert first.startswith("trace-001-training-data:")


def test_trace001_resume_matches_uninterrupted_training() -> None:
    config = TrainingConfig(epochs=6)
    partial = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
        config=config,
        stop_after_epoch=2,
    )
    resumed = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
        config=config,
        resume=partial,
    )
    clean = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
        config=config,
    )
    assert resumed == clean


def test_trace001_checkpoint_tamper_and_remote_code_are_rejected() -> None:
    checkpoint = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
    )
    tampered = deepcopy(checkpoint)
    tampered["weights"][0] += 1
    with pytest.raises(ContractError, match="IDENTITY_MISMATCH"):
        verify_checkpoint(tampered)
    remote = deepcopy(checkpoint)
    remote["remote_code"] = True
    with pytest.raises(ContractError, match="CONTRACT_REJECTED"):
        verify_checkpoint(remote)


def test_trace001_training_rejects_non_allowlisted_or_evaluation_data() -> None:
    groups = _groups()
    groups[0]["partition"] = "MODEL_SELECTION"
    with pytest.raises(PolicyError, match="GROUP_CONTRACT_REJECTED"):
        validate_groups(
            groups,
            audit_card_allowlist=_allowlist(),
            config=TrainingConfig(),
        )
    groups = _groups()
    with pytest.raises(PolicyError, match="GROUP_CONTRACT_REJECTED"):
        validate_groups(
            groups,
            audit_card_allowlist=set(),
            config=TrainingConfig(),
        )


def test_trace001_quantization_preserves_ranking_on_separated_example() -> None:
    checkpoint = train_linear_ranker(
        _groups(),
        audit_card_allowlist=_allowlist(),
        training_manifest_id="manifest:1",
    )
    candidates = [
        {"candidate_id": "target", "features": _features(3.0, 2.0)},
        {"candidate_id": "negative", "features": _features(0.0, 0.0, 1.0)},
    ]
    quantized = quantize_int8(checkpoint)
    assert [item["candidate_id"] for item in rank_with_quantized(quantized, candidates)] == [
        item["candidate_id"] for item in rank_with_checkpoint(checkpoint, candidates)
    ]
