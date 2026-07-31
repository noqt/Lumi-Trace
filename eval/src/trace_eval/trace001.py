# SPDX-License-Identifier: Apache-2.0
"""Bounded from-scratch TRACE-001 linear candidate reranker.

This module contains training machinery but performs no training at import
time. It accepts only precomputed numeric candidate features admitted through
an audit-card allowlist. It has no model provider, tokenizer, remote-code, or
network path.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .canonical import stable_id
from .errors import ContractError, PolicyError

FEATURE_NAMES = (
    "path_overlap",
    "symbol_overlap",
    "content_overlap",
    "description_overlap",
    "symbol_present",
    "production_path",
    "harness_indicator",
    "path_depth_inverse",
)
MODEL_SCHEMA = "trace-001-linear-ranker-v1"
QUANTIZED_SCHEMA = "trace-001-linear-ranker-int8-v1"


@dataclass(frozen=True)
class TrainingConfig:
    epochs: int = 12
    learning_rate: float = 0.05
    l2: float = 0.0001
    margin: float = 1.0
    seed: int = 104
    maximum_groups: int = 100_000
    maximum_candidates_per_group: int = 2_000
    maximum_pairs_per_group: int = 4_000

    def as_dict(self) -> dict[str, int | float]:
        value = {
            "epochs": self.epochs,
            "learning_rate": self.learning_rate,
            "l2": self.l2,
            "margin": self.margin,
            "seed": self.seed,
            "maximum_groups": self.maximum_groups,
            "maximum_candidates_per_group": self.maximum_candidates_per_group,
            "maximum_pairs_per_group": self.maximum_pairs_per_group,
        }
        _validate_config(value)
        return value


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _validate_config(value: dict[str, Any]) -> None:
    if (
        set(value)
        != {
            "epochs",
            "learning_rate",
            "l2",
            "margin",
            "seed",
            "maximum_groups",
            "maximum_candidates_per_group",
            "maximum_pairs_per_group",
        }
        or not isinstance(value["epochs"], int)
        or not 1 <= value["epochs"] <= 1_000
        or not _finite_number(value["learning_rate"])
        or not 0 < value["learning_rate"] <= 1
        or not _finite_number(value["l2"])
        or not 0 <= value["l2"] <= 1
        or not _finite_number(value["margin"])
        or not 0 < value["margin"] <= 100
        or not isinstance(value["seed"], int)
        or not 0 <= value["seed"] <= 2**31 - 1
        or not isinstance(value["maximum_groups"], int)
        or not 1 <= value["maximum_groups"] <= 1_000_000
        or not isinstance(value["maximum_candidates_per_group"], int)
        or not 2 <= value["maximum_candidates_per_group"] <= 100_000
        or not isinstance(value["maximum_pairs_per_group"], int)
        or not 1 <= value["maximum_pairs_per_group"] <= 1_000_000
    ):
        raise PolicyError("TRACE_001_TRAINING_CONFIG_REJECTED")


def _vector(features: dict[str, Any]) -> tuple[float, ...]:
    if set(features) != set(FEATURE_NAMES):
        raise PolicyError("TRACE_001_FEATURE_CONTRACT_REJECTED")
    values = tuple(float(features[name]) for name in FEATURE_NAMES)
    if not all(math.isfinite(value) and abs(value) <= 1_000_000 for value in values):
        raise PolicyError("TRACE_001_FEATURE_VALUE_REJECTED")
    return values


def validate_groups(
    groups: list[dict[str, Any]],
    *,
    audit_card_allowlist: set[str],
    config: TrainingConfig,
) -> list[dict[str, Any]]:
    """Validate training groups and enforce the audit-card identity allowlist."""

    config_value = config.as_dict()
    if not groups or len(groups) > config_value["maximum_groups"]:
        raise PolicyError("TRACE_001_GROUP_COUNT_REJECTED")
    group_ids: set[str] = set()
    validated: list[dict[str, Any]] = []
    for group in groups:
        if (
            not isinstance(group, dict)
            or set(group)
            != {
                "group_id",
                "family_id",
                "audit_card_id",
                "partition",
                "candidates",
            }
            or not isinstance(group["group_id"], str)
            or not isinstance(group["family_id"], str)
            or not isinstance(group["audit_card_id"], str)
            or group["audit_card_id"] not in audit_card_allowlist
            or group["partition"] != "TRAINING"
            or group["group_id"] in group_ids
            or not isinstance(group["candidates"], list)
            or not 2 <= len(group["candidates"]) <= config_value["maximum_candidates_per_group"]
        ):
            raise PolicyError("TRACE_001_GROUP_CONTRACT_REJECTED")
        group_ids.add(group["group_id"])
        candidate_ids: set[str] = set()
        candidates: list[dict[str, Any]] = []
        target_count = 0
        for candidate in group["candidates"]:
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"candidate_id", "features", "target"}
                or not isinstance(candidate["candidate_id"], str)
                or not candidate["candidate_id"]
                or candidate["candidate_id"] in candidate_ids
                or not isinstance(candidate["target"], bool)
                or not isinstance(candidate["features"], dict)
            ):
                raise PolicyError("TRACE_001_CANDIDATE_CONTRACT_REJECTED")
            candidate_ids.add(candidate["candidate_id"])
            target_count += candidate["target"]
            candidates.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "features": _vector(candidate["features"]),
                    "target": candidate["target"],
                }
            )
        if target_count < 1 or target_count == len(candidates):
            raise PolicyError("TRACE_001_PAIRWISE_LABEL_BALANCE_REJECTED")
        validated.append(
            {
                "group_id": group["group_id"],
                "family_id": group["family_id"],
                "audit_card_id": group["audit_card_id"],
                "candidates": candidates,
            }
        )
    return validated


def _ordered_groups(groups: list[dict[str, Any]], *, epoch: int, seed: int) -> list[dict[str, Any]]:
    return sorted(
        groups,
        key=lambda group: stable_id(
            "trace-001-group-order",
            {
                "epoch": epoch,
                "seed": seed,
                "family_id": group["family_id"],
                "group_id": group["group_id"],
            },
        ),
    )


def _training_data_identity(groups: list[dict[str, Any]]) -> str:
    """Bind every validated candidate through bounded per-group identities."""

    group_identities = []
    for group in sorted(groups, key=lambda item: item["group_id"]):
        group_identities.append(
            stable_id(
                "trace-001-training-group-data",
                {
                    "group_id": group["group_id"],
                    "family_id": group["family_id"],
                    "audit_card_id": group["audit_card_id"],
                    "candidates": [
                        {
                            "candidate_id": candidate["candidate_id"],
                            "features": list(candidate["features"]),
                            "target": candidate["target"],
                        }
                        for candidate in group["candidates"]
                    ],
                },
            )
        )
    return stable_id("trace-001-training-data", group_identities)


def _score(weights: tuple[float, ...] | list[float], vector: tuple[float, ...]) -> float:
    return sum(weight * value for weight, value in zip(weights, vector, strict=True))


def _checkpoint(
    *,
    weights: list[float],
    completed_epochs: int,
    config: TrainingConfig,
    training_manifest_id: str,
    training_data_id: str,
    pair_updates: int,
) -> dict[str, Any]:
    value = {
        "schema_version": MODEL_SCHEMA,
        "algorithm": "PAIRWISE_HINGE_SGD_FROM_SCRATCH",
        "feature_names": list(FEATURE_NAMES),
        "weights": weights,
        "active_parameters": len(weights),
        "completed_epochs": completed_epochs,
        "training_config": config.as_dict(),
        "training_manifest_id": training_manifest_id,
        "training_data_id": training_data_id,
        "pair_updates": pair_updates,
        "foundation_model": None,
        "tokenizer": None,
        "remote_code": False,
        "hosted_service": False,
        "cpu_inference": True,
    }
    value["checkpoint_id"] = stable_id("trace-001-linear-checkpoint", value)
    return value


def verify_checkpoint(
    checkpoint: dict[str, Any],
    *,
    training_manifest_id: str | None = None,
    training_data_id: str | None = None,
) -> dict[str, Any]:
    """Verify a JSON-only checkpoint and its self-identity."""

    required = {
        "schema_version",
        "algorithm",
        "feature_names",
        "weights",
        "active_parameters",
        "completed_epochs",
        "training_config",
        "training_manifest_id",
        "training_data_id",
        "pair_updates",
        "foundation_model",
        "tokenizer",
        "remote_code",
        "hosted_service",
        "cpu_inference",
        "checkpoint_id",
    }
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != required
        or checkpoint["schema_version"] != MODEL_SCHEMA
        or checkpoint["algorithm"] != "PAIRWISE_HINGE_SGD_FROM_SCRATCH"
        or checkpoint["feature_names"] != list(FEATURE_NAMES)
        or not isinstance(checkpoint["weights"], list)
        or len(checkpoint["weights"]) != len(FEATURE_NAMES)
        or not all(_finite_number(value) for value in checkpoint["weights"])
        or checkpoint["active_parameters"] != len(FEATURE_NAMES)
        or not isinstance(checkpoint["completed_epochs"], int)
        or checkpoint["completed_epochs"] < 0
        or not isinstance(checkpoint["pair_updates"], int)
        or checkpoint["pair_updates"] < 0
        or checkpoint["foundation_model"] is not None
        or checkpoint["tokenizer"] is not None
        or checkpoint["remote_code"] is not False
        or checkpoint["hosted_service"] is not False
        or checkpoint["cpu_inference"] is not True
    ):
        raise ContractError("TRACE_001_CHECKPOINT_CONTRACT_REJECTED")
    _validate_config(checkpoint["training_config"])
    expected = stable_id(
        "trace-001-linear-checkpoint",
        {key: value for key, value in checkpoint.items() if key != "checkpoint_id"},
    )
    if checkpoint["checkpoint_id"] != expected:
        raise ContractError("TRACE_001_CHECKPOINT_IDENTITY_MISMATCH")
    if (
        training_manifest_id is not None
        and checkpoint["training_manifest_id"] != training_manifest_id
    ):
        raise ContractError("TRACE_001_TRAINING_MANIFEST_MISMATCH")
    if training_data_id is not None and checkpoint["training_data_id"] != training_data_id:
        raise ContractError("TRACE_001_TRAINING_DATA_MISMATCH")
    return checkpoint


def train_linear_ranker(
    groups: list[dict[str, Any]],
    *,
    audit_card_allowlist: set[str],
    training_manifest_id: str,
    config: TrainingConfig | None = None,
    resume: dict[str, Any] | None = None,
    stop_after_epoch: int | None = None,
) -> dict[str, Any]:
    """Train locally only when called by an already-authorised workflow."""

    config = config or TrainingConfig()
    validated = validate_groups(
        groups,
        audit_card_allowlist=audit_card_allowlist,
        config=config,
    )
    training_data_id = _training_data_identity(validated)
    weights = [0.0] * len(FEATURE_NAMES)
    start_epoch = 0
    pair_updates = 0
    if resume is not None:
        verify_checkpoint(
            resume,
            training_manifest_id=training_manifest_id,
            training_data_id=training_data_id,
        )
        if resume["training_config"] != config.as_dict():
            raise ContractError("TRACE_001_RESUME_CONFIG_MISMATCH")
        weights = [float(value) for value in resume["weights"]]
        start_epoch = resume["completed_epochs"]
        pair_updates = resume["pair_updates"]
    end_epoch = config.epochs if stop_after_epoch is None else stop_after_epoch
    if not start_epoch <= end_epoch <= config.epochs:
        raise PolicyError("TRACE_001_STOP_EPOCH_REJECTED")
    for epoch in range(start_epoch, end_epoch):
        for group in _ordered_groups(validated, epoch=epoch, seed=config.seed):
            positives = [item for item in group["candidates"] if item["target"]]
            negatives = [item for item in group["candidates"] if not item["target"]]
            pairs = [(positive, negative) for positive in positives for negative in negatives][
                : config.maximum_pairs_per_group
            ]
            for positive, negative in pairs:
                difference = tuple(
                    positive_value - negative_value
                    for positive_value, negative_value in zip(
                        positive["features"],
                        negative["features"],
                        strict=True,
                    )
                )
                pair_margin = _score(weights, difference)
                shrink = 1.0 - config.learning_rate * config.l2
                weights = [weight * shrink for weight in weights]
                if pair_margin < config.margin:
                    weights = [
                        weight + config.learning_rate * delta
                        for weight, delta in zip(weights, difference, strict=True)
                    ]
                pair_updates += 1
    return _checkpoint(
        weights=weights,
        completed_epochs=end_epoch,
        config=config,
        training_manifest_id=training_manifest_id,
        training_data_id=training_data_id,
        pair_updates=pair_updates,
    )


def rank_with_checkpoint(
    checkpoint: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run structured CPU inference from a verified local JSON checkpoint."""

    verify_checkpoint(checkpoint)
    seen: set[str] = set()
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        if (
            not isinstance(candidate, dict)
            or set(candidate) != {"candidate_id", "features"}
            or not isinstance(candidate["candidate_id"], str)
            or not candidate["candidate_id"]
            or candidate["candidate_id"] in seen
            or not isinstance(candidate["features"], dict)
        ):
            raise PolicyError("TRACE_001_INFERENCE_CANDIDATE_REJECTED")
        seen.add(candidate["candidate_id"])
        score = _score(
            checkpoint["weights"],
            _vector(candidate["features"]),
        )
        ranked.append(
            {
                "candidate_id": candidate["candidate_id"],
                "score": score,
                "model_id": checkpoint["checkpoint_id"],
            }
        )
    return sorted(
        ranked,
        key=lambda item: (-item["score"], item["candidate_id"]),
    )


def quantize_int8(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic symmetric int8 projection for comparison only."""

    verify_checkpoint(checkpoint)
    maximum = max((abs(float(value)) for value in checkpoint["weights"]), default=0.0)
    scale = maximum / 127.0 if maximum else 1.0
    quantized = [
        max(-127, min(127, round(float(value) / scale))) for value in checkpoint["weights"]
    ]
    value = {
        "schema_version": QUANTIZED_SCHEMA,
        "source_checkpoint_id": checkpoint["checkpoint_id"],
        "feature_names": list(FEATURE_NAMES),
        "weights_int8": quantized,
        "scale": scale,
        "active_parameters": len(quantized),
        "cpu_inference": True,
        "remote_code": False,
    }
    value["artifact_id"] = stable_id("trace-001-linear-int8", value)
    return value


def rank_with_quantized(
    artifact: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    expected = stable_id(
        "trace-001-linear-int8",
        {key: value for key, value in artifact.items() if key != "artifact_id"},
    )
    if (
        artifact.get("schema_version") != QUANTIZED_SCHEMA
        or artifact.get("feature_names") != list(FEATURE_NAMES)
        or artifact.get("artifact_id") != expected
        or artifact.get("remote_code") is not False
        or artifact.get("cpu_inference") is not True
        or not isinstance(artifact.get("weights_int8"), list)
        or len(artifact["weights_int8"]) != len(FEATURE_NAMES)
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and -127 <= value <= 127
            for value in artifact["weights_int8"]
        )
        or not _finite_number(artifact.get("scale"))
        or artifact["scale"] <= 0
    ):
        raise ContractError("TRACE_001_QUANTIZED_ARTIFACT_REJECTED")
    projected = {
        **artifact,
        "schema_version": MODEL_SCHEMA,
        "algorithm": "PAIRWISE_HINGE_SGD_FROM_SCRATCH",
        "weights": [value * float(artifact["scale"]) for value in artifact["weights_int8"]],
        "completed_epochs": 0,
        "training_config": TrainingConfig().as_dict(),
        "training_manifest_id": "QUANTIZED_PROJECTION",
        "training_data_id": "QUANTIZED_PROJECTION",
        "pair_updates": 0,
        "foundation_model": None,
        "tokenizer": None,
        "hosted_service": False,
        "checkpoint_id": artifact["artifact_id"],
    }
    allowed = {
        "schema_version",
        "algorithm",
        "feature_names",
        "weights",
        "active_parameters",
        "completed_epochs",
        "training_config",
        "training_manifest_id",
        "training_data_id",
        "pair_updates",
        "foundation_model",
        "tokenizer",
        "remote_code",
        "hosted_service",
        "cpu_inference",
        "checkpoint_id",
    }
    projected = {key: value for key, value in projected.items() if key in allowed}
    ranked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        if (
            not isinstance(candidate, dict)
            or set(candidate) != {"candidate_id", "features"}
            or candidate["candidate_id"] in seen
        ):
            raise PolicyError("TRACE_001_INFERENCE_CANDIDATE_REJECTED")
        seen.add(candidate["candidate_id"])
        ranked.append(
            {
                "candidate_id": candidate["candidate_id"],
                "score": _score(projected["weights"], _vector(candidate["features"])),
                "model_id": artifact["artifact_id"],
            }
        )
    return sorted(ranked, key=lambda item: (-item["score"], item["candidate_id"]))
