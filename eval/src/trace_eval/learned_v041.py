# SPDX-License-Identifier: Apache-2.0
"""Isolated V0.4.1 trainer for the product's bounded integer ranker."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from lumi_trace.canonical import stable_id as product_stable_id
from lumi_trace.learned_ranker import (
    ALGORITHM,
    BASE_RANKER,
    DIMENSIONS,
    FEATURE_CONTRACT,
    MODEL_SCHEMA,
)

from .canonical import stable_id
from .errors import PolicyError


@dataclass(frozen=True)
class LearnedTrainingConfig:
    epochs: int = 16
    margin: int = 8
    maximum_candidates_per_group: int = 128
    maximum_pairs_per_group: int = 256
    seed: int = 41

    def as_dict(self) -> dict[str, int]:
        if (
            not 1 <= self.epochs <= 128
            or not 1 <= self.margin <= 10_000
            or not 2 <= self.maximum_candidates_per_group <= 2_000
            or not 1 <= self.maximum_pairs_per_group <= 10_000
            or not 0 <= self.seed <= 2**31 - 1
        ):
            raise PolicyError("V0_4_1_LEARNED_CONFIG_REJECTED")
        return {
            "epochs": self.epochs,
            "margin": self.margin,
            "maximum_candidates_per_group": self.maximum_candidates_per_group,
            "maximum_pairs_per_group": self.maximum_pairs_per_group,
            "seed": self.seed,
        }


def _score(weights: list[int], vector: tuple[tuple[int, int], ...]) -> int:
    return sum(weights[index] * value for index, value in vector)


def _validate_groups(
    groups: list[dict[str, Any]],
    *,
    audit_card_allowlist: set[str],
    config: LearnedTrainingConfig,
) -> list[dict[str, Any]]:
    config.as_dict()
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for group in groups:
        if (
            not isinstance(group, dict)
            or set(group) != {"group_id", "family_id", "audit_card_id", "partition", "candidates"}
            or group["partition"] != "TRAINING"
            or group["audit_card_id"] not in audit_card_allowlist
            or group["group_id"] in seen
            or not isinstance(group["candidates"], list)
            or not 2 <= len(group["candidates"]) <= config.maximum_candidates_per_group
        ):
            raise PolicyError("V0_4_1_LEARNED_GROUP_REJECTED")
        seen.add(group["group_id"])
        candidates = []
        positives = 0
        for candidate in group["candidates"]:
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"candidate_id", "features", "target"}
                or not isinstance(candidate["target"], bool)
                or not isinstance(candidate["features"], list)
            ):
                raise PolicyError("V0_4_1_LEARNED_CANDIDATE_REJECTED")
            vector = tuple((int(index), int(value)) for index, value in candidate["features"])
            if (
                not vector
                or list(vector) != sorted(vector)
                or any(
                    not 0 <= index < DIMENSIONS or not -64 <= value <= 64 or value == 0
                    for index, value in vector
                )
            ):
                raise PolicyError("V0_4_1_LEARNED_FEATURE_REJECTED")
            positives += candidate["target"]
            candidates.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "features": vector,
                    "target": candidate["target"],
                }
            )
        if positives < 1 or positives == len(candidates):
            raise PolicyError("V0_4_1_LEARNED_LABEL_BALANCE_REJECTED")
        validated.append({**group, "candidates": candidates})
    if not validated:
        raise PolicyError("V0_4_1_LEARNED_EMPTY_TRAINING_SET")
    return validated


def train_integer_pairwise_ranker(
    groups: list[dict[str, Any]],
    *,
    audit_card_allowlist: set[str],
    training_manifest_id: str,
    config: LearnedTrainingConfig | None = None,
) -> dict[str, Any]:
    """Train with one rotating group per family per epoch."""

    config = config or LearnedTrainingConfig()
    validated = _validate_groups(
        groups,
        audit_card_allowlist=audit_card_allowlist,
        config=config,
    )
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in validated:
        by_family[group["family_id"]].append(group)
    for family, family_groups in by_family.items():
        by_family[family] = sorted(
            family_groups,
            key=lambda group: stable_id(
                "v0.4.1-family-group-order",
                {
                    "seed": config.seed,
                    "family_id": family,
                    "group_id": group["group_id"],
                },
            ),
        )
    training_data_id = stable_id(
        "v0.4.1-learned-training-data",
        [
            stable_id(
                "v0.4.1-learned-training-group",
                {
                    **group,
                    "candidates": [
                        {
                            **candidate,
                            "features": [list(item) for item in candidate["features"]],
                        }
                        for candidate in group["candidates"]
                    ],
                },
            )
            for group in sorted(validated, key=lambda item: item["group_id"])
        ],
    )
    weights = [0] * DIMENSIONS
    updates = 0
    for epoch in range(config.epochs):
        epoch_groups = [
            groups_for_family[epoch % len(groups_for_family)]
            for _, groups_for_family in sorted(by_family.items())
        ]
        epoch_groups.sort(
            key=lambda group: stable_id(
                "v0.4.1-training-epoch-order",
                {"seed": config.seed, "epoch": epoch, "group_id": group["group_id"]},
            )
        )
        for group in epoch_groups:
            positives = [item for item in group["candidates"] if item["target"]]
            negatives = [item for item in group["candidates"] if not item["target"]]
            pairs = [(positive, negative) for positive in positives for negative in negatives][
                : config.maximum_pairs_per_group
            ]
            for positive, negative in pairs:
                if (
                    _score(weights, positive["features"])
                    - _score(
                        weights,
                        negative["features"],
                    )
                    >= config.margin
                ):
                    continue
                delta: dict[int, int] = defaultdict(int)
                for index, value in positive["features"]:
                    delta[index] += value
                for index, value in negative["features"]:
                    delta[index] -= value
                for index, value in delta.items():
                    weights[index] = max(
                        -1_000_000,
                        min(1_000_000, weights[index] + value),
                    )
                updates += 1
    sparse_weights = [
        {"index": index, "weight": weight} for index, weight in enumerate(weights) if weight
    ]
    artifact = {
        "schema_version": MODEL_SCHEMA,
        "algorithm": ALGORITHM,
        "feature_contract": FEATURE_CONTRACT,
        "dimensions": DIMENSIONS,
        "base_ranker": BASE_RANKER,
        "weights": sparse_weights,
        "active_parameters": len(sparse_weights),
        "training_manifest_id": training_manifest_id,
        "training_data_id": training_data_id,
        "training_config": config.as_dict(),
        "completed_epochs": config.epochs,
        "pair_updates": updates,
        "family_balanced": True,
        "foundation_model": None,
        "tokenizer": None,
        "remote_code": False,
        "hosted_service": False,
        "cpu_inference": True,
    }
    artifact["artifact_id"] = product_stable_id("lumi-trace-localization-model", artifact)
    return artifact
