# SPDX-License-Identifier: Apache-2.0
"""V0.4.1 builder/scorer/custodian integrity contracts."""

from __future__ import annotations

import math
from pathlib import Path
from statistics import NormalDist
from typing import Any

from lumi_trace.canonical import stable_id as runtime_stable_id
from lumi_trace.localization import verify_raw_localization

from .baselines import score_v04_group
from .canonical import stable_id
from .errors import ContractError, PolicyError

SCORING_LABEL_SCHEMA = "lumi-trace-v0.4.1-private-scoring-label-v1"
QUALIFICATION_BUDGET_SCHEMA = "lumi-trace-v0.4.1-qualification-budget-v1"


def make_scoring_labels(
    *,
    group_id: str,
    family_id: str,
    targets: list[dict[str, Any]],
    hard_negative_paths: list[str],
    matched_safe_control_id: str,
    semantic_review_resolution_id: str,
) -> dict[str, Any]:
    """Create the scorer-only label object after semantic review."""

    if (
        not group_id
        or not family_id
        or not targets
        or any(
            not isinstance(item, dict)
            or set(item) - {"path", "symbol", "region", "role"}
            or not isinstance(item.get("path"), str)
            or not item["path"]
            for item in targets
        )
    ):
        raise PolicyError("V0_4_1_SCORING_LABEL_REJECTED")
    value = {
        "schema_version": SCORING_LABEL_SCHEMA,
        "group_id": group_id,
        "family_id": family_id,
        "targets": targets,
        "hard_negative_paths": sorted(set(hard_negative_paths)),
        "matched_safe_control_id": matched_safe_control_id,
        "semantic_review_resolution_id": semantic_review_resolution_id,
    }
    value["label_id"] = stable_id("v0.4.1-scoring-label", value)
    return value


def verify_scoring_labels(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "group_id",
        "family_id",
        "targets",
        "hard_negative_paths",
        "matched_safe_control_id",
        "semantic_review_resolution_id",
        "label_id",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != SCORING_LABEL_SCHEMA
        or not isinstance(value.get("targets"), list)
        or not value["targets"]
        or not isinstance(value.get("hard_negative_paths"), list)
    ):
        raise ContractError("V0_4_1_SCORING_LABEL_CONTRACT_REJECTED")
    expected = stable_id(
        "v0.4.1-scoring-label",
        {key: item for key, item in value.items() if key != "label_id"},
    )
    if value.get("label_id") != expected:
        raise ContractError("V0_4_1_SCORING_LABEL_IDENTITY_MISMATCH")
    return value


def score_sealed_localization(
    raw_output: dict[str, Any],
    labels: dict[str, Any],
    *,
    metric_specification_id: str,
) -> dict[str, Any]:
    """Reveal labels only after the builder output seal verifies."""

    verified_raw = verify_raw_localization(raw_output)
    verified_labels = verify_scoring_labels(labels)
    candidates = verified_raw["candidates"]
    inventory = verified_raw["candidate_inventory"]
    target_paths = {item["path"] for item in verified_labels["targets"]}
    target_symbols = {
        (item["path"], item["symbol"]) for item in verified_labels["targets"] if item.get("symbol")
    }
    hard_paths = set(verified_labels["hard_negative_paths"])
    file_target_ids = {item["candidate_id"] for item in inventory if item["path"] in target_paths}
    role_target_ids = {
        item["candidate_id"]
        for item in inventory
        if (item["path"], item.get("symbol")) in target_symbols
    }
    hard_negative_ids = {item["candidate_id"] for item in inventory if item["path"] in hard_paths}
    metrics = score_v04_group(
        [{"candidate_id": item["candidate_id"]} for item in candidates],
        file_target_candidate_ids=file_target_ids,
        role_target_candidate_ids=role_target_ids,
        hard_negative_candidate_ids=hard_negative_ids,
        family_id=verified_labels["family_id"],
    )
    metrics["file_target_indexable"] = bool(file_target_ids)
    metrics["role_target_indexable"] = bool(role_target_ids)
    value = {
        "schema_version": "lumi-trace-v0.4.1-private-scored-ranking-v1",
        "group_id": verified_labels["group_id"],
        "raw_output_seal": verified_raw["raw_output_seal"],
        "ranking_id": verified_raw["ranking_id"],
        "scoring_label_id": verified_labels["label_id"],
        "metric_specification_id": metric_specification_id,
        "seal_verified_before_scoring": True,
        "builder_output_mutated": False,
        "metrics": metrics,
    }
    value["score_record_id"] = stable_id("v0.4.1-scored-ranking", value)
    return value


def one_sided_wilson_bound(
    successes: int,
    total: int,
    *,
    confidence: float = 0.90,
    side: str = "lower",
) -> float | None:
    """Return a one-sided Wilson bound with an explicit denominator."""

    if (
        isinstance(successes, bool)
        or isinstance(total, bool)
        or not isinstance(successes, int)
        or not isinstance(total, int)
        or total < 0
        or successes < 0
        or successes > total
        or not 0.5 < confidence < 1.0
        or side not in {"lower", "upper"}
    ):
        raise PolicyError("V0_4_1_CONFIDENCE_BOUND_REJECTED")
    if total == 0:
        return None
    z = NormalDist().inv_cdf(confidence)
    rate = successes / total
    denominator = 1 + z * z / total
    centre = (rate + z * z / (2 * total)) / denominator
    half_width = (
        z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    )
    if side == "lower":
        return max(0.0, centre - half_width)
    return min(1.0, centre + half_width)


def create_qualification_budget(*, partition_seal_id: str, custodian_root: Path) -> dict[str, Any]:
    resolved = custodian_root.resolve(strict=True)
    value = {
        "schema_version": QUALIFICATION_BUDGET_SCHEMA,
        "partition_seal_id": partition_seal_id,
        "custodian_root_identity": runtime_stable_id("custodian-root", str(resolved)),
        "capacity": 1,
        "consumed": 0,
        "remaining": 1,
        "state": "SEALED_UNOPENED",
    }
    value["budget_id"] = stable_id("v0.4.1-qualification-budget", value)
    return value


def consume_qualification_budget(
    budget: dict[str, Any],
    *,
    readiness_case_id: str,
    authorization: str,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "partition_seal_id",
        "custodian_root_identity",
        "capacity",
        "consumed",
        "remaining",
        "state",
        "budget_id",
    }
    expected = stable_id(
        "v0.4.1-qualification-budget",
        {key: value for key, value in budget.items() if key != "budget_id"},
    )
    if (
        set(budget) != required
        or budget.get("schema_version") != QUALIFICATION_BUDGET_SCHEMA
        or budget.get("budget_id") != expected
        or budget.get("remaining") != 1
        or budget.get("consumed") != 0
        or budget.get("state") != "SEALED_UNOPENED"
        or authorization != "QUALIFICATION_EXECUTION_AUTHORISED"
    ):
        raise PolicyError("V0_4_1_QUALIFICATION_CONSUMPTION_REJECTED")
    value = {
        **budget,
        "predecessor_budget_id": budget["budget_id"],
        "consumed": 1,
        "remaining": 0,
        "state": "CONSUMED",
        "readiness_case_id": readiness_case_id,
    }
    value.pop("budget_id")
    value["budget_id"] = stable_id("v0.4.1-qualification-budget", value)
    return value
