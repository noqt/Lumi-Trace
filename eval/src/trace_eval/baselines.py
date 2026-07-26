# SPDX-License-Identifier: Apache-2.0
"""Locked deterministic and sparse V0.4 ranking comparators."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from .canonical import stable_id
from .errors import PolicyError

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]{1,63}")


def tokens(value: str | Iterable[str]) -> list[str]:
    """Tokenize without accepting labels, paths from labels, or model output."""

    text = value if isinstance(value, str) else " ".join(value)
    return [match.group(0).casefold() for match in _TOKEN.finditer(text)]


def _validate_candidates(candidates: list[dict[str, Any]]) -> None:
    identities: set[str] = set()
    for candidate in candidates:
        if (
            not isinstance(candidate, dict)
            or set(candidate)
            != {
                "candidate_id",
                "path_tokens",
                "symbol_tokens",
                "content_tokens",
            }
            or not isinstance(candidate["candidate_id"], str)
            or not candidate["candidate_id"]
            or candidate["candidate_id"] in identities
            or not all(
                isinstance(candidate[field], list)
                and all(isinstance(item, str) for item in candidate[field])
                for field in ("path_tokens", "symbol_tokens", "content_tokens")
            )
        ):
            raise PolicyError("BASELINE_CANDIDATE_CONTRACT_REJECTED")
        identities.add(candidate["candidate_id"])


def lexical_rank(
    finding_tokens: list[str], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Simple overlap baseline with a predeclared path/symbol/content tie order."""

    _validate_candidates(candidates)
    finding = Counter(token.casefold() for token in finding_tokens)
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        path = Counter(token.casefold() for token in candidate["path_tokens"])
        symbol = Counter(token.casefold() for token in candidate["symbol_tokens"])
        content = Counter(token.casefold() for token in candidate["content_tokens"])
        score = (
            3 * sum((finding & symbol).values())
            + 2 * sum((finding & path).values())
            + sum((finding & content).values())
        )
        ranked.append(
            {
                "candidate_id": candidate["candidate_id"],
                "score": float(score),
                "algorithm": "v0.4-lexical-overlap-v1",
            }
        )
    return sorted(
        ranked,
        key=lambda item: (
            -item["score"],
            item["candidate_id"],
        ),
    )


def sparse_rank(
    finding_tokens: list[str], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Sparse BM25-style comparator fitted only to the current candidate set."""

    _validate_candidates(candidates)
    query = Counter(token.casefold() for token in finding_tokens)
    documents = [
        [
            *[token.casefold() for token in candidate["path_tokens"]] * 3,
            *[token.casefold() for token in candidate["symbol_tokens"]] * 4,
            *[token.casefold() for token in candidate["content_tokens"]],
        ]
        for candidate in candidates
    ]
    document_frequency = Counter(token for document in documents for token in set(document))
    average_length = (
        sum(len(document) for document in documents) / len(documents) if documents else 0.0
    )
    ranked: list[dict[str, Any]] = []
    for candidate, document in zip(candidates, documents, strict=True):
        frequencies = Counter(document)
        score = 0.0
        for token, query_frequency in query.items():
            frequency = frequencies[token]
            if not frequency:
                continue
            inverse_frequency = math.log(
                1
                + (len(documents) - document_frequency[token] + 0.5)
                / (document_frequency[token] + 0.5)
            )
            denominator = frequency + 1.2 * (
                0.25 + 0.75 * (len(document) / average_length if average_length else 0.0)
            )
            score += query_frequency * inverse_frequency * (frequency * 2.2 / denominator)
        ranked.append(
            {
                "candidate_id": candidate["candidate_id"],
                "score": score,
                "algorithm": "v0.4-sparse-bm25-v1",
            }
        )
    return sorted(ranked, key=lambda item: (-item["score"], item["candidate_id"]))


def random_control(group_id: str, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identity-seeded control; deterministic but unrelated to case labels."""

    _validate_candidates(candidates)
    return sorted(
        (
            {
                "candidate_id": candidate["candidate_id"],
                "score": 0.0,
                "algorithm": "v0.4-identity-random-control-v1",
            }
            for candidate in candidates
        ),
        key=lambda item: stable_id(
            "random-control-order",
            {"group_id": group_id, "candidate_id": item["candidate_id"]},
        ),
    )


def score_group(
    ranked: list[dict[str, Any]],
    *,
    accepted_candidate_ids: set[str],
    family_id: str,
) -> dict[str, Any]:
    """Apply labels only after a ranking has been sealed."""

    if not accepted_candidate_ids:
        raise PolicyError("BASELINE_ACCEPTED_TARGET_EMPTY")
    positions = [
        index
        for index, item in enumerate(ranked, start=1)
        if item["candidate_id"] in accepted_candidate_ids
    ]
    first = min(positions, default=None)
    return {
        "family_id": family_id,
        "candidate_count": len(ranked),
        "target_indexable": bool(positions),
        "recall_at_5": bool(first is not None and first <= 5),
        "recall_at_10": bool(first is not None and first <= 10),
        "recall_at_20": bool(first is not None and first <= 20),
        "reciprocal_rank": 0.0 if first is None else 1.0 / first,
    }


def aggregate_grouped(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        raise PolicyError("BASELINE_RESULT_SET_EMPTY")
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        by_family[result["family_id"]].append(result)
    family_recall = {
        family: sum(item["recall_at_20"] for item in items) / len(items)
        for family, items in sorted(by_family.items())
    }
    count = len(results)
    return {
        "group_count": count,
        "family_count": len(by_family),
        "target_indexability": sum(item["target_indexable"] for item in results) / count,
        "file_recall_at_5": sum(item["recall_at_5"] for item in results) / count,
        "file_recall_at_10": sum(item["recall_at_10"] for item in results) / count,
        "file_recall_at_20": sum(item["recall_at_20"] for item in results) / count,
        "mean_reciprocal_rank": sum(item["reciprocal_rank"] for item in results) / count,
        "family_macro_recall_at_20": sum(family_recall.values()) / len(family_recall),
        "minimum_family_recall_at_20": min(family_recall.values()),
        "maximum_family_recall_at_20": max(family_recall.values()),
        "zero_recall_family_count": sum(value == 0.0 for value in family_recall.values()),
    }


def score_v04_group(
    ranked: list[dict[str, Any]],
    *,
    file_target_candidate_ids: set[str],
    role_target_candidate_ids: set[str],
    hard_negative_candidate_ids: set[str],
    family_id: str,
) -> dict[str, Any]:
    """Score locked V0.4 ranking metrics after candidate order is sealed."""

    identities = [item["candidate_id"] for item in ranked]
    if len(identities) != len(set(identities)):
        raise PolicyError("V0_4_RANKED_CANDIDATE_DUPLICATE")
    positions = {candidate_id: rank for rank, candidate_id in enumerate(identities, 1)}
    file_positions = [
        positions[candidate_id]
        for candidate_id in file_target_candidate_ids
        if candidate_id in positions
    ]
    role_positions = [
        positions[candidate_id]
        for candidate_id in role_target_candidate_ids
        if candidate_id in positions
    ]
    hard_positions = [
        positions[candidate_id]
        for candidate_id in hard_negative_candidate_ids
        if candidate_id in positions
    ]
    first_file = min(file_positions, default=None)
    first_role = min(role_positions, default=None)
    top = identities[0] if identities else None
    return {
        "family_id": family_id,
        "candidate_count": len(ranked),
        "valid_attempt": True,
        "target_indexable": bool(file_target_candidate_ids),
        "file_recall_at_5": bool(first_file is not None and first_file <= 5),
        "file_recall_at_10": bool(first_file is not None and first_file <= 10),
        "file_recall_at_20": bool(first_file is not None and first_file <= 20),
        "location_role_recall_at_20": bool(first_role is not None and first_role <= 20),
        "reciprocal_rank": (0.0 if first_file is None else 1.0 / first_file),
        "no_relevant_candidate": not file_target_candidate_ids,
        "has_hard_negative": bool(hard_negative_candidate_ids),
        "hard_negative_outrank": bool(
            hard_positions and (first_file is None or min(hard_positions) < first_file)
        ),
        "wrong_location_role_top_one": bool(
            top in file_target_candidate_ids and top not in role_target_candidate_ids
        ),
        "disposition_emitted": False,
        "false_supported_disposition": False,
        "false_vulnerability_safe_control": False,
        "unsafe_non_abstention": False,
    }


def aggregate_v04(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate V0.4 micro and family-aware candidate-ranking metrics."""

    if not results:
        raise PolicyError("V0_4_RESULT_SET_EMPTY")
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        by_family[result["family_id"]].append(result)
    family_recall = {
        family: sum(item["file_recall_at_20"] for item in items) / len(items)
        for family, items in sorted(by_family.items())
    }
    count = len(results)
    hard_negative_results = [item for item in results if item["has_hard_negative"]]

    def rate(
        key: str,
        denominator: list[dict[str, Any]] = results,
    ) -> float:
        return (
            sum(bool(item[key]) for item in denominator) / len(denominator) if denominator else 0.0
        )

    return {
        "group_count": count,
        "family_count": len(by_family),
        "valid_attempt_completion": rate("valid_attempt"),
        "target_indexability": rate("target_indexable"),
        "file_recall_at_5": rate("file_recall_at_5"),
        "file_recall_at_10": rate("file_recall_at_10"),
        "file_recall_at_20": rate("file_recall_at_20"),
        "location_role_correct_recall_at_20": rate("location_role_recall_at_20"),
        "mean_reciprocal_rank": sum(float(item["reciprocal_rank"]) for item in results) / count,
        "no_relevant_candidate": rate("no_relevant_candidate"),
        "hard_negative_outrank": rate("hard_negative_outrank", hard_negative_results),
        "hard_negative_denominator": len(hard_negative_results),
        "wrong_location_role_top_one": rate("wrong_location_role_top_one"),
        "repository_family_macro_recall_at_20": sum(family_recall.values()) / len(family_recall),
        "minimum_family_recall_at_20": min(family_recall.values()),
        "maximum_family_recall_at_20": max(family_recall.values()),
        "zero_recall_family_count": sum(value == 0.0 for value in family_recall.values()),
        "false_supported_disposition": sum(item["false_supported_disposition"] for item in results),
        "false_vulnerability_safe_control": sum(
            item["false_vulnerability_safe_control"] for item in results
        ),
        "unsafe_non_abstention": sum(item["unsafe_non_abstention"] for item in results),
        "positive_claim_scope": "CANDIDATE_RANKING_ONLY",
    }
