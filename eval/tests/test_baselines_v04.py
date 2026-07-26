# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from trace_eval.baselines import (
    aggregate_grouped,
    aggregate_v04,
    lexical_rank,
    random_control,
    score_group,
    score_v04_group,
    sparse_rank,
    tokens,
)


def _candidates() -> list[dict[str, object]]:
    return [
        {
            "candidate_id": "candidate:observation",
            "path_tokens": ["tests", "test", "parser"],
            "symbol_tokens": ["test", "invalid"],
            "content_tokens": ["assert", "raises"],
        },
        {
            "candidate_id": "candidate:implementation",
            "path_tokens": ["src", "parser"],
            "symbol_tokens": ["parse", "record"],
            "content_tokens": ["validate", "input", "record"],
        },
    ]


def test_v04_lexical_and_sparse_baselines_rank_without_label_fields() -> None:
    finding = tokens("invalid record input parser validation")
    assert lexical_rank(finding, _candidates())[0]["candidate_id"] == ("candidate:implementation")
    assert sparse_rank(finding, _candidates())[0]["candidate_id"] == ("candidate:implementation")


def test_v04_random_control_is_replay_deterministic() -> None:
    first = random_control("group:test", _candidates())
    second = random_control("group:test", list(reversed(_candidates())))
    assert first == second


def test_v04_grouped_metrics_keep_minimum_family_visible() -> None:
    ranked = lexical_rank(tokens("parser record"), _candidates())
    good = score_group(
        ranked,
        accepted_candidate_ids={"candidate:implementation"},
        family_id="family:good",
    )
    missed = score_group(
        ranked[:1],
        accepted_candidate_ids={"candidate:missing"},
        family_id="family:missed",
    )
    aggregate = aggregate_grouped([good, missed])
    assert aggregate["file_recall_at_20"] == 0.5
    assert aggregate["family_macro_recall_at_20"] == 0.5
    assert aggregate["minimum_family_recall_at_20"] == 0.0
    assert aggregate["zero_recall_family_count"] == 1


def test_v04_locked_metrics_cover_roles_hard_negatives_and_families() -> None:
    results = [
        score_v04_group(
            [
                {"candidate_id": "role"},
                {"candidate_id": "file"},
                {"candidate_id": "hard"},
            ],
            file_target_candidate_ids={"role", "file"},
            role_target_candidate_ids={"role"},
            hard_negative_candidate_ids={"hard"},
            family_id="family-a",
        ),
        score_v04_group(
            [{"candidate_id": "hard"}, {"candidate_id": "other"}],
            file_target_candidate_ids=set(),
            role_target_candidate_ids=set(),
            hard_negative_candidate_ids={"hard"},
            family_id="family-b",
        ),
    ]
    aggregate = aggregate_v04(results)
    assert aggregate["file_recall_at_5"] == 0.5
    assert aggregate["location_role_correct_recall_at_20"] == 0.5
    assert aggregate["hard_negative_outrank"] == 0.5
    assert aggregate["no_relevant_candidate"] == 0.5
    assert aggregate["zero_recall_family_count"] == 1
    assert aggregate["positive_claim_scope"] == "CANDIDATE_RANKING_ONLY"
