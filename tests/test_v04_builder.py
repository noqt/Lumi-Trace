# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

import pytest

from scripts.build_v0_4_assurance import (
    PolicyError,
    _augment_assignments,
    _family_cap_exclusions,
    _load_assignment_source,
    _parse_ls_remote_head,
    _reassign_untouched_lineages,
    _reconsidered_candidate,
)


def test_v04_head_parser_ignores_symref_metadata_and_pins_the_object() -> None:
    revision = "9" * 40
    output = f"ref: refs/heads/main\tHEAD\n{revision}\tHEAD\n".encode()
    assert _parse_ls_remote_head(output) == revision


def test_v04_head_parser_rejects_missing_or_ambiguous_objects() -> None:
    with pytest.raises(PolicyError, match="HEAD_IDENTITY_INVALID"):
        _parse_ls_remote_head(b"ref: refs/heads/main\tHEAD\n")
    with pytest.raises(PolicyError, match="HEAD_IDENTITY_INVALID"):
        _parse_ls_remote_head((f"{'8' * 40}\tHEAD\n{'9' * 40}\tHEAD\n").encode())


def _assignment(
    repository: str,
    partition: str,
    groups: int = 25,
) -> dict[str, object]:
    owner = repository.split("/", 1)[0]
    return {
        "repository": repository,
        "repository_token": repository.replace("/", "-"),
        "source_record_id": f"source:{repository}",
        "repository_family_id": f"family:{repository}",
        "organization_lineage": owner,
        "candidate_group_count": groups,
        "licence": "Apache-2.0",
        "head_revision": "1" * 40,
        "partition": partition,
    }


def test_v04_supply_augmentation_is_additive_and_organization_disjoint() -> None:
    base = [
        _assignment("dev/a", "ENGINEERING_DEVELOPMENT"),
        _assignment("train/a", "TRAINING"),
    ]
    candidates = [
        {
            key: value
            for key, value in _assignment("fresh/a", "UNASSIGNED", 30).items()
            if key != "partition"
        },
        {
            key: value
            for key, value in _assignment("dev/b", "UNASSIGNED", 30).items()
            if key != "partition"
        },
        {
            key: value
            for key, value in _assignment("model/a", "UNASSIGNED", 30).items()
            if key != "partition"
        },
    ]
    assignments, added = _augment_assignments(
        base,
        candidates,
        supply_targets={"ENGINEERING_DEVELOPMENT": 50, "MODEL_SELECTION": 25},
        family_candidate_cap=25,
    )
    assert assignments[:2] == base
    assert {(item["repository"], item["partition"]) for item in added} == {
        ("dev/b", "ENGINEERING_DEVELOPMENT"),
        ("fresh/a", "MODEL_SELECTION"),
    }


def test_v04_supply_augmentation_fails_closed_when_supply_is_insufficient() -> None:
    with pytest.raises(PolicyError, match="INSUFFICIENT_ADDITIVE_RAW_SUPPLY"):
        _augment_assignments(
            [_assignment("dev/a", "ENGINEERING_DEVELOPMENT")],
            [],
            supply_targets={"ENGINEERING_DEVELOPMENT": 50},
            family_candidate_cap=25,
        )


def test_v04_assignment_source_resolves_by_identity_not_probe_run(tmp_path) -> None:
    wanted = {"record_id": "source-candidate:wanted", "payload": {}}
    (tmp_path / "token.run2.json").write_text(
        json.dumps({"record_id": "source-candidate:old"}),
        encoding="utf-8",
    )
    (tmp_path / "token.run4.json").write_text(
        json.dumps(wanted),
        encoding="utf-8",
    )
    assert (
        _load_assignment_source(
            tmp_path,
            repository_token="token",
            source_record_id="source-candidate:wanted",
        )
        == wanted
    )


def test_v04_rebalance_moves_complete_untouched_lineage_only() -> None:
    base = [
        _assignment("shared/a", "QUALIFICATION", 30),
        _assignment("shared/b", "QUALIFICATION", 20),
        _assignment("other/a", "TRAINING", 10),
    ]
    assignments, changed = _reassign_untouched_lineages(
        base,
        moves={base[0]["repository_token"]: "TRAINING"},
        touched_repository_tokens=set(),
    )
    assert [item["partition"] for item in assignments] == [
        "TRAINING",
        "TRAINING",
        "TRAINING",
    ]
    assert len(changed) == 2


def test_v04_rebalance_rejects_any_touched_lineage_member() -> None:
    base = [
        _assignment("shared/a", "QUALIFICATION"),
        _assignment("shared/b", "QUALIFICATION"),
    ]
    with pytest.raises(PolicyError, match="TOUCHED_REPOSITORY"):
        _reassign_untouched_lineages(
            base,
            moves={base[0]["repository_token"]: "TRAINING"},
            touched_repository_tokens={base[1]["repository_token"]},
        )


def test_v04_policy_reconsideration_gets_a_new_append_only_identity() -> None:
    original = {
        "candidate_id": "v0.4-candidate-group:" + "a" * 64,
        "repository": "owner/repository",
        "fixing_revision": "b" * 40,
    }
    replacement = _reconsidered_candidate(original)
    assert replacement["candidate_id"] != original["candidate_id"]
    assert replacement["supersedes_candidate_id"] == original["candidate_id"]
    assert replacement["repository"] == original["repository"]
    assert _reconsidered_candidate(original) == replacement


def test_v04_training_family_cap_is_stable_and_partition_scoped() -> None:
    cards = [
        {
            "record_id": f"card:{index:02d}",
            "payload": {
                "partition": "TRAINING",
                "family_id": "family:one",
            },
        }
        for index in range(4)
    ]
    cards.append(
        {
            "record_id": "card:evaluation",
            "payload": {
                "partition": "QUALIFICATION",
                "family_id": "family:one",
            },
        }
    )
    assert _family_cap_exclusions(
        cards,
        partition="TRAINING",
        maximum_groups_per_family=2,
        already_excluded=set(),
    ) == {"card:02", "card:03"}
