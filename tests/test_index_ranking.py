# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
from pathlib import Path

import pytest

import lumi_trace.indexing as indexing
from lumi_trace.canonical import stable_id
from lumi_trace.errors import IntegrityError, UnsupportedError
from lumi_trace.findings import import_manual
from lumi_trace.indexing import build_repository_index, verify_repository_index
from lumi_trace.ranking import (
    SCORE_REASON_MATCH_LIMIT,
    _reason,
    rank_candidates,
    verify_ranked_candidates,
)
from lumi_trace.repository import RepositoryWorkspace, compute_repository_identity


def test_index_and_rank_are_deterministic(
    fixture_repository: Path, manual_finding_path: Path
) -> None:
    finding = import_manual(manual_finding_path, fixture_repository)
    with RepositoryWorkspace(fixture_repository) as workspace:
        first_index = build_repository_index(workspace.root, workspace.identity)
        second_index = build_repository_index(workspace.root, workspace.identity)
    assert first_index == second_index
    archive_file = next(item for item in first_index["files"] if item["path"] == "src/archive.sh")
    assert any(symbol["name"] == "unsafe_join" for symbol in archive_file["symbols"])

    first_rank = rank_candidates(finding, first_index, top_k=10)
    second_rank = rank_candidates(finding, second_index, top_k=10)
    assert first_rank == second_rank
    top = first_rank["candidates"][0]
    assert top["path"] == "src/archive.sh"
    assert top["kind"] == "symbol"
    assert top["symbol"]["name"] == "unsafe_join"
    assert top["integer_score"] > 0
    assert first_rank["confidence_is_not_probability"] is True


def test_python_ast_recursion_limit_is_reported_without_crashing(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "deep.py"
    source.write_text("value = " + "+".join(["1"] * 3_000) + "\n", encoding="utf-8")

    index = build_repository_index(repository, compute_repository_identity(repository))

    record = index["files"][0]
    assert record["content_indexed"] is True
    assert record["symbol_extraction_issue"] == "complexity_limit"
    assert record["symbols"] == []


def test_python_symbol_accumulation_stops_at_the_requested_cap() -> None:
    text = "\n".join(f"def function_{number}(): pass" for number in range(20))

    symbols, issue, limited = indexing._python_symbols(text, max_symbols=3)

    assert issue is None
    assert limited is True
    assert [symbol["name"] for symbol in symbols] == [
        "function_0",
        "function_1",
        "function_2",
    ]


def test_python_ast_walk_stops_at_the_node_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(indexing, "MAX_PYTHON_AST_NODES", 2)

    symbols, issue, limited = indexing._python_symbols("def bounded():\n    return 1\n")

    assert [symbol["name"] for symbol in symbols] == ["bounded"]
    assert issue == "complexity_limit"
    assert limited is False


def test_python_symbol_names_are_bounded() -> None:
    oversized_name = "a" * (indexing.MAX_SYMBOL_NAME_CHARS + 1)

    symbols, issue, limited = indexing._python_symbols(f"def {oversized_name}(): pass\n")

    assert symbols == []
    assert issue == "complexity_limit"
    assert limited is False


def test_global_index_budgets_are_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.py").write_text(
        "def alpha_one(): pass\ndef alpha_two(): pass\n", encoding="utf-8"
    )
    (repository / "b.py").write_text("def beta_three(): pass\n", encoding="utf-8")
    identity = compute_repository_identity(repository)
    monkeypatch.setattr(indexing, "MAX_TOTAL_TOKEN_ENTRIES", 2)
    monkeypatch.setattr(indexing, "MAX_TOTAL_SYMBOLS", 1)

    first = build_repository_index(repository, identity)
    second = build_repository_index(repository, identity)

    assert first == second
    assert sum(len(record["tokens"]) for record in first["files"]) == 2
    assert first["symbol_count"] == 1
    assert first["global_limit_reached"] == {"token_entries": True, "symbols": True}


def test_index_refuses_more_file_records_than_its_loader_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.txt").write_text("one\n", encoding="utf-8")
    (repository / "b.txt").write_text("two\n", encoding="utf-8")
    identity = compute_repository_identity(repository)
    monkeypatch.setattr(indexing, "MAX_INDEX_FILE_RECORDS", 1)

    with pytest.raises(UnsupportedError, match="index file-record limit"):
        build_repository_index(repository, identity)


def test_index_refuses_an_artifact_larger_than_its_json_loader_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.txt").write_text("bounded output\n", encoding="utf-8")
    identity = compute_repository_identity(repository)
    monkeypatch.setattr(indexing, "MAX_INDEX_JSON_BYTES", 100)

    with pytest.raises(UnsupportedError, match="JSON artifact limit"):
        build_repository_index(repository, identity)


def test_rehashing_does_not_make_a_malformed_index_valid(
    fixture_repository: Path,
) -> None:
    with RepositoryWorkspace(fixture_repository) as workspace:
        index = build_repository_index(workspace.root, workspace.identity)
    malformed = copy.deepcopy(index)
    malformed["files"][0]["size_bytes"] = "not-an-integer"
    malformed["index_id"] = stable_id("index", malformed, omit_keys=("index_id",))
    with pytest.raises(IntegrityError, match="file identity"):
        verify_repository_index(malformed)


def _candidate_with_reason(reason: dict[str, object]) -> dict[str, object]:
    identity: dict[str, object] = {
        "kind": "file",
        "path": "source.py",
        "region": {
            "start_line": 1,
            "start_column": 1,
            "end_line": 1,
            "end_column": 1,
        },
    }
    return {
        **identity,
        "integer_score": 1,
        "score_reasons": [reason],
        "candidate_id": stable_id("candidate", identity),
        "rank": 1,
    }


@pytest.mark.parametrize("count", [0, 1, 8, 9, 10, 20])
def test_score_reason_match_boundaries_round_trip(count: int) -> None:
    matches = [f"match-{index:02d}" for index in range(count)]
    reason = _reason("MESSAGE_CONTENT_MATCH", count, matches)

    verify_ranked_candidates([_candidate_with_reason(reason)])

    if count:
        assert reason["matches"] == matches
    else:
        assert "matches" not in reason


def test_score_reason_producer_rejects_more_than_canonical_match_limit() -> None:
    matches = [f"match-{index:02d}" for index in range(SCORE_REASON_MATCH_LIMIT + 1)]

    with pytest.raises(ValueError, match="canonical limit"):
        _reason("MESSAGE_CONTENT_MATCH", 1, matches)


@pytest.mark.parametrize(
    "matches",
    [
        [],
        ["duplicate", "duplicate"],
        ["zulu", "alpha"],
        ["valid", ""],
        ["valid", 1],
    ],
)
def test_score_reason_verifier_rejects_noncanonical_matches(matches: list[object]) -> None:
    candidate = _candidate_with_reason(
        {"code": "MESSAGE_CONTENT_MATCH", "points": 1, "matches": matches}
    )

    with pytest.raises(IntegrityError, match="score reason is invalid"):
        verify_ranked_candidates([candidate])
