# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

import lumi_trace.indexing as indexing
from lumi_trace.canonical import stable_id
from lumi_trace.errors import IntegrityError, UnsupportedError
from lumi_trace.findings import import_manual
from lumi_trace.indexing import build_repository_index, verify_repository_index
from lumi_trace.ranking import (
    SCORE_REASON_MATCH_LIMIT,
    _query,
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


def test_python_lexical_line_limit_is_reported_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "deep.py"
    source.write_text("value = 1\nvalue = 2\nvalue = 3\n", encoding="utf-8")
    monkeypatch.setattr(indexing, "MAX_PYTHON_SOURCE_LINES", 2)

    index = build_repository_index(repository, compute_repository_identity(repository))

    record = index["files"][0]
    assert record["content_indexed"] is True
    assert record["symbol_extraction_issue"] == "complexity_limit"
    assert record["symbols"] == []


def test_current_non_python_symbols_use_ascii_regex_semantics(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "drift.js").write_text(
        "class A\U00011f02 {}\n",
        encoding="utf-8",
    )

    index = build_repository_index(repository, compute_repository_identity(repository))

    assert [symbol["name"] for symbol in index["files"][0]["symbols"]] == ["A"]


@pytest.mark.parametrize("filename", ["caf\u00e9.py", "target\x7f.py"])
def test_current_index_rejects_non_printable_ascii_repository_paths(
    tmp_path: Path,
    filename: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / filename).write_text("def retained(): pass\n", encoding="utf-8")

    with pytest.raises(UnsupportedError, match="ASCII repository paths"):
        build_repository_index(repository, compute_repository_identity(repository))


def test_current_index_rejects_an_ungoverned_python_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("def retained(): pass\n", encoding="utf-8")
    monkeypatch.setattr(indexing, "supported_python_runtime", lambda: False)

    with pytest.raises(UnsupportedError, match="governed recursion limit"):
        build_repository_index(repository, compute_repository_identity(repository))


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


def test_step1_python_symbol_grammar_rejects_python_312_type_aliases() -> None:
    source = "type Alias = int\n\nclass Python312Only:\n    pass\n"

    symbols, issue, limited = indexing._python_symbols(source)

    assert symbols == []
    assert issue == "syntax_error"
    assert limited is False


def test_legacy_index_algorithm_remains_explicitly_verifiable(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text(
        'def retained():\n    value = """a\u2028b"""\n    return value\n',
        encoding="utf-8",
    )

    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 12):
        with pytest.raises(UnsupportedError, match="requires CPython 3.12"):
            build_repository_index(
                repository,
                compute_repository_identity(repository),
                algorithm=indexing.LEGACY_INDEX_ALGORITHM,
            )
        return

    index = build_repository_index(
        repository,
        compute_repository_identity(repository),
        algorithm=indexing.LEGACY_INDEX_ALGORITHM,
    )

    assert index["algorithm"] == "deterministic-lexical-index-v2"
    assert index["files"][0]["line_count"] == 4
    assert index["files"][0]["symbols"][0]["end_line"] == 3
    verify_repository_index(index)


def test_superseded_step1_ast_index_is_verification_only(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("def retained():\n    return 1\n", encoding="utf-8")
    identity = compute_repository_identity(repository)

    with pytest.raises(UnsupportedError, match="verification-only"):
        build_repository_index(
            repository,
            identity,
            algorithm=indexing.STEP1_AST_INDEX_ALGORITHM,
        )

    current = build_repository_index(repository, identity)
    current["algorithm"] = indexing.STEP1_AST_INDEX_ALGORITHM
    current["limits"]["max_python_ast_nodes"] = indexing.MAX_PYTHON_AST_NODES
    del current["limits"]["max_python_source_lines"]
    del current["limits"]["max_python_bracket_depth"]
    del current["limits"]["max_python_fstring_depth"]
    del current["limits"]["max_python_projection_chars"]
    del current["limits"]["max_python_projection_work"]
    del current["limits"]["max_python_projection_ast_nodes"]
    del current["limits"]["max_python_projection_ast_depth"]
    current["files"][0]["symbols"][0]["extractor"] = "python-ast-v1"
    current["index_id"] = stable_id("index", current, omit_keys=("index_id",))

    verify_repository_index(current)


def test_current_index_rejects_partial_symbols_after_extraction_issue(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("def retained(): pass\n", encoding="utf-8")
    index = build_repository_index(repository, compute_repository_identity(repository))
    index["files"][0]["symbol_extraction_issue"] = "syntax_error"
    index["index_id"] = stable_id("index", index, omit_keys=("index_id",))

    with pytest.raises(IntegrityError, match="cannot retain partial Python symbols"):
        verify_repository_index(index)


def test_python_lexical_scan_stops_at_the_line_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(indexing, "MAX_PYTHON_SOURCE_LINES", 1)

    symbols, issue, limited = indexing._python_symbols("def bounded():\n    return 1\n")

    assert symbols == []
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
    indexed_source = next(record for record in first["files"] if record["path"] == "a.py")
    assert [symbol["name"] for symbol in indexed_source["symbols"]] == ["alpha_one"]


def test_source_index_budget_is_allocated_before_observational_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.txt").write_text("documentation observation\n", encoding="utf-8")
    (repository / "z.py").write_text("def implementation_target(): pass\n", encoding="utf-8")
    identity = compute_repository_identity(repository)
    monkeypatch.setattr(indexing, "MAX_TOTAL_TOKEN_ENTRIES", 2)
    monkeypatch.setattr(indexing, "MAX_TOTAL_SYMBOLS", 1)

    result = build_repository_index(repository, identity)

    assert [record["path"] for record in result["files"]] == ["a.txt", "z.py"]
    source = result["files"][1]
    assert source["tokens"]
    assert [symbol["name"] for symbol in source["symbols"]] == ["implementation_target"]


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


def test_index_refuses_an_artifact_above_the_evaluator_item_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text(
        "def bounded_output():\n    return 1\n",
        encoding="utf-8",
    )
    identity = compute_repository_identity(repository)
    monkeypatch.setattr(indexing, "MAX_INDEX_JSON_ITEMS", 20)

    with pytest.raises(UnsupportedError, match="JSON item limit"):
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


def test_top_k_limits_each_path_to_two_candidates(
    tmp_path: Path, manual_finding_path: Path
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "implementation.py").write_text(
        "\n".join(f"def unsafe_archive_{number}(): pass" for number in range(12)),
        encoding="utf-8",
    )
    (repository / "secondary.py").write_text(
        "def bounded_archive(): pass\n",
        encoding="utf-8",
    )
    finding = import_manual(manual_finding_path, repository)
    index = build_repository_index(repository, compute_repository_identity(repository))

    result = rank_candidates(finding, index, top_k=10)

    paths = [candidate["path"] for candidate in result["candidates"]]
    assert paths.count("implementation.py") == 2
    assert "secondary.py" in paths


def test_natural_message_terms_rank_specific_implementation_over_generic_decoy(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "validation.py").write_text(
        "def validate_service():\n    return True\n",
        encoding="utf-8",
    )
    (repository / "ipv6.py").write_text(
        "def clean_ipv6_address(value):\n    return value\n",
        encoding="utf-8",
    )
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(
        json.dumps(
            {
                "schema_version": "manual-finding-v1",
                "id": "CVE-TEST",
                "title": "Service vulnerability in IPv6 validation",
                "description": "IPv6 address validation lacks a bounded input check.",
                "severity": "high",
                "rule": {
                    "id": "CVE-TEST",
                    "name": "Service vulnerability in IPv6 validation",
                    "cwes": ["CWE-770"],
                    "tags": ["public-security-advisory"],
                },
                "locations": [],
                "keywords": ["ipv6", "address", "validation"],
                "fingerprints": {},
            }
        ),
        encoding="utf-8",
    )
    finding = import_manual(finding_path, repository)
    query = _query(finding)
    assert "has" not in query["identifier_terms"]
    assert "security" not in query["identifier_terms"]
    index = build_repository_index(repository, compute_repository_identity(repository))

    result = rank_candidates(finding, index, top_k=4)

    assert result["candidates"][0]["path"] == "ipv6.py"


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
