# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from trace_eval.features import (
    apply_private_labels,
    build_candidate_features,
    training_candidate_projection,
)


def _finding() -> dict[str, object]:
    return {
        "advisory_identifier": "ADV-1",
        "aliases": ["CVE-1"],
        "packages": ["parser"],
        "summary": "unsafe parser input",
        "description": "validate parser input before use",
    }


def test_v04_candidate_generation_is_label_blind_bounded_and_deterministic() -> None:
    files = [
        {
            "path": "pkg/parser.py",
            "source": "def validate_input(value):\n    return value\n",
        },
        {
            "path": "tests/test_parser.py",
            "source": "def test_parser():\n    assert True\n",
        },
    ]
    first = build_candidate_features(_finding(), files, maximum_candidates=3)
    second = build_candidate_features(_finding(), list(reversed(files)), maximum_candidates=3)
    assert first == second
    assert len(first) == 3
    assert all("target" not in candidate for candidate in first)


def test_v04_candidate_cap_reserves_file_coverage_before_symbols() -> None:
    files = [
        {
            "path": f"pkg/module_{index}.py",
            "source": "\n".join(
                f"def parser_{symbol}():\n    return {symbol}" for symbol in range(20)
            ),
        }
        for index in range(3)
    ]
    candidates = build_candidate_features(
        _finding(),
        files,
        maximum_candidates=3,
    )
    assert len(candidates) == 3
    assert {candidate["path"] for candidate in candidates} == {item["path"] for item in files}
    assert all(candidate["symbol"] is None for candidate in candidates)


def test_v04_large_tree_uses_query_aware_file_and_symbol_budget() -> None:
    files = [
        {
            "path": f"pkg/unrelated_{index}.py",
            "source": (
                "# Apache Foundation boilerplate\n" * 300
                + f"\ndef unrelated_{index}():\n    return {index}\n"
            ),
        }
        for index in range(8)
    ]
    files.append(
        {
            "path": "pkg/security/parser.py",
            "source": (
                "# Apache Foundation boilerplate\n" * 300
                + "\ndef validate_parser_input(value):\n    return value\n"
            ),
        }
    )
    candidates = build_candidate_features(
        _finding(),
        files,
        maximum_candidates=4,
    )
    assert len(candidates) == 4
    assert any(candidate["path"] == "pkg/security/parser.py" for candidate in candidates)
    assert any(candidate["symbol"] is not None for candidate in candidates)


def test_v04_private_labels_bind_file_role_and_hard_negative_after_generation() -> None:
    candidates = build_candidate_features(
        _finding(),
        [
            {
                "path": "pkg/parser.py",
                "source": "def validate_input(value):\n    return value\n",
            },
            {
                "path": "tests/test_parser.py",
                "source": "def test_parser():\n    assert True\n",
            },
        ],
    )
    labels = apply_private_labels(
        candidates,
        targets=[{"path": "pkg/parser.py", "symbol": "validate_input"}],
        hard_negative_paths=["tests/test_parser.py"],
    )
    assert labels["file_target_present"] is True
    assert labels["role_target_present"] is True
    assert labels["file_target_candidate_ids"]
    assert labels["role_target_candidate_ids"]
    assert labels["hard_negative_candidate_ids"]
    projected = [
        training_candidate_projection(
            candidate,
            target_ids=set(labels["role_target_candidate_ids"]),
        )
        for candidate in candidates
    ]
    assert sum(candidate["target"] for candidate in projected) == 1
