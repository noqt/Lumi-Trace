# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from lumi_trace.canonical import load_json
from lumi_trace.cli import main


def _result(
    rule_id: str,
    *,
    path: str = "src/app.py",
    line: int = 1,
    fingerprint: str | None = None,
    message: str = "synthetic finding",
) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {
                        "startLine": line,
                        "startColumn": 1,
                        "endLine": line,
                        "endColumn": 5,
                    },
                }
            }
        ],
    }
    if fingerprint is not None:
        result["fingerprints"] = {"primaryLocationLineHash": fingerprint}
    return result


def _report(
    results: list[object],
    *,
    tool: str = "Synthetic Scanner",
    version: str = "1.0.0",
    rule_ids: list[str] | None = None,
) -> dict[str, object]:
    if rule_ids is None:
        rule_ids = sorted(
            {
                item["ruleId"]
                for item in results
                if isinstance(item, dict) and isinstance(item.get("ruleId"), str)
            }
        )
    rules = [{"id": rule_id, "name": rule_id} for rule_id in rule_ids]
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "semanticVersion": version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _compare(
    tmp_path: Path,
    before: dict[str, object],
    after: dict[str, object],
    *,
    repository: Path | None = None,
    output_name: str = "comparison.json",
) -> tuple[int, dict[str, object], Path]:
    repository = repository or (tmp_path / "repository")
    repository.mkdir(parents=True, exist_ok=True)
    before_path = tmp_path / "before.sarif"
    after_path = tmp_path / "after.sarif"
    output = tmp_path / output_name
    _write(before_path, before)
    _write(after_path, after)
    result = main(
        [
            "compare-sarif",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--repository",
            str(repository),
            "--output",
            str(output),
        ]
    )
    return result, load_json(output), output


def test_reordered_findings_match_without_hash_or_position_identity(tmp_path: Path, capsys) -> None:
    first = _result("RULE-A", line=4, fingerprint="aaa")
    second = _result("RULE-B", path="src/other.py", line=8, fingerprint="bbb")
    before = _report([first, second])
    after = _report([deepcopy(second), deepcopy(first)])
    after["runs"][0]["properties"] = {"synthetic_change": True}  # type: ignore[index]
    status, comparison, _ = _compare(tmp_path, before, after)
    capsys.readouterr()

    assert status == 0
    assert comparison["comparison_status"] == "COMPLETE"
    assert comparison["summary"] == {
        "new_in_report": 0,
        "absent_from_report": 0,
        "unchanged": 2,
        "ambiguous": 0,
    }
    assert comparison["inputs"]["before"]["sha256"] != comparison["inputs"]["after"]["sha256"]
    for item in comparison["categories"]["unchanged"]:
        assert "input_sha256" not in item["identity"]
        assert "raw_position" not in item["identity"]


def test_added_and_absent_items_use_exact_path_region(tmp_path: Path, capsys) -> None:
    before = _report([_result("RULE-A", line=2)])
    after = _report([_result("RULE-A", line=2), _result("RULE-A", path="src/new.py", line=3)])
    status, comparison, _ = _compare(tmp_path, before, after)
    capsys.readouterr()
    assert status == 0
    assert comparison["summary"]["unchanged"] == 1
    assert comparison["summary"]["new_in_report"] == 1

    status, comparison, _ = _compare(
        tmp_path / "absent",
        _report([_result("RULE-A", line=2), _result("RULE-A", path="src/old.py", line=3)]),
        _report([_result("RULE-A", line=2)]),
    )
    capsys.readouterr()
    assert status == 0
    assert comparison["summary"]["absent_from_report"] == 1


def test_duplicate_and_shifted_locations_are_ambiguous(tmp_path: Path, capsys) -> None:
    duplicate = _result("RULE-A", line=6)
    status, duplicate_comparison, _ = _compare(
        tmp_path / "duplicate",
        _report([duplicate, deepcopy(duplicate)]),
        _report([duplicate]),
    )
    capsys.readouterr()
    assert status == 0
    assert duplicate_comparison["comparison_status"] == "INCONCLUSIVE"
    assert duplicate_comparison["summary"]["ambiguous"] == 3
    assert duplicate_comparison["summary"]["new_in_report"] == 0
    assert duplicate_comparison["summary"]["absent_from_report"] == 0

    status, shifted, _ = _compare(
        tmp_path / "shifted",
        _report([_result("RULE-A", line=6)]),
        _report([_result("RULE-A", line=7)]),
    )
    capsys.readouterr()
    assert status == 0
    assert shifted["summary"]["ambiguous"] == 2
    assert shifted["summary"]["new_in_report"] == 0
    assert shifted["summary"]["absent_from_report"] == 0

    status, shifted_duplicate_after, _ = _compare(
        tmp_path / "shifted-duplicate-after",
        _report([_result("RULE-A", path="x.py", line=10)]),
        _report(
            [
                _result("RULE-A", path="x.py", line=20),
                _result("RULE-A", path="x.py", line=20),
            ]
        ),
    )
    capsys.readouterr()
    assert status == 0
    assert shifted_duplicate_after["comparison_status"] == "INCONCLUSIVE"
    assert shifted_duplicate_after["summary"] == {
        "new_in_report": 0,
        "absent_from_report": 0,
        "unchanged": 0,
        "ambiguous": 3,
    }

    status, shifted_duplicate_before, _ = _compare(
        tmp_path / "shifted-duplicate-before",
        _report(
            [
                _result("RULE-A", path="x.py", line=20),
                _result("RULE-A", path="x.py", line=20),
            ]
        ),
        _report([_result("RULE-A", path="x.py", line=10)]),
    )
    capsys.readouterr()
    assert status == 0
    assert shifted_duplicate_before["comparison_status"] == "INCONCLUSIVE"
    assert shifted_duplicate_before["summary"] == {
        "new_in_report": 0,
        "absent_from_report": 0,
        "unchanged": 0,
        "ambiguous": 3,
    }


def test_unique_fingerprint_matches_across_location_shift_and_preserves_evidence(
    tmp_path: Path, capsys
) -> None:
    status, comparison, _ = _compare(
        tmp_path,
        _report([_result("RULE-A", line=6, fingerprint="stable")]),
        _report([_result("RULE-A", line=77, fingerprint="stable")]),
    )
    capsys.readouterr()
    assert status == 0
    item = comparison["categories"]["unchanged"][0]
    assert item["match_basis"] == "stable_fingerprint"
    assert item["before"]["tool"] == {"name": "Synthetic Scanner", "version": "1.0.0"}
    assert item["before"]["rule"]["id"] == "RULE-A"
    assert item["before"]["locations"][0]["path"] == "src/app.py"
    assert item["before"]["locations"][0]["region"]["start_line"] == 6
    assert item["after"]["locations"][0]["region"]["start_line"] == 77
    assert item["before"]["raw_locations"][0]["region"]["startLine"] == 6
    assert item["before"]["raw_position"] == {"run_index": 0, "result_index": 0}
    assert comparison["inputs"]["before"]["sha256"].startswith("sha256:")
    assert comparison["inputs"]["after"]["sha256"].startswith("sha256:")


@pytest.mark.parametrize(
    "before,after,reason",
    [
        (
            _report([_result("RULE-A")], version="1.0.0"),
            _report([_result("RULE-A")], version="2.0.0"),
            "TOOL_INCOMPATIBLE",
        ),
        (
            _report([_result("RULE-A"), "not-an-object"]),
            _report([_result("RULE-A")]),
            "INPUT_PARTIAL",
        ),
    ],
)
def test_incompatible_and_partial_inputs_are_inconclusive(
    tmp_path: Path,
    before: dict[str, object],
    after: dict[str, object],
    reason: str,
    capsys,
) -> None:
    status, comparison, _ = _compare(tmp_path, before, after)
    capsys.readouterr()
    assert status == 0
    assert comparison["comparison_status"] == "INCONCLUSIVE"
    assert comparison["summary"]["ambiguous"] >= 1
    assert any(
        item["reason_code"] == reason for item in comparison["categories"]["ambiguous"]
    )
    assert comparison["summary"]["new_in_report"] == 0
    assert comparison["summary"]["absent_from_report"] == 0


def test_malformed_and_empty_unknown_inputs_never_report_zero_removals_as_complete(
    tmp_path: Path, capsys
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    before_path = tmp_path / "before.sarif"
    after_path = tmp_path / "after.sarif"
    before_path.write_text("{not-json", encoding="utf-8")
    _write(after_path, _report([] , tool="", version=""))
    output = tmp_path / "malformed-comparison.json"
    assert (
        main(
            [
                "compare-sarif",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--repository",
                str(repository),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    capsys.readouterr()
    comparison = load_json(output)
    assert comparison["comparison_status"] == "INCONCLUSIVE"
    assert comparison["input_completeness"]["before"] == "malformed"
    assert comparison["summary"]["new_in_report"] == 0
    assert comparison["summary"]["absent_from_report"] == 0
    assert comparison["summary"]["ambiguous"] >= 1


def test_failed_invocations_block_empty_nonempty_and_mixed_reports(
    tmp_path: Path, capsys
) -> None:
    empty_before = _report([], rule_ids=["RULE-A"])
    empty_before["runs"][0]["invocations"] = [  # type: ignore[index]
        {"executionSuccessful": False}
    ]
    status, empty, _ = _compare(
        tmp_path / "empty-invocation",
        empty_before,
        _report([], rule_ids=["RULE-A"]),
    )
    capsys.readouterr()
    assert status == 0
    assert empty["comparison_status"] == "INCONCLUSIVE"
    assert empty["input_completeness"]["before"] == "failed"
    assert "INVOCATION_FAILED" in empty["inputs"]["before"]["error_codes"]
    assert empty["summary"]["new_in_report"] == 0
    assert empty["summary"]["absent_from_report"] == 0

    nonempty_before = _report([_result("RULE-A", line=4)])
    nonempty_before["runs"][0]["invocations"] = [  # type: ignore[index]
        {"executionSuccessful": False}
    ]
    status, nonempty, _ = _compare(
        tmp_path / "nonempty-invocation",
        nonempty_before,
        _report([_result("RULE-A", line=4)]),
    )
    capsys.readouterr()
    assert status == 0
    assert nonempty["comparison_status"] == "INCONCLUSIVE"
    assert nonempty["input_completeness"]["before"] == "partial"
    assert nonempty["summary"]["new_in_report"] == 0
    assert nonempty["summary"]["absent_from_report"] == 0
    assert nonempty["summary"]["unchanged"] == 0

    mixed_before = _report([_result("RULE-A", line=4)], rule_ids=["RULE-A"])
    mixed_before["runs"].append(  # type: ignore[index]
        {
            "tool": {
                "driver": {
                    "name": "Synthetic Scanner",
                    "semanticVersion": "1.0.0",
                    "rules": [{"id": "RULE-A", "name": "RULE-A"}],
                }
            },
            "invocations": [{"executionSuccessful": False}],
            "results": [],
        }
    )
    status, mixed, _ = _compare(
        tmp_path / "mixed-invocation",
        mixed_before,
        _report([_result("RULE-A", line=4)], rule_ids=["RULE-A"]),
    )
    capsys.readouterr()
    assert status == 0
    assert mixed["comparison_status"] == "INCONCLUSIVE"
    assert mixed["input_completeness"]["before"] == "partial"
    assert mixed["summary"]["new_in_report"] == 0
    assert mixed["summary"]["absent_from_report"] == 0
    assert mixed["summary"]["unchanged"] == 0


def test_deterministic_bounded_output_and_schema_shape(tmp_path: Path, capsys) -> None:
    before = _report([_result("RULE-A", line=3), _result("RULE-A", path="src/b.py", line=2)])
    after = _report([_result("RULE-A", path="src/b.py", line=2), _result("RULE-A", line=3)])
    first_status, first, _ = _compare(tmp_path, before, after, output_name="one.json")
    capsys.readouterr()
    second_status, second, _ = _compare(tmp_path, before, after, output_name="two.json")
    capsys.readouterr()
    assert first_status == second_status == 0
    assert first == second
    assert set(first["categories"]) == {
        "new_in_report",
        "absent_from_report",
        "unchanged",
        "ambiguous",
    }
    assert all(len(value) <= 2000 for value in first["categories"].values())


def test_invalid_missing_unsafe_symlink_existing_output_and_repository_failures(
    tmp_path: Path, capsys
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    before = tmp_path / "before.sarif"
    after = tmp_path / "after.sarif"
    _write(before, _report([_result("RULE-A")]))
    _write(after, _report([_result("RULE-A")]))

    missing_output = tmp_path / "missing.json"
    assert (
        main(
            [
                "compare-sarif",
                "--before",
                str(tmp_path / "does-not-exist.sarif"),
                "--after",
                str(after),
                "--repository",
                str(repository),
                "--output",
                str(missing_output),
            ]
        )
        == 2
    )
    capsys.readouterr()
    assert not missing_output.exists()

    unsafe = tmp_path / "unsafe.sarif"
    _write(unsafe, _report([_result("RULE-A", path="../escape.py")]))
    assert (
        main(
            [
                "compare-sarif",
                "--before",
                str(unsafe),
                "--after",
                str(after),
                "--repository",
                str(repository),
                "--output",
                str(tmp_path / "unsafe-output.json"),
            ]
        )
        == 2
    )
    capsys.readouterr()

    if hasattr(os, "symlink"):
        symlink = tmp_path / "before-link.sarif"
        try:
            symlink.symlink_to(before)
        except OSError:
            symlink = None
        if symlink is not None:
            assert (
                main(
                    [
                        "compare-sarif",
                        "--before",
                        str(symlink),
                        "--after",
                        str(after),
                        "--repository",
                        str(repository),
                        "--output",
                        str(tmp_path / "symlink-output.json"),
                    ]
                )
                == 2
            )
            capsys.readouterr()

    existing = tmp_path / "existing.json"
    existing.write_text("do not overwrite", encoding="utf-8")
    assert (
        main(
            [
                "compare-sarif",
                "--before",
                str(before),
                "--after",
                str(after),
                "--repository",
                str(repository),
                "--output",
                str(existing),
            ]
        )
        == 2
    )
    capsys.readouterr()
    assert existing.read_text(encoding="utf-8") == "do not overwrite"

    repository_file = tmp_path / "not-a-repository"
    repository_file.write_text("file", encoding="utf-8")
    assert (
        main(
            [
                "compare-sarif",
                "--before",
                str(before),
                "--after",
                str(after),
                "--repository",
                str(repository_file),
                "--output",
                str(tmp_path / "bad-repo-output.json"),
            ]
        )
        == 2
    )
    capsys.readouterr()


def test_invalid_arguments_are_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["compare-sarif"])

