# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from lumi_trace.canonical import dump_json, load_json
from lumi_trace.cli import main
from lumi_trace.errors import InputError, IntegrityError
from lumi_trace.pipeline import trace_repository
from lumi_trace.triage import TRIAGE_PARTIAL_SUCCESS_EXIT_CODE, triage_sarif, verify_triage_package


def _multi_result_sarif(project_root: Path, destination: Path) -> Path:
    source = json.loads((project_root / "tests" / "data" / "finding.sarif").read_text("utf-8"))
    original = source["runs"][0]["results"][0]
    duplicate = deepcopy(original)
    unrelated = deepcopy(original)
    unrelated["ruleId"] = "UNRELATED"
    unrelated["message"] = {"text": "Quasar nebula mismatch"}
    unrelated["locations"] = []
    invalid = deepcopy(original)
    invalid["locations"] = "not-an-array"
    source["runs"][0]["results"] = [original, duplicate, unrelated]
    second_run = deepcopy(source["runs"][0])
    second_run["results"] = [invalid]
    source["runs"].append(second_run)
    destination.write_text(json.dumps(source), encoding="utf-8")
    return destination


def _empty_sarif(project_root: Path, destination: Path) -> Path:
    source = json.loads((project_root / "tests" / "data" / "finding.sarif").read_text("utf-8"))
    source["runs"][0]["results"] = []
    destination.write_text(json.dumps(source), encoding="utf-8")
    return destination


def test_triage_accepts_empty_sarif_as_verified_complete_package(
    tmp_path: Path, project_root: Path
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    sarif = _empty_sarif(project_root, tmp_path / "empty.sarif")
    output = tmp_path / "empty-triage"

    result = triage_sarif(
        sarif_path=sarif,
        repository_source=repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )

    assert result["exit_code"] == 0
    verify_triage_package(output)
    assert load_json(output / "triage-summary.json") == {
        "artifact_type": "summary",
        "completed_localizations": 0,
        "exit_code": 0,
        "exit_status": "complete",
        "localization_abstentions": 0,
        "queue_order_is_not_probability": True,
        "result_local_errors": 0,
        "schema_version": "batch-triage-package-v1",
        "selected_results": 0,
        "unique_review_paths": 0,
    }
    assert load_json(output / "normalized-findings.json")["findings"] == []
    assert load_json(output / "review-queue.json")["entries"] == []
    projected = load_json(output / "triage.sarif")
    assert projected["runs"][0]["tool"]["driver"]["rules"] == []
    assert projected["runs"][0]["results"] == []
    assert main(["verify", str(output)]) == 0


def test_triage_cli_reports_empty_complete_and_verifies(
    tmp_path: Path,
    project_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    sarif = _empty_sarif(project_root, tmp_path / "empty.sarif")
    output = tmp_path / "empty-cli-triage"

    assert (
        main(
            [
                "triage",
                "--sarif",
                str(sarif),
                "--repository",
                str(repository),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    machine_summary = json.loads(captured.out)
    assert machine_summary["command"] == "triage"
    assert machine_summary["selected_results"] == 0
    assert machine_summary["unique_review_paths"] == 0
    assert machine_summary["exit_status"] == "complete"
    assert "0 selected; 0 completed; 0 error" in captured.err
    assert main(["verify", str(output)]) == 0


def test_triage_preserves_single_finding_candidates_and_partial_success(
    tmp_path: Path, project_root: Path
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    sarif = _multi_result_sarif(project_root, tmp_path / "findings.sarif")
    output = tmp_path / "triage"

    result = triage_sarif(
        sarif_path=sarif,
        repository_source=repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )

    assert result["exit_code"] == TRIAGE_PARTIAL_SUCCESS_EXIT_CODE
    verify_triage_package(output)
    summary = load_json(output / "triage-summary.json")
    assert summary == {
        "artifact_type": "summary",
        "completed_localizations": 3,
        "exit_code": TRIAGE_PARTIAL_SUCCESS_EXIT_CODE,
        "exit_status": "partial-success",
        "localization_abstentions": 1,
        "queue_order_is_not_probability": True,
        "result_local_errors": 1,
        "schema_version": "batch-triage-package-v1",
        "selected_results": 4,
        "unique_review_paths": 2,
    }
    normalized = load_json(output / "normalized-findings.json")
    keys = [item["result_key"] for item in normalized["findings"]]
    assert len(keys) == 3
    assert len(set(keys)) == 3
    assert keys[0] != keys[1]  # duplicate SARIF occurrences remain visible.
    standalone = trace_repository(
        finding_path=sarif,
        finding_format="sarif",
        repository_source=repository,
        output_directory=tmp_path / "standalone",
        run_index=0,
        result_index=0,
        implementation_revision="fixture-revision",
    )
    batch_candidates = load_json(output / "findings" / keys[0] / "candidates.json")
    assert batch_candidates == standalone["candidate_set"]
    queue = load_json(output / "review-queue.json")["entries"]
    assert queue[0]["path"] == "src/archive.py"
    assert queue[0]["finding_count"] == 2
    assert queue[0]["queue_order_is_not_probability"] is True
    assert (output / "errors" / f"{sorted((output / 'errors').iterdir())[0].stem}.json").is_file()


def test_triage_cli_reports_partial_success_and_verifies(
    tmp_path: Path, project_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    sarif = _multi_result_sarif(project_root, tmp_path / "findings.sarif")
    output = tmp_path / "triage"

    assert (
        main(
            [
                "triage",
                "--sarif",
                str(sarif),
                "--repository",
                str(repository),
                "--output",
                str(output),
            ]
        )
        == TRIAGE_PARTIAL_SUCCESS_EXIT_CODE
    )
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["command"] == "triage"
    assert summary["exit_code"] == TRIAGE_PARTIAL_SUCCESS_EXIT_CODE
    assert "Lumi Trace batch result" in captured.err
    assert "Queue order: review priority, not probability or exploitability" in captured.err
    assert main(["verify", str(output)]) == 0


def test_triage_refuses_oversize_selection_before_repository_materialisation(
    tmp_path: Path, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sarif = _multi_result_sarif(project_root, tmp_path / "findings.sarif")

    class ForbiddenWorkspace:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError(
                "repository must not be materialised for an oversize SARIF selection"
            )

    monkeypatch.setattr("lumi_trace.triage.RepositoryWorkspace", ForbiddenWorkspace)
    with pytest.raises(InputError, match="exceeding --max-findings"):
        triage_sarif(
            sarif_path=sarif,
            repository_source=tmp_path,
            output_directory=tmp_path / "unused",
            max_findings=3,
        )


def test_triage_verification_rejects_review_queue_tampering(
    tmp_path: Path, project_root: Path
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    sarif = _multi_result_sarif(project_root, tmp_path / "findings.sarif")
    output = tmp_path / "triage"
    triage_sarif(
        sarif_path=sarif,
        repository_source=repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )
    queue_path = output / "review-queue.json"
    queue = load_json(queue_path)
    queue["entries"][0]["queue_rank"] = 99
    dump_json(queue_path, queue)
    with pytest.raises(IntegrityError):
        verify_triage_package(output)
