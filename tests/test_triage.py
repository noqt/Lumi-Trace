# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path, PurePosixPath

import pytest

from lumi_trace.canonical import dump_json, load_json, sha256_file, stable_id
from lumi_trace.cli import main
from lumi_trace.errors import InputError, IntegrityError
from lumi_trace.findings import import_sarif
from lumi_trace.pipeline import trace_repository
from lumi_trace.triage import (
    TRIAGE_PARTIAL_SUCCESS_EXIT_CODE,
    review_triage_package,
    triage_sarif,
    verify_triage_package,
)


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
    projected_run = projected["runs"][0]
    assert projected_run["tool"]["driver"]["rules"] == []
    assert projected_run["results"] == []
    assert projected_run["originalUriBaseIds"] == {
        "%SRCROOT%": {"description": {"text": "Repository root for relative artifact paths."}}
    }
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
    capsys.readouterr()

    assert main(["review", str(output), "--fail-on-partial"]) == 0
    review_capture = capsys.readouterr()
    review_summary = json.loads(review_capture.out)
    assert review_summary["completeness_status"] == "complete"
    assert review_summary["selected_results"] == 0
    assert review_summary["completed_localizations"] == 0
    assert review_summary["result_local_errors"] == 0
    assert "Completeness: complete; 0 selected; 0 completed; 0 result-local errors" in (
        review_capture.err
    )


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
    projected_sarif = load_json(output / "triage.sarif")
    projected_run = projected_sarif["runs"][0]
    assert str(repository) not in json.dumps(projected_sarif)
    assert projected_run["originalUriBaseIds"] == {
        "%SRCROOT%": {"description": {"text": "Repository root for relative artifact paths."}}
    }
    artifact_locations = [
        location["physicalLocation"]["artifactLocation"]
        for result_item in projected_run["results"]
        for location in result_item.get("locations", []) + result_item.get("relatedLocations", [])
    ]
    assert artifact_locations
    assert all(
        location["uriBaseId"] == "%SRCROOT%" and not PurePosixPath(location["uri"]).is_absolute()
        for location in artifact_locations
    )
    primary_artifact_locations = [
        location["physicalLocation"]["artifactLocation"]
        for result_item in projected_run["results"]
        for location in result_item.get("locations", [])
    ]
    round_tripped = import_sarif(output / "triage.sarif", repository_root=repository)
    assert [location["path"] for finding in round_tripped for location in finding["locations"]] == [
        location["uri"] for location in primary_artifact_locations
    ]
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


def test_review_pages_verified_queue_and_does_not_mutate_package(
    tmp_path: Path,
    project_root: Path,
    capsys: pytest.CaptureFixture[str],
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
    before = {
        item.relative_to(output).as_posix(): item.read_bytes()
        for item in output.rglob("*")
        if item.is_file()
    }

    assert main(["review", str(output), "--limit", "1"]) == 0
    first_capture = capsys.readouterr()
    first = json.loads(first_capture.out)
    assert first["command"] == "review"
    assert first["after_rank"] == 0
    assert first["limit"] == 1
    assert first["total"] == 2
    assert first["has_more"] is True
    assert first["next_after_rank"] == 1
    assert first["queue_order_is_not_probability"] is True
    assert first["completeness_status"] == "partial-success"
    assert first["selected_results"] == 4
    assert first["completed_localizations"] == 3
    assert first["result_local_errors"] == 1
    assert len(first["entries"]) == 1

    assert main(["review", str(output), "--after-rank", "1", "--limit", "1"]) == 0
    second_capture = capsys.readouterr()
    second = json.loads(second_capture.out)
    assert second["after_rank"] == 1
    assert second["has_more"] is False
    assert second["next_after_rank"] is None
    assert len(second["entries"]) == 1

    assert main(["review", str(output), "--limit", "1", "--fail-on-partial"]) == 5
    strict_capture = capsys.readouterr()
    strict = json.loads(strict_capture.out)
    assert strict["completeness_status"] == "partial-success"
    assert strict["selected_results"] == 4
    assert strict["completed_localizations"] == 3
    assert strict["result_local_errors"] == 1
    rows = first["entries"] + second["entries"]
    assert [row["queue_rank"] for row in rows] == [1, 2]
    for row in rows:
        assert row["path"].isascii()
        assert all(character.isprintable() for character in row["path"])
        assert "\\" not in row["path"]
        assert not PurePosixPath(row["path"]).is_absolute()
        assert row["role"] in {
            "implementation",
            "wrapper",
            "test",
            "fixture",
            "generated",
            "vendor",
        }
        assert row["severity"] in {"critical", "high", "medium", "low", "unknown"}
        assert isinstance(row["finding_count"], int)
        assert isinstance(row["best_shortlist_rank"], int)
        assert set(row["primary_region"]) == {
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        }
        assert row["candidates_reference"].startswith("findings/result-")
        assert row["candidates_reference"].endswith("/candidates.json")
        assert row["evidence_bundle_reference"].startswith("findings/result-")
        assert row["evidence_bundle_reference"].endswith("/evidence-bundle.json")
    rendered = (
        first_capture.out
        + first_capture.err
        + second_capture.out
        + second_capture.err
        + strict_capture.out
        + strict_capture.err
    )
    human_output = first_capture.err + second_capture.err + strict_capture.err
    assert "Completeness: partial-success; 4 selected; 3 completed; 1 result-local errors" in (
        human_output
    )
    for row in rows:
        region = row["primary_region"]
        assert f"{row['queue_rank']}. {row['path']}" in human_output
        assert row["role"] in human_output
        assert row["severity"] in human_output
        assert f"{row['finding_count']} findings" in human_output
        assert f"best shortlist rank {row['best_shortlist_rank']}" in human_output
        assert (
            f"Primary region {region['start_line']}:{region['start_column']}-"
            f"{region['end_line']}:{region['end_column']}"
        ) in human_output
        assert row["candidates_reference"] in human_output
        assert row["evidence_bundle_reference"] in human_output
    assert str(output) not in rendered
    assert str(repository) not in rendered
    assert "Quasar nebula mismatch" not in rendered
    assert "\x1b" not in rendered
    assert "Queue order is review priority, not probability" in first_capture.err
    after = {
        item.relative_to(output).as_posix(): item.read_bytes()
        for item in output.rglob("*")
        if item.is_file()
    }
    assert after == before


@pytest.mark.parametrize(
    "options",
    [
        ["--after-rank", "not-a-rank"],
        ["--after-rank", "-1"],
        ["--limit", "0"],
        ["--limit", "201"],
    ],
)
def test_review_rejects_invalid_pagination_without_echoing_inputs(
    tmp_path: Path,
    options: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "\x1b[31mhidden-path-marker"
    output = tmp_path / marker
    assert main(["review", str(output), *options]) != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "review pagination arguments are invalid" in captured.err
    assert marker not in captured.err
    assert "\x1b" not in captured.err


def test_review_parse_errors_do_not_echo_terminal_controls(
    capsys: pytest.CaptureFixture[str],
) -> None:
    control_marker = "\x1b[31mprivate-option-marker"
    assert main(["review", "package", "--unknown", control_marker]) != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "review arguments are invalid" in captured.err
    assert control_marker not in captured.err
    assert "\x1b" not in captured.err


def test_review_beyond_end_is_deterministic_empty_page(
    tmp_path: Path,
    project_root: Path,
    capsys: pytest.CaptureFixture[str],
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

    assert main(["review", str(output), "--after-rank", "999", "--limit", "1"]) == 0
    captured = capsys.readouterr()
    page = json.loads(captured.out)
    assert page["entries"] == []
    assert page["total"] == 2
    assert page["has_more"] is False
    assert page["next_after_rank"] is None


@pytest.mark.parametrize("tamper", ["queue", "manifest"])
def test_review_emits_no_rows_for_tampered_queue_or_manifest(
    tmp_path: Path,
    project_root: Path,
    capsys: pytest.CaptureFixture[str],
    tamper: str,
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
    if tamper == "queue":
        queue_path = output / "review-queue.json"
        queue = load_json(queue_path)
        queue["entries"][0]["queue_rank"] = 99
        dump_json(queue_path, queue)
    else:
        manifest_path = output / "manifest.json"
        manifest = load_json(manifest_path)
        manifest["package_id"] = "tampered-manifest-identity"
        dump_json(manifest_path, manifest)

    assert main(["review", str(output)]) != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "review failed; package verification was unsuccessful" in captured.err
    assert str(output) not in captured.err
    assert "\x1b" not in captured.err


def test_review_output_excludes_finding_and_result_error_details(
    tmp_path: Path,
    project_root: Path,
    capsys: pytest.CaptureFixture[str],
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
    error_path = next((output / "errors").glob("*.json"))
    error = load_json(error_path)
    detail_marker = "private-result-error-detail-\x1b[31m"
    error["detail"] = detail_marker
    dump_json(error_path, error)

    manifest_path = output / "manifest.json"
    manifest = load_json(manifest_path)
    relative_error = error_path.relative_to(output).as_posix()
    artifact = next(item for item in manifest["artifacts"] if item["path"] == relative_error)
    artifact["sha256"] = sha256_file(error_path)
    artifact["size_bytes"] = error_path.stat().st_size
    manifest.pop("package_id")
    manifest["package_id"] = stable_id("triage-package", manifest)
    dump_json(manifest_path, manifest)

    assert main(["review", str(output)]) == 0
    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "Quasar nebula mismatch" not in rendered
    assert "private-result-error-detail" not in rendered
    assert "\x1b" not in rendered
    assert str(output) not in rendered
    assert str(repository) not in rendered


def test_review_rows_use_only_verified_data_returned_by_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified_entry = {
        "queue_rank": 1,
        "path": "src/example.py",
        "role": "implementation",
        "highest_severity": "high",
        "finding_count": 1,
        "best_shortlist_rank": 1,
        "primary_anchor": {
            "finding_key": "result-000-00000-0123456789ab",
            "candidate_id": "candidate-id",
            "region": {
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
            },
        },
    }
    monkeypatch.setattr(
        "lumi_trace.triage.verify_triage_package",
        lambda _path: {
            "summary": {
                "exit_status": "partial-success",
                "selected_results": 3,
                "completed_localizations": 2,
                "result_local_errors": 1,
            },
            "review_queue": [verified_entry],
        },
    )
    monkeypatch.setattr(
        "lumi_trace.triage.load_json",
        lambda *_args, **_kwargs: pytest.fail("review must not perform an unchecked reread"),
    )

    page = review_triage_package(tmp_path / "not-read", limit=1)
    assert page["total"] == 1
    assert page["entries"][0]["path"] == "src/example.py"
    assert page["completeness_status"] == "partial-success"
    assert page["selected_results"] == 3
    assert page["completed_localizations"] == 2
    assert page["result_local_errors"] == 1
