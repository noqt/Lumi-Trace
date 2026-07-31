# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from lumi_trace.canonical import dump_json, load_json, stable_id
from lumi_trace.cli import _write_trace_summary, main


def test_version_reports_zero_weights(capsys) -> None:
    assert main(["version"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["inventory_id"] == "skylark.lumi.trace"
    assert output["model_status"] == "DEVELOPMENT_RUNTIME_NO_PACKAGED_WEIGHTS"
    assert output["checkpoint"] is None
    assert output["current_weights"] == 0


def test_cli_import_and_trace_without_provider_or_api_key(
    tmp_path: Path,
    fixture_repository: Path,
    manual_finding_path: Path,
    capsys,
) -> None:
    normalized = tmp_path / "normalized.json"
    assert (
        main(
            [
                "import-manual",
                str(manual_finding_path),
                "--repository",
                str(fixture_repository),
                "--output",
                str(normalized),
            ]
        )
        == 0
    )
    capsys.readouterr()
    output = tmp_path / "evidence"
    assert (
        main(
            [
                "trace",
                "--finding",
                str(normalized),
                "--finding-format",
                "normalized",
                "--repository",
                str(fixture_repository),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["classification"] == "INSUFFICIENT_EVIDENCE"
    assert summary["ranking_abstained"] is True
    assert summary["ranking_abstention_reason"] == "NO_POSITIVE_FINDING_GUIDED_SIGNAL"
    assert summary["reason_codes"] == ["NO_REPRODUCTION_PLAN"]
    assert summary["ranking_algorithm"] == "role-aware-sparse-v0.4.1.3"
    assert summary["candidate_algorithm"] == "label-blind-python-role-candidates-v0.4.1.7"
    assert summary["reproduction_requested"] is False
    assert summary["reproduction_abstained"] is True
    assert "Lumi Trace result" in captured.err
    assert "Localisation: complete; abstained (NO_POSITIVE_FINDING_GUIDED_SIGNAL)" in captured.err
    assert "Confirmation: not attempted (NO_REPRODUCTION_PLAN)" in captured.err
    assert "Evidence classification: INSUFFICIENT_EVIDENCE" in captured.err
    assert f'lumi-trace verify "{output}"' in captured.err
    assert (output / "evidence.sarif").is_file()
    assert main(["verify", str(output)]) == 0
    capsys.readouterr()
    manifest_path = output / "manifest.json"
    original_manifest = load_json(manifest_path)
    malformed_manifest = dict(original_manifest)
    malformed_manifest["unexpected"] = True
    malformed_manifest["manifest_id"] = stable_id(
        "evidence-package", malformed_manifest, omit_keys=("manifest_id",)
    )
    dump_json(manifest_path, malformed_manifest)
    assert main(["verify", str(output)]) == 2
    assert "manifest" in capsys.readouterr().err
    dump_json(manifest_path, original_manifest)
    (output / "unmanifested.json").write_text("{}", encoding="utf-8")
    assert main(["verify", str(output)]) == 2
    assert "unmanifested" in capsys.readouterr().err


def test_cli_traces_sarif_against_safe_archive_end_to_end(
    tmp_path: Path,
    project_root: Path,
    capsys,
) -> None:
    fixture_repository = project_root / "tests" / "fixtures" / "localization-repository"
    archive = tmp_path / "repository.zip"
    with zipfile.ZipFile(archive, "w") as package:
        for path in sorted(fixture_repository.rglob("*")):
            if path.is_file():
                package.write(path, Path("demo-repository") / path.relative_to(fixture_repository))

    output = tmp_path / "sarif-evidence"
    assert (
        main(
            [
                "trace",
                "--finding",
                str(project_root / "tests" / "data" / "finding.sarif"),
                "--finding-format",
                "sarif",
                "--run-index",
                "0",
                "--result-index",
                "0",
                "--repository",
                str(archive),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["ranking_algorithm"] == "role-aware-sparse-v0.4.1.3"
    assert summary["ranking_abstained"] is False
    assert summary["top_ranked_locations"][0]["path"] == "src/archive.py"
    assert summary["top_implementation_locations"][0]["path"] == "src/archive.py"
    assert main(["verify", str(output)]) == 0
    capsys.readouterr()


def test_trace_summary_foregrounds_implementation_candidates_at_true_rank(
    tmp_path: Path,
    capsys,
) -> None:
    candidates = [
        {
            "rank": rank,
            "path": path,
            "symbol": {"qualified_name": symbol},
            "role": role,
            "integer_score": 100 - rank,
        }
        for rank, path, symbol, role in (
            (1, "tests/test_alpha.py", "test_alpha", "test"),
            (2, "tests/test_beta.py", "test_beta", "test"),
            (3, "docs/example.py", "example", "documentation"),
            (4, "src/alpha.py", "alpha", "implementation"),
            (8, "src/beta.py", "beta", "implementation"),
            (11, "src/gamma.py", "gamma", "implementation"),
        )
    ]
    _write_trace_summary(
        {
            "output_directory": tmp_path / "evidence",
            "candidate_set": {
                "algorithm": "role-aware-sparse-v0.4.1.3",
                "candidate_algorithm": "label-blind-python-role-candidates-v0.4.1.7",
                "ranking_id": "ranking:fixture",
                "confidence_descriptor": "FINDING_GUIDED_SIGNAL_PRESENT",
                "abstention": {"abstained": False, "reason": None},
                "candidates": candidates,
            },
            "bundle": {
                "bundle_id": "evidence-bundle:fixture",
                "classification": {
                    "outcome": "INSUFFICIENT_EVIDENCE",
                    "reason_codes": ["NO_REPRODUCTION_PLAN"],
                    "confidence_grade": "ABSTAINED",
                    "confidence_basis_points": 0,
                },
                "reproduction": {
                    "requested": False,
                    "attempted": False,
                },
            },
        }
    )

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert [item["rank"] for item in summary["top_ranked_locations"]] == [1, 2, 3]
    assert [item["rank"] for item in summary["top_implementation_locations"]] == [4, 8, 11]
    assert "Top implementation locations (true overall rank)" in captured.err
    assert "    4. src/alpha.py::alpha" in captured.err
    assert "    1. tests/test_alpha.py::test_alpha" not in captured.err


def test_cli_rejects_ambiguous_sarif_with_actionable_selection_hint(
    tmp_path: Path,
    fixture_repository: Path,
    project_root: Path,
    capsys,
) -> None:
    source = json.loads(
        (project_root / "tests" / "data" / "finding.sarif").read_text(encoding="utf-8")
    )
    source["runs"][0]["results"].append(source["runs"][0]["results"][0])
    ambiguous = tmp_path / "ambiguous.sarif"
    ambiguous.write_text(json.dumps(source), encoding="utf-8")

    assert (
        main(
            [
                "trace",
                "--finding",
                str(ambiguous),
                "--finding-format",
                "sarif",
                "--repository",
                str(fixture_repository),
                "--output",
                str(tmp_path / "unused"),
            ]
        )
        == 2
    )
    error = capsys.readouterr().err
    assert "selection produced 2 findings" in error
    assert "--run-index and --result-index" in error


def test_cli_rejects_unsafe_archive_with_actionable_hint(
    tmp_path: Path,
    project_root: Path,
    capsys,
) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("../escape.py", "print('unsafe')\n")

    assert (
        main(
            [
                "trace",
                "--finding",
                str(project_root / "tests" / "data" / "manual-finding.json"),
                "--finding-format",
                "manual",
                "--repository",
                str(archive),
                "--output",
                str(tmp_path / "unused"),
            ]
        )
        == 2
    )
    error = capsys.readouterr().err
    assert "unsafe archive member" in error
    assert "regular ZIP/TAR-family archive" in error


def test_trace_rejects_public_source_revision_override(
    fixture_repository: Path,
    manual_finding_path: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "trace",
                "--finding",
                str(manual_finding_path),
                "--finding-format",
                "manual",
                "--repository",
                str(fixture_repository),
                "--output",
                str(tmp_path / "unused"),
                "--source-revision",
                "spoofed-revision",
            ]
        )
    assert raised.value.code == 2
