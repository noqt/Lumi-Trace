# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

from lumi_trace.canonical import dump_json, load_json, stable_id
from lumi_trace.cli import main


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
                "--source-revision",
                "fixture-revision",
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["classification"] == "INSUFFICIENT_EVIDENCE"
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
