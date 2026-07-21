# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from lumi_trace.canonical import load_json
from lumi_trace.errors import InputError
from lumi_trace.pipeline import source_revision, trace_repository
from lumi_trace.reporting import verify_evidence_bundle


def test_pipeline_emits_complete_package_without_reproduction(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    output = tmp_path / "evidence"
    result = trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=fixture_repository,
        output_directory=output,
        top_k=8,
        implementation_revision="fixture-revision",
    )
    assert result["bundle"]["classification"]["outcome"] == "INSUFFICIENT_EVIDENCE"
    expected = {
        "normalized-finding.json",
        "repository-index.json",
        "candidates.json",
        "evidence-bundle.json",
        "evidence.sarif",
        "manifest.json",
    }
    assert {item.name for item in output.iterdir()} == expected
    verify_evidence_bundle(load_json(output / "evidence-bundle.json"))


def test_pipeline_is_byte_deterministic_without_reproduction(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    kwargs = {
        "finding_path": manual_finding_path,
        "finding_format": "manual",
        "repository_source": fixture_repository,
        "top_k": 8,
        "implementation_revision": "fixture-revision",
    }
    trace_repository(output_directory=first, **kwargs)
    trace_repository(output_directory=second, **kwargs)
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }


def test_pipeline_refuses_existing_output_directory(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    stale = output / "stale-receipt.json"
    stale.write_text("do not retain", encoding="utf-8")
    with pytest.raises(InputError, match="already exists"):
        trace_repository(
            finding_path=manual_finding_path,
            finding_format="manual",
            repository_source=fixture_repository,
            output_directory=output,
            implementation_revision="fixture-revision",
        )
    assert stale.read_text(encoding="utf-8") == "do not retain"


def test_source_revision_does_not_inherit_an_unrelated_parent_repository(tmp_path: Path) -> None:
    package_like_directory = tmp_path / "site-packages"
    package_like_directory.mkdir()
    assert source_revision(package_like_directory) == "release:0.1.0"
