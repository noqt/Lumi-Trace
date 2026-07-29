# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator

from lumi_trace.findings import import_sarif


def _example_directory(project_root: Path) -> Path:
    return project_root / "examples" / "public-ghsa-8359-h9fx-j6v9"


def _fetch_module(project_root: Path) -> ModuleType:
    path = _example_directory(project_root) / "fetch_example.py"
    spec = importlib.util.spec_from_file_location("lumi_trace_public_example_fetch", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_archive(path: Path, root: str, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(f"{root}/", b"")
        for relative_path, content in files.items():
            archive.writestr(f"{root}/{relative_path}", content)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_public_example_finding_is_valid_and_does_not_supply_targets(
    project_root: Path,
) -> None:
    example = _example_directory(project_root)
    finding = json.loads((example / "finding.json").read_text(encoding="utf-8"))
    schema = json.loads(
        (project_root / "schemas" / "manual-finding-v1.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(finding)

    assert finding["id"] == "GHSA-8359-h9fx-j6v9"
    assert "locations" not in finding
    serialized = json.dumps(finding).lower()
    assert "jsonschema.py" not in serialized
    assert "_get_ref_body" not in serialized


def test_public_example_sarif_imports_without_supplying_targets(
    project_root: Path,
) -> None:
    example = _example_directory(project_root)
    source = json.loads((example / "finding.sarif").read_text(encoding="utf-8"))
    assert len(source["runs"]) == 1
    assert len(source["runs"][0]["results"]) == 1
    result = source["runs"][0]["results"][0]
    assert "locations" not in result
    assert result["properties"]["sourceLicence"] == "CC-BY-4.0"
    assert result["properties"]["source"].endswith("/GHSA-8359-h9fx-j6v9")

    findings = import_sarif(example / "finding.sarif")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule"]["id"] == "GHSA-8359-h9fx-j6v9"
    assert finding["locations"] == []
    serialized = json.dumps(finding).lower()
    assert "jsonschema.py" not in serialized
    assert "_get_ref_body" not in serialized


def test_public_example_metadata_is_pinned_and_archive_is_not_committed(
    project_root: Path,
) -> None:
    example = _example_directory(project_root)
    fetch = _fetch_module(project_root)

    assert fetch.REVISION == "2dbe5b5794472a4cad8e9286c942dffda7359816"
    assert fetch.ARCHIVE_NAME == (
        "datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip"
    )
    assert fetch.ARCHIVE_URL == (
        "https://codeload.github.com/koxudaxi/datamodel-code-generator/zip/"
        "2dbe5b5794472a4cad8e9286c942dffda7359816"
    )
    assert fetch.ARCHIVE_SHA256 == (
        "12a2eef58a6241b250f87f9a2c0c581a5a6d29be88bf4e5090df0df060fb806c"
    )
    assert fetch.ARCHIVE_SIZE == 3_844_899
    assert fetch.EXPECTED_FILES["LICENSE"] == (
        "2b9e0bc1cebf8ddbb272ccbca051634047924ae122aaf5488c21885ce327b934"
    )
    assert fetch.EXPECTED_FILES["docs/assets/playground/THIRD_PARTY_LICENSES.txt"] == (
        "554dc29604b51ebe1b286ed60a9e21bbfc824c7851b7a2c8a3849ded2f769903"
    )
    assert not list(example.glob("*.zip"))
    rights = (example / "RIGHTS_AND_PROVENANCE.md").read_text(encoding="utf-8")
    assert fetch.ARCHIVE_SHA256 in rights
    assert fetch.ARCHIVE_URL in rights


def test_fetcher_validates_a_synthetic_safe_archive(
    project_root: Path,
    tmp_path: Path,
) -> None:
    fetch = _fetch_module(project_root)
    archive_path = tmp_path / "safe.zip"
    root = "reviewed-source"
    files = {
        "LICENSE": b"Skylark-authored test licence\n",
        "src/example.py": b"def example():\n    return True\n",
    }
    _write_archive(archive_path, root, files)
    expected_files = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}

    summary = fetch._validate_archive(
        archive_path,
        expected_sha256=_sha256(archive_path),
        expected_size=archive_path.stat().st_size,
        expected_root=root,
        expected_files=expected_files,
    )

    assert summary["member_count"] == 3
    assert summary["regular_file_count"] == 2
    assert summary["uncompressed_regular_bytes"] == sum(map(len, files.values()))


def test_fetcher_rejects_a_synthetic_traversal_member(
    project_root: Path,
    tmp_path: Path,
) -> None:
    fetch = _fetch_module(project_root)
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, mode="w") as archive:
        archive.writestr("reviewed-source/../escape.txt", b"not extracted\n")

    with pytest.raises(fetch.FetchError, match="escapes the expected root"):
        fetch._validate_archive(
            archive_path,
            expected_sha256=_sha256(archive_path),
            expected_size=archive_path.stat().st_size,
            expected_root="reviewed-source",
            expected_files={},
        )
