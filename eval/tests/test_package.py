# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from trace_eval.errors import ContractError
from trace_eval.package import seal_package, verify_package


def test_package_manifest_detects_tamper_and_unmanifested_files(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    artifact = package / "artifact.txt"
    artifact.write_text("sealed\n", encoding="utf-8")
    seal_package(package)
    verify_package(package)
    artifact.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ContractError, match="artifact mismatch"):
        verify_package(package)


def test_package_manifest_rejects_symlinks_when_supported(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    target = package / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = package / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ContractError, match="symbolic link"):
        seal_package(package)
