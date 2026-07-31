# SPDX-License-Identifier: Apache-2.0
"""Exact run-package manifests and tamper detection."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import dump_json, load_json, sha256_file, stable_id
from .contracts import validate_record
from .errors import ContractError

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _safe_files(root: Path) -> dict[str, Path]:
    if root.is_symlink() or not root.is_dir():
        raise ContractError("package root must be a regular directory")
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ContractError("package contains a symbolic link")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in result:
            raise ContractError("package contains an unsafe or duplicate path")
        result[relative] = path
    return result


def seal_package(root: Path) -> dict[str, Any]:
    if (root / "manifest.json").exists():
        raise ContractError("refusing to overwrite package manifest")
    files = _safe_files(root)
    artifacts = [
        {"path": relative, "sha256": sha256_file(path), "size_bytes": path.stat().st_size}
        for relative, path in sorted(files.items())
    ]
    manifest: dict[str, Any] = {
        "schema_version": "trace-eval-package-manifest-v1",
        "artifacts": artifacts,
    }
    manifest["package_id"] = stable_id("trace-eval-package", manifest)
    dump_json(root / "manifest.json", manifest)
    return manifest


def verify_package(root: Path) -> dict[str, Any]:
    manifest = load_json(root / "manifest.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "artifacts", "package_id"}
        or manifest.get("schema_version") != "trace-eval-package-manifest-v1"
        or not isinstance(manifest.get("artifacts"), list)
    ):
        raise ContractError("package manifest fields are invalid")
    expected = stable_id(
        "trace-eval-package", {key: value for key, value in manifest.items() if key != "package_id"}
    )
    if manifest["package_id"] != expected:
        raise ContractError("package identity mismatch")
    files = _safe_files(root)
    files.pop("manifest.json", None)
    declared: dict[str, dict[str, Any]] = {}
    previous = ""
    for artifact in manifest["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256", "size_bytes"}
            or not isinstance(artifact["path"], str)
            or not isinstance(artifact["sha256"], str)
            or _SHA256.fullmatch(artifact["sha256"]) is None
            or not isinstance(artifact["size_bytes"], int)
            or isinstance(artifact["size_bytes"], bool)
            or artifact["size_bytes"] < 0
            or artifact["path"] <= previous
        ):
            raise ContractError("package artifact declaration is invalid or unsorted")
        previous = artifact["path"]
        declared[artifact["path"]] = artifact
    if set(files) != set(declared):
        raise ContractError("package contains an unmanifested or missing file")
    for relative, path in files.items():
        artifact = declared[relative]
        if sha256_file(path) != artifact["sha256"] or path.stat().st_size != artifact["size_bytes"]:
            raise ContractError(f"package artifact mismatch: {relative}")
        if relative.endswith(".json"):
            value = load_json(path)
            if isinstance(value, dict) and "record_id" in value:
                validate_record(value)
    return manifest
