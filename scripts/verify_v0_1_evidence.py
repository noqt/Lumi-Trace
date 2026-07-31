# SPDX-License-Identifier: Apache-2.0
"""Verify a sealed Lumi Trace V0.1 release-evidence tree without mutation."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from seal_v0_1 import (
    DEFAULT_OUTPUT,
    RELEASE_VERSION,
    REQUIRED_CHECKS,
    ROOT,
    SealError,
    _assert_public_safe_json,
    _identity,
    _load_json,
    _read_flat_inventory,
    _require_bundle_source_revision,
    _sha256_file,
    _verify_release_layout,
)

_SOURCE_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_RECORD_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]*")
_MAX_FILES = 2_000
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or _SAFE_RECORD_PATH.fullmatch(value) is None:
        raise SealError("seal manifest contains an invalid path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "\\" in value or pure.as_posix() != value:
        raise SealError("seal manifest contains an unsafe path")
    return value


def _tree_files(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or _is_reparse_point(path):
            raise SealError("sealed evidence contains a symbolic link or reparse point")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SealError("sealed evidence contains a non-regular entry")
        relative = path.relative_to(root).as_posix()
        if relative in result:
            raise SealError("sealed evidence contains a duplicate path")
        result[relative] = path
    return result


def verify_seal_manifest(root: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    """Verify exact tree membership, sizes, hashes, order, and manifest identity."""

    if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
        raise SealError("sealed evidence root must be a real directory")
    manifest_path = root / "seal-manifest.json"
    manifest = _load_json(manifest_path, max_bytes=4 * 1024 * 1024)
    required = {"schema_version", "release_version", "source_revision", "files", "seal_id"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise SealError("seal manifest fields are invalid")
    if (
        manifest.get("schema_version") != "lumi-trace-v0.1-seal-manifest-v1"
        or manifest.get("release_version") != RELEASE_VERSION
        or not isinstance(manifest.get("source_revision"), str)
        or _SOURCE_REVISION.fullmatch(manifest["source_revision"]) is None
    ):
        raise SealError("seal manifest identity is invalid")
    records = manifest.get("files")
    if not isinstance(records, list) or len(records) > _MAX_FILES:
        raise SealError("seal manifest file list is invalid")
    declared: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size_bytes"}:
            raise SealError("seal manifest file record is invalid")
        relative = _safe_relative_path(record["path"])
        if relative == "seal-manifest.json" or relative in declared:
            raise SealError("seal manifest path is duplicate or self-referential")
        if not isinstance(record["sha256"], str) or _SHA256.fullmatch(record["sha256"]) is None:
            raise SealError("seal manifest file digest is invalid")
        size = record["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise SealError("seal manifest file size is invalid")
        total_bytes += size
        declared[relative] = record
    if list(declared) != sorted(declared) or total_bytes > _MAX_TOTAL_BYTES:
        raise SealError("seal manifest paths are unsorted or exceed the total byte limit")
    actual = _tree_files(root)
    if set(actual) != set(declared) | {"seal-manifest.json"}:
        raise SealError("sealed evidence has an unmanifested or missing file")
    for relative, record in declared.items():
        path = actual[relative]
        if path.stat().st_size != record["size_bytes"] or _sha256_file(path) != record["sha256"]:
            raise SealError(f"sealed evidence file does not match its manifest: {relative}")
    expected_id = _identity("lumi-trace-v0.1-seal", manifest, omit=("seal_id",))
    if manifest["seal_id"] != expected_id:
        raise SealError("seal manifest identity mismatch")
    return manifest, actual


def _verify_identity(document: dict[str, Any], prefix: str, field: str) -> None:
    expected = _identity(prefix, document, omit=(field,))
    if document.get(field) != expected:
        raise SealError(f"{document.get('schema_version')} identity mismatch")


def _verify_checks(root: Path, source_revision: str) -> None:
    document = _load_json(root / "check-results.json")
    required = {
        "schema_version",
        "release_version",
        "source_revision",
        "overall_status",
        "checks",
        "check_set_id",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("release check results are malformed")
    expected_checks = [{"id": check_id, "status": "PASS"} for check_id in REQUIRED_CHECKS]
    if (
        document.get("schema_version") != "v0.1-release-check-results-v1"
        or document.get("release_version") != RELEASE_VERSION
        or document.get("source_revision") != source_revision
        or document.get("overall_status") != "PASS"
        or document.get("checks") != expected_checks
    ):
        raise SealError("release checks are incomplete or did not pass")
    _verify_identity(document, "release-checks", "check_set_id")


def _verify_evidence_package(
    root: Path, source_revision: str, *, runtime_source: Path | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    if runtime_source is not None:
        source_root = str(runtime_source)
        if source_root not in sys.path:
            sys.path.insert(0, source_root)
    from lumi_trace.cli import _verify_package  # noqa: PLC0415

    package = root / "evidence-package"
    _verify_package(package)
    bundle = _load_json(package / "evidence-bundle.json")
    receipt = _load_json(package / "reproduction-receipt.json")
    if not isinstance(bundle, dict) or not isinstance(receipt, dict):
        raise SealError("evidence package contracts are malformed")
    _require_bundle_source_revision(bundle, source_revision)
    if (
        bundle.get("classification", {}).get("outcome") != "CONFIRMED"
        or receipt.get("status") != "COMPLETED"
        or receipt.get("attempted") is not True
        or receipt.get("sandbox", {}).get("qualified") is not True
    ):
        raise SealError("evidence package is not a qualified CONFIRMED owned-fixture result")
    return bundle, receipt


def _verify_qualification(root: Path, source_revision: str, receipt: dict[str, Any]) -> None:
    document = _load_json(root / "sandbox-qualification.json")
    required = {
        "schema_version",
        "source_revision",
        "evidence_package_manifest_id",
        "receipt_id",
        "policy_id",
        "qualification_id",
        "image_reference_sha256",
        "image_id",
        "network_mode",
        "source_mount",
        "classification",
        "qualification",
        "attestation_id",
    }
    package_manifest = _load_json(root / "evidence-package" / "manifest.json")
    sandbox = receipt["sandbox"]
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("sandbox qualification evidence is malformed")
    expected = {
        "schema_version": "sandbox-qualification-evidence-v1",
        "source_revision": source_revision,
        "evidence_package_manifest_id": package_manifest.get("manifest_id"),
        "receipt_id": receipt.get("receipt_id"),
        "policy_id": receipt.get("policy_id"),
        "qualification_id": receipt.get("qualification_id"),
        "image_reference_sha256": sandbox.get("image_reference_sha256"),
        "image_id": sandbox.get("image_id"),
        "network_mode": "none",
        "source_mount": "read_only",
        "classification": "CONFIRMED",
        "qualification": receipt.get("qualification"),
    }
    if {key: document.get(key) for key in expected} != expected:
        raise SealError("sandbox qualification does not match its reproduction receipt")
    _verify_identity(document, "sandbox-qualification", "attestation_id")


def _verify_dependency_inventory(document: Any) -> None:
    required = {
        "schema_version",
        "project_name",
        "project_version",
        "runtime_dependency_count",
        "dependencies",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("dependency inventory is malformed")
    dependencies = document.get("dependencies")
    if (
        document.get("schema_version") != "resolved-dependency-inventory-v1"
        or document.get("project_name") != "skylark-lumi-trace"
        or document.get("project_version") != RELEASE_VERSION
        or document.get("runtime_dependency_count") != 0
        or not isinstance(dependencies, list)
    ):
        raise SealError("dependency inventory violates the V0.1 contract")
    previous = ""
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {
            "licence",
            "name",
            "relationship",
            "version",
        }:
            raise SealError("dependency inventory entry is malformed")
        if dependency["relationship"] not in {"direct", "transitive"}:
            raise SealError("dependency inventory relationship is invalid")
        if not all(isinstance(dependency[key], str) and dependency[key] for key in dependency):
            raise SealError("dependency inventory contains an empty metadata value")
        if dependency["name"] <= previous:
            raise SealError("dependency inventory must be uniquely sorted by name")
        previous = dependency["name"]


def _verify_inventory(root: Path, source_revision: str) -> None:
    dependency_path = root / "dependency-inventory.json"
    dependency_inventory = _load_json(dependency_path)
    _verify_dependency_inventory(dependency_inventory)
    document = _load_json(root / "inventory-attestation.json")
    required = {
        "schema_version",
        "source_revision",
        "model_inventory",
        "dependency_inventory",
        "attestation_id",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("inventory attestation is malformed")
    model_path = root / "model-inventory.yaml"
    model = _read_flat_inventory(model_path)
    expected_model = {
        "path": "model-inventory.yaml",
        "sha256": _sha256_file(model_path),
        "inventory_id": model["id"],
        "model_status": "PROPOSED_NOT_TRAINED",
        "checkpoint": None,
        "active_parameters": 0,
        "skylark_trained_parameters": 0,
    }
    expected_dependency = {
        "path": "dependency-inventory.json",
        "sha256": _sha256_file(dependency_path),
        "dependency_count": len(dependency_inventory["dependencies"]),
        "runtime_dependency_count": 0,
    }
    if (
        document.get("schema_version") != "inventory-attestation-v1"
        or document.get("source_revision") != source_revision
        or document.get("model_inventory") != expected_model
        or document.get("dependency_inventory") != expected_dependency
    ):
        raise SealError("inventory attestation does not match its inventories")
    _verify_identity(document, "inventory-attestation", "attestation_id")


def _safe_archive_members(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if any((info.external_attr >> 16) & 0o170000 == 0o120000 for info in infos):
                raise SealError("release artifact contains a symbolic link")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if any(not member.isfile() and not member.isdir() for member in members):
                raise SealError("release artifact contains an unsafe member type")
            names = [member.name for member in members if member.isfile()]
    else:
        raise SealError("release attestation names an unsupported artifact")
    result: set[str] = set()
    for name in names:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name or pure.as_posix() != name:
            raise SealError("release artifact contains an unsafe path")
        if name in result:
            raise SealError("release artifact contains a duplicate path")
        result.add(name)
    return result


def _verify_release_artifacts(root: Path, source_revision: str) -> None:
    document = _load_json(root / "release-artifacts.json")
    required = {
        "schema_version",
        "release_version",
        "source_revision",
        "artifacts",
        "artifact_set_id",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("release artifact attestation is malformed")
    artifacts = document.get("artifacts")
    if (
        document.get("schema_version") != "release-artifacts-v1"
        or document.get("release_version") != RELEASE_VERSION
        or document.get("source_revision") != source_revision
        or not isinstance(artifacts, list)
        or len(artifacts) != 2
    ):
        raise SealError("release artifact attestation is incomplete")
    observed_types: set[str] = set()
    previous = ""
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {
            "media_type",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise SealError("release artifact record is malformed")
        relative = _safe_relative_path(record["path"])
        if not relative.startswith("release-artifacts/") or relative <= previous:
            raise SealError("release artifact paths are invalid or unsorted")
        previous = relative
        path = root / Path(*PurePosixPath(relative).parts)
        if (
            not path.is_file()
            or path.stat().st_size != record["size_bytes"]
            or _sha256_file(path) != record["sha256"]
        ):
            raise SealError("release artifact does not match its attestation")
        expected_media_type = "application/zip" if path.suffix == ".whl" else "application/gzip"
        if record["media_type"] != expected_media_type:
            raise SealError("release artifact media type does not match its filename")
        observed_types.add(record["media_type"])
        _safe_archive_members(path)
    if observed_types != {"application/zip", "application/gzip"}:
        raise SealError("release artifact media types are incomplete")
    _verify_release_layout(
        [root / Path(*PurePosixPath(record["path"]).parts) for record in artifacts]
    )
    _verify_identity(document, "release-artifacts", "artifact_set_id")


def _verify_training_readiness(root: Path, source_revision: str) -> None:
    document = _load_json(root / "training-readiness.json")
    required = {
        "schema_version",
        "inventory_id",
        "source_revision",
        "recommendation",
        "all_gates_satisfied",
        "training_started",
        "weights_downloaded",
        "checkpoint",
        "gates",
        "recommendation_id",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SealError("training-readiness recommendation is malformed")
    gates = document.get("gates")
    if (
        document.get("schema_version") != "trace-001-training-readiness-v1"
        or document.get("inventory_id") != "skylark.lumi.trace"
        or document.get("source_revision") != source_revision
        or document.get("recommendation") != "DO_NOT_BEGIN_TRACE_001"
        or document.get("all_gates_satisfied") is not False
        or document.get("training_started") is not False
        or document.get("weights_downloaded") is not False
        or document.get("checkpoint") is not None
        or not isinstance(gates, list)
        or len(gates) != 6
        or any(not isinstance(gate, dict) or gate.get("satisfied") is not False for gate in gates)
    ):
        raise SealError("TRACE-001 training gate is not fail-closed")
    expected_gates = [
        {
            "gate": "labelled_candidate_ranking_groups",
            "required": 500,
            "observed": 0,
            "satisfied": False,
        },
        {
            "gate": "unrelated_training_repositories",
            "required": 25,
            "observed": 0,
            "satisfied": False,
        },
        {"gate": "repository_disjoint_development_and_holdback_sets", "satisfied": False},
        {"gate": "meaningful_hard_negatives_and_controls", "satisfied": False},
        {"gate": "audited_location_and_reproduction_labels", "satisfied": False},
        {"gate": "adequate_deterministic_candidate_recall", "satisfied": False},
    ]
    if gates != expected_gates:
        raise SealError("TRACE-001 gates are incomplete or inaccurate")
    _verify_identity(document, "training-readiness", "recommendation_id")


def _verify_exact_tree(root: Path, actual: dict[str, Path]) -> None:
    package_manifest = _load_json(root / "evidence-package" / "manifest.json")
    package_records = package_manifest.get("artifacts")
    release_document = _load_json(root / "release-artifacts.json")
    release_records = release_document.get("artifacts")
    if not isinstance(package_records, list) or not isinstance(release_records, list):
        raise SealError("sealed evidence component manifest is malformed")
    package_paths = {
        f"evidence-package/{_safe_relative_path(record.get('path'))}"
        for record in package_records
        if isinstance(record, dict)
    }
    if len(package_paths) != len(package_records):
        raise SealError("evidence package manifest contains a duplicate path")
    release_paths = {
        _safe_relative_path(record.get("path"))
        for record in release_records
        if isinstance(record, dict)
    }
    if len(release_paths) != len(release_records):
        raise SealError("release artifact attestation contains a duplicate path")
    expected = {
        "check-results.json",
        "dependency-inventory.json",
        "evidence-package/manifest.json",
        "inventory-attestation.json",
        "model-inventory.yaml",
        "release-artifacts.json",
        "sandbox-qualification.json",
        "seal-manifest.json",
        "training-readiness.json",
        *package_paths,
        *release_paths,
    }
    if set(actual) != expected:
        raise SealError("sealed evidence tree contains an unexpected or missing component")


def verify_seal(root: Path, *, runtime_source: Path | None = ROOT / "src") -> dict[str, Any]:
    """Verify the complete V0.1 evidence seal and return its manifest."""

    manifest, actual = verify_seal_manifest(root)
    source_revision = manifest["source_revision"]
    _assert_public_safe_json(root)
    _verify_checks(root, source_revision)
    _, receipt = _verify_evidence_package(root, source_revision, runtime_source=runtime_source)
    _verify_qualification(root, source_revision, receipt)
    _verify_inventory(root, source_revision)
    _verify_release_artifacts(root, source_revision)
    _verify_training_readiness(root, source_revision)
    _verify_exact_tree(root, actual)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--installed-runtime",
        action="store_true",
        help="verify contracts with the active environment's installed historical runtime",
    )
    arguments = parser.parse_args(argv)
    try:
        manifest = verify_seal(
            arguments.path,
            runtime_source=None if arguments.installed_runtime else ROOT / "src",
        )
    except (OSError, SealError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"V0.1 evidence verification failed: {exc}", file=sys.stderr)
        return 1
    try:
        display_path = arguments.path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        display_path = arguments.path.name
    print(
        json.dumps(
            {
                "path": display_path,
                "seal_id": manifest["seal_id"],
                "status": "VERIFIED_FOR_REVIEW",
                "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
