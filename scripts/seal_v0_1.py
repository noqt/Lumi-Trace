# SPDX-License-Identifier: Apache-2.0
"""Create the deterministic, public-safe Lumi Trace V0.1 release evidence seal.

This script intentionally performs no Git mutation and no image pull. Run it
from a clean implementation commit after preloading the explicitly named OCI
image. The destination must be absent or an empty reserved directory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "evidence" / "v0.1.0"
RELEASE_VERSION = "0.1.0"
EXPECTED_BRANCH = "codex/lumi-trace-v0-1"

_SOURCE_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_IMAGE_REFERENCE = re.compile(r"(?:[a-z0-9][a-z0-9._/-]*@)?sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_HOST_PATHS = (
    re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|Data|Documents|Windows|Temp)[\\/]"),
    re.compile(r"(?i)(?:^|[^A-Za-z0-9])/(?:home|Users|var/lib|private/var)/"),
    re.compile(r"\\\\[^\\\s]+\\[^\\\s]+"),
)
_CREDENTIALS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
)

REQUIRED_CHECKS = (
    "clean-implementation-commit",
    "owned-fixture-manifest",
    "unit-tests",
    "sandbox-tests",
    "ruff-lint",
    "ruff-format",
    "licences",
    "secrets",
    "dependencies",
    "public-boundary",
    "dependency-vulnerabilities",
    "owned-fixture-confirmed",
    "evidence-package-verification",
    "dependency-inventory",
    "release-build",
    "release-reproducibility",
    "release-metadata",
    "release-artifact-layout",
)


class SealError(RuntimeError):
    """Raised when a V0.1 seal cannot be produced safely."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _identity(prefix: str, value: Mapping[str, Any], omit: Iterable[str] = ()) -> str:
    omitted = set(omit)
    payload = {key: item for key, item in value.items() if key not in omitted}
    return f"{prefix}:{_sha256_bytes(_canonical_bytes(payload)).removeprefix('sha256:')}"


def _write_json(path: Path, value: Any) -> None:
    if path.exists():
        raise SealError(f"refusing to overwrite seal output: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    path.write_text(rendered, encoding="utf-8", newline="\n")


def _load_json(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> Any:
    if path.stat().st_size > max_bytes:
        raise SealError(f"JSON evidence exceeds the byte limit: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SealError(f"cannot read JSON evidence: {path.name}") from exc


def _git_text(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise SealError(f"Git precondition failed: {' '.join(arguments)}")
    return result.stdout.strip()


def _validate_source_state(source_revision: str) -> int:
    if _SOURCE_REVISION.fullmatch(source_revision) is None:
        raise SealError("--source-revision must be a lowercase immutable Git object ID")
    if _git_text("rev-parse", "HEAD") != source_revision:
        raise SealError("--source-revision does not match the checked-out implementation commit")
    if _git_text("symbolic-ref", "--quiet", "--short", "HEAD") != EXPECTED_BRANCH:
        raise SealError(f"the seal must be produced on {EXPECTED_BRANCH}")
    if _git_text("status", "--porcelain=v1", "--untracked-files=all"):
        raise SealError("the implementation worktree must be clean before sealing")
    commit_epoch = _git_text("show", "-s", "--format=%ct", source_revision)
    if not commit_epoch.isdecimal():
        raise SealError("the implementation commit does not have a valid source epoch")
    return int(commit_epoch)


def _validate_image_reference(image: str) -> None:
    if _IMAGE_REFERENCE.fullmatch(image) is None:
        raise SealError(
            "--image must be a lowercase local digest reference without credentials or a tag"
        )


def _validate_destination(output: Path) -> bool:
    evidence_directory = ROOT / "evidence"
    if evidence_directory.is_symlink():
        raise SealError("repository evidence directory must not be a symbolic link")
    evidence_root = evidence_directory.resolve(strict=False)
    try:
        evidence_root.relative_to(ROOT.resolve(strict=True))
    except ValueError as exc:
        raise SealError("repository evidence directory resolves outside the repository") from exc
    resolved = output.resolve(strict=False)
    try:
        resolved.relative_to(evidence_root)
    except ValueError as exc:
        raise SealError("seal output must be inside the repository evidence directory") from exc
    if resolved == evidence_root:
        raise SealError("seal output must be a versioned child of the evidence directory")
    if output.is_symlink():
        raise SealError("seal output must not be a symbolic link")
    if not output.exists():
        return False
    if not output.is_dir() or any(output.iterdir()):
        raise SealError("seal output already exists and is not an empty reserved directory")
    return True


def _safe_environment(*, image: str, source_epoch: int) -> dict[str, str]:
    environment = os.environ.copy()
    secret_name = re.compile(
        r"(?:^|_)(?:API_KEY|AUTH|CREDENTIALS?|PASSWD|PASSWORD|PRIVATE_KEY|SECRET|SESSION|TOKEN)(?:_|$)",
        re.IGNORECASE,
    )
    for name in tuple(environment):
        if secret_name.search(name):
            environment.pop(name, None)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "LUMI_TRACE_TEST_IMAGE": image,
            "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": os.pathsep.join(
                filter(None, (str(ROOT / "src"), environment.get("PYTHONPATH", "")))
            ),
            "SOURCE_DATE_EPOCH": str(source_epoch),
            "TZ": "UTC",
        }
    )
    return environment


def _run(command: list[str], *, check_id: str, environment: Mapping[str, str]) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=dict(environment),
        check=False,
        capture_output=True,
        timeout=900,
    )
    if result.returncode:
        raise SealError(f"release check failed: {check_id} (exit {result.returncode})")


def _verify_owned_fixture_manifest() -> None:
    manifest_path = ROOT / "tests" / "fixtures" / "fixture-manifest.json"
    manifest = _load_json(manifest_path, max_bytes=1024 * 1024)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "fixture-manifest-v1":
        raise SealError("owned fixture manifest has an invalid schema")
    if (
        manifest.get("provenance") != "Skylark.AI-authored synthetic test material"
        or manifest.get("licence") != "Apache-2.0"
        or manifest.get("third_party_repository_contents") is not False
    ):
        raise SealError("owned fixture provenance is not releasable")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise SealError("owned fixture manifest entries are invalid")
    declared: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise SealError("owned fixture manifest entry is invalid")
        relative = entry["path"]
        if not isinstance(relative, str) or PurePosixPath(relative).as_posix() != relative:
            raise SealError("owned fixture manifest path is invalid")
        path = ROOT / Path(*PurePosixPath(relative).parts)
        if (
            not path.is_file()
            or path.is_symlink()
            or _sha256_file(path).removeprefix("sha256:") != entry["sha256"]
        ):
            raise SealError(f"owned fixture does not match its manifest: {relative}")
        declared.append(relative)
    if declared != sorted(set(declared)):
        raise SealError("owned fixture manifest paths must be unique and sorted")
    actual = sorted(
        path.relative_to(ROOT).as_posix()
        for base in (ROOT / "tests" / "data", ROOT / "tests" / "fixtures")
        for path in base.rglob("*")
        if path.is_file() and path != manifest_path and "__pycache__" not in path.parts
    )
    if actual != declared:
        raise SealError("owned fixture manifest does not account for every fixture file")


def _read_flat_inventory(path: Path) -> dict[str, object]:
    """Read the intentionally flat Micro-Model Inventory without a YAML dependency."""

    result: dict[str, object] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, raw = stripped.partition(":")
        if not separator or not key or key in result:
            raise SealError("model-inventory.yaml must remain a flat unique-key mapping")
        value: object
        if raw.strip() == "null":
            value = None
        elif raw.strip() in {"true", "false"}:
            value = raw.strip() == "true"
        elif raw.strip().isdigit():
            value = int(raw.strip())
        else:
            value = raw.strip()
        result[key] = value
    required = {
        "schema_version": "model-inventory-v1",
        "id": "skylark.lumi.trace",
        "model_status": "PROPOSED_NOT_TRAINED",
        "checkpoint": None,
        "active_parameters": 0,
        "skylark_trained_parameters": 0,
        "api_keys_required": False,
        "hosted_inference": False,
    }
    if any(result.get(key) != expected for key, expected in required.items()):
        raise SealError("Micro-Model Inventory violates the zero-weight V0.1 contract")
    return result


def _require_bundle_source_revision(bundle: object, expected: str) -> None:
    if not isinstance(bundle, dict) or not isinstance(bundle.get("tool"), dict):
        raise SealError("owned-fixture evidence bundle has no tool identity")
    if bundle["tool"].get("source_revision") != expected:
        raise SealError("owned-fixture evidence has the wrong source revision")


def _archive_paths(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            paths = archive.namelist()
            if any(
                info.is_dir() or info.external_attr >> 16 & 0o170000 == 0o120000
                for info in archive.infolist()
            ):
                raise SealError("wheel contains a directory entry or symbolic link")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if any(not member.isfile() and not member.isdir() for member in members):
                raise SealError("source distribution contains a non-file archive member")
            paths = [member.name for member in members if member.isfile()]
    else:
        raise SealError("unexpected release artifact type")
    normalized: set[str] = set()
    for name in paths:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name or name != pure.as_posix():
            raise SealError("release artifact contains an unsafe member path")
        if name in normalized:
            raise SealError("release artifact contains a duplicate member path")
        normalized.add(name)
    return normalized


def _normalize_source_distribution(path: Path, source_epoch: int) -> None:
    """Rewrite an sdist with canonical TAR and gzip metadata."""

    records: list[tuple[str, bool, bool, bytes]] = []
    names: set[str] = set()
    total_bytes = 0
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 2_000:
            raise SealError("source distribution exceeds the member limit")
        for member in members:
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in member.name
                or pure.as_posix() != member.name
                or member.name in names
                or not (member.isfile() or member.isdir())
            ):
                raise SealError("source distribution contains an unsafe member")
            names.add(member.name)
            content = b""
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SealError("source distribution file cannot be read")
                content = extracted.read()
                total_bytes += len(content)
                if total_bytes > 256 * 1024 * 1024:
                    raise SealError("source distribution exceeds the byte limit")
            records.append((member.name, member.isdir(), bool(member.mode & 0o111), content))

    temporary = path.with_name(f".{path.name}.normalized.tmp")
    if temporary.exists():
        raise SealError("source-distribution normalization target already exists")
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=source_epoch
            ) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output,
        ):
            for name, is_directory, executable, content in sorted(records):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
                member.mode = 0o755 if is_directory or executable else 0o644
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = source_epoch
                member.size = 0 if is_directory else len(content)
                output.addfile(member, None if is_directory else io.BytesIO(content))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _normalize_release_build(directory: Path, source_epoch: int) -> None:
    artifacts = sorted(path for path in directory.iterdir() if path.is_file())
    source_distributions = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(source_distributions) != 1:
        raise SealError("release build must contain exactly one source distribution")
    _normalize_source_distribution(source_distributions[0], source_epoch)


def _verify_release_layout(artifacts: list[Path]) -> None:
    wheel = next((path for path in artifacts if path.suffix == ".whl"), None)
    source = next((path for path in artifacts if path.name.endswith(".tar.gz")), None)
    if wheel is None or source is None or len(artifacts) != 2:
        raise SealError("release build must produce exactly one wheel and one source distribution")
    wheel_paths = _archive_paths(wheel)
    wheel_required_suffixes = {
        ".dist-info/licenses/LICENSE",
        ".dist-info/licenses/NOTICE",
        "share/skylark-lumi-trace/THIRD_PARTY_NOTICES.md",
        "share/skylark-lumi-trace/model-inventory.yaml",
        "share/skylark-lumi-trace/docs/MODEL_CARD.md",
        "share/skylark-lumi-trace/schemas/evidence-bundle-v1.json",
        "lumi_trace/cli.py",
    }
    for suffix in wheel_required_suffixes:
        if not any(name.endswith(suffix) for name in wheel_paths):
            raise SealError(f"wheel is missing required release content: {suffix}")
    source_paths = _archive_paths(source)
    source_required_suffixes = {
        "/CHANGELOG.md",
        "/LICENSE",
        "/NOTICE",
        "/THIRD_PARTY_NOTICES.md",
        "/model-inventory.yaml",
        "/scripts/seal_v0_1.py",
        "/scripts/verify_v0_1_evidence.py",
        "/tests/fixtures/fixture-manifest.json",
    }
    for suffix in source_required_suffixes:
        if not any(name.endswith(suffix) for name in source_paths):
            raise SealError(f"source distribution is missing required release content: {suffix}")


def _release_artifacts(
    build_directory: Path,
    staging: Path,
    source_revision: str,
) -> tuple[dict[str, Any], list[Path]]:
    artifacts = sorted(
        (path for path in build_directory.iterdir() if path.is_file()), key=lambda item: item.name
    )
    _verify_release_layout(artifacts)
    destination = staging / "release-artifacts"
    destination.mkdir()
    records: list[dict[str, object]] = []
    copied: list[Path] = []
    for source in artifacts:
        target = destination / source.name
        if target.exists():
            raise SealError("duplicate release artifact name")
        shutil.copyfile(source, target)
        copied.append(target)
        records.append(
            {
                "media_type": (
                    "application/zip" if source.suffix == ".whl" else "application/gzip"
                ),
                "path": f"release-artifacts/{source.name}",
                "sha256": _sha256_file(target),
                "size_bytes": target.stat().st_size,
            }
        )
    document: dict[str, Any] = {
        "schema_version": "release-artifacts-v1",
        "release_version": RELEASE_VERSION,
        "source_revision": source_revision,
        "artifacts": records,
    }
    document["artifact_set_id"] = _identity("release-artifacts", document)
    return document, copied


def _sandbox_qualification(
    package: Path,
    source_revision: str,
) -> dict[str, Any]:
    bundle = _load_json(package / "evidence-bundle.json")
    receipt = _load_json(package / "reproduction-receipt.json")
    package_manifest = _load_json(package / "manifest.json")
    if not isinstance(bundle, dict) or not isinstance(receipt, dict):
        raise SealError("owned-fixture evidence package is malformed")
    if bundle.get("classification", {}).get("outcome") != "CONFIRMED":
        raise SealError("owned fixture did not produce CONFIRMED evidence")
    _require_bundle_source_revision(bundle, source_revision)
    if receipt.get("status") != "COMPLETED" or receipt.get("attempted") is not True:
        raise SealError("owned-fixture reproduction did not complete")
    sandbox = receipt.get("sandbox")
    qualification = receipt.get("qualification")
    if (
        not isinstance(sandbox, dict)
        or sandbox.get("qualified") is not True
        or not isinstance(qualification, dict)
        or qualification.get("qualified") is not True
    ):
        raise SealError("sandbox did not produce a positive qualification attestation")
    document: dict[str, Any] = {
        "schema_version": "sandbox-qualification-evidence-v1",
        "source_revision": source_revision,
        "evidence_package_manifest_id": package_manifest.get("manifest_id"),
        "receipt_id": receipt.get("receipt_id"),
        "policy_id": receipt.get("policy_id"),
        "qualification_id": receipt.get("qualification_id"),
        "image_reference_sha256": sandbox.get("image_reference_sha256"),
        "image_id": sandbox.get("image_id"),
        "network_mode": sandbox.get("network_mode"),
        "source_mount": sandbox.get("source_mount"),
        "classification": "CONFIRMED",
        "qualification": qualification,
    }
    if any(
        not isinstance(document.get(key), str) or _SHA256.fullmatch(str(document[key])) is None
        for key in ("image_reference_sha256", "image_id", "qualification_id")
    ):
        raise SealError("sandbox qualification identities are invalid")
    document["attestation_id"] = _identity("sandbox-qualification", document)
    return document


def _training_readiness(source_revision: str) -> dict[str, Any]:
    gates = [
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
    document: dict[str, Any] = {
        "schema_version": "trace-001-training-readiness-v1",
        "inventory_id": "skylark.lumi.trace",
        "source_revision": source_revision,
        "recommendation": "DO_NOT_BEGIN_TRACE_001",
        "all_gates_satisfied": False,
        "training_started": False,
        "weights_downloaded": False,
        "checkpoint": None,
        "gates": gates,
    }
    document["recommendation_id"] = _identity("training-readiness", document)
    return document


def _inventory_attestation(
    staging: Path,
    dependency_inventory: dict[str, Any],
    source_revision: str,
) -> dict[str, Any]:
    source_model_path = ROOT / "model-inventory.yaml"
    model_path = staging / "model-inventory.yaml"
    if model_path.exists():
        raise SealError("refusing to overwrite the sealed model inventory snapshot")
    shutil.copyfile(source_model_path, model_path)
    model = _read_flat_inventory(model_path)
    dependency_path = staging / "dependency-inventory.json"
    dependencies = dependency_inventory.get("dependencies")
    if not isinstance(dependencies, list):
        raise SealError("resolved dependency inventory is malformed")
    document: dict[str, Any] = {
        "schema_version": "inventory-attestation-v1",
        "source_revision": source_revision,
        "model_inventory": {
            "path": "model-inventory.yaml",
            "sha256": _sha256_file(model_path),
            "inventory_id": model["id"],
            "model_status": model["model_status"],
            "checkpoint": model["checkpoint"],
            "active_parameters": model["active_parameters"],
            "skylark_trained_parameters": model["skylark_trained_parameters"],
        },
        "dependency_inventory": {
            "path": "dependency-inventory.json",
            "sha256": _sha256_file(dependency_path),
            "dependency_count": len(dependencies),
            "runtime_dependency_count": dependency_inventory.get("runtime_dependency_count"),
        },
    }
    document["attestation_id"] = _identity("inventory-attestation", document)
    return document


def _assert_public_safe_json(root: Path) -> None:
    for path in sorted(
        item for item in root.rglob("*") if item.suffix.casefold() in {".json", ".sarif"}
    ):
        text = path.read_text(encoding="utf-8")
        if any(pattern.search(text) for pattern in (*_HOST_PATHS, *_CREDENTIALS)):
            raise SealError(
                f"public evidence contains host-path or credential material: {path.name}"
            )
        value = json.loads(text)
        stack: list[Any] = [value]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                for key, item in current.items():
                    folded = key.casefold()
                    if any(part in folded for part in ("timestamp", "created_at", "generated_at")):
                        raise SealError(f"public evidence contains a timestamp field: {path.name}")
                    if (
                        folded.startswith("duration")
                        and item is not None
                        and not (
                            folded == "duration_measurement"
                            and item == "not_recorded_for_determinism"
                        )
                    ):
                        raise SealError(
                            f"public evidence contains a recorded duration: {path.name}"
                        )
                    stack.append(item)
            elif isinstance(current, list):
                stack.extend(current)
            elif isinstance(current, str) and any(
                pattern.search(current) for pattern in (*_HOST_PATHS, *_CREDENTIALS)
            ):
                raise SealError(
                    f"public evidence contains host-path or credential material: {path.name}"
                )


def _manifest_files(root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise SealError("seal tree must not contain symbolic links")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "seal-manifest.json":
            continue
        records.append(
            {"path": relative, "sha256": _sha256_file(path), "size_bytes": path.stat().st_size}
        )
    return records


def _seal_manifest(staging: Path, source_revision: str) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "lumi-trace-v0.1-seal-manifest-v1",
        "release_version": RELEASE_VERSION,
        "source_revision": source_revision,
        "files": _manifest_files(staging),
    }
    document["seal_id"] = _identity("lumi-trace-v0.1-seal", document)
    return document


def create_seal(*, output: Path, image: str, source_revision: str) -> dict[str, Any]:
    """Run the V0.1 gates and atomically create a fresh evidence seal."""

    _validate_image_reference(image)
    reserved_empty_output = _validate_destination(output)
    source_epoch = _validate_source_state(source_revision)
    _verify_owned_fixture_manifest()
    environment = _safe_environment(image=image, source_epoch=source_epoch)

    commands = (
        ("unit-tests", [sys.executable, "-m", "pytest", "-q", "-m", "not docker"]),
        ("sandbox-tests", [sys.executable, "-m", "pytest", "-q", "-m", "docker"]),
        ("ruff-lint", [sys.executable, "-m", "ruff", "check", "."]),
        ("ruff-format", [sys.executable, "-m", "ruff", "format", "--check", "."]),
        ("licences", [sys.executable, "scripts/check_licenses.py"]),
        ("secrets", [sys.executable, "scripts/check_secrets.py"]),
        ("dependencies", [sys.executable, "scripts/check_dependencies.py"]),
        ("public-boundary", [sys.executable, "scripts/check_public_boundary.py"]),
        (
            "dependency-vulnerabilities",
            [sys.executable, "-m", "pip_audit", "--skip-editable", "--progress-spinner", "off"],
        ),
    )
    for check_id, command in commands:
        _run(command, check_id=check_id, environment=environment)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".lumi-trace-v0.1-", dir=ROOT.parent) as temporary:
        temporary_root = Path(temporary)
        staging = temporary_root / "seal"
        staging.mkdir()
        package = staging / "evidence-package"

        _run(
            [
                sys.executable,
                "-m",
                "lumi_trace",
                "trace",
                "--finding",
                "tests/data/manual-finding.json",
                "--finding-format",
                "manual",
                "--repository",
                "tests/fixtures/demo-repository",
                "--output",
                str(package),
                "--plan",
                "tests/data/reproduction-plan.json",
                "--image",
                image,
                "--top-k",
                "20",
                "--source-revision",
                source_revision,
            ],
            check_id="owned-fixture-confirmed",
            environment=environment,
        )
        _run(
            [sys.executable, "-m", "lumi_trace", "verify", str(package)],
            check_id="evidence-package-verification",
            environment=environment,
        )

        dependency_path = staging / "dependency-inventory.json"
        _run(
            [
                sys.executable,
                "scripts/dependency_inventory.py",
                "--output",
                str(dependency_path),
            ],
            check_id="dependency-inventory",
            environment=environment,
        )
        dependency_inventory = _load_json(dependency_path)
        if not isinstance(dependency_inventory, dict):
            raise SealError("dependency inventory tool emitted a non-object")

        build_directory = temporary_root / "dist"
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(build_directory),
            ],
            check_id="release-build",
            environment=environment,
        )
        _normalize_release_build(build_directory, source_epoch)
        rebuild_directory = temporary_root / "dist-rebuilt"
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(rebuild_directory),
            ],
            check_id="release-reproducibility",
            environment=environment,
        )
        _normalize_release_build(rebuild_directory, source_epoch)
        first_build = {
            path.name: (path.stat().st_size, _sha256_file(path))
            for path in build_directory.iterdir()
            if path.is_file()
        }
        second_build = {
            path.name: (path.stat().st_size, _sha256_file(path))
            for path in rebuild_directory.iterdir()
            if path.is_file()
        }
        if first_build != second_build:
            raise SealError("release artifacts are not byte-reproducible from the source commit")
        artifacts = sorted(path for path in build_directory.iterdir() if path.is_file())
        _run(
            [sys.executable, "-m", "twine", "check", *map(str, artifacts)],
            check_id="release-metadata",
            environment=environment,
        )
        release_document, _ = _release_artifacts(build_directory, staging, source_revision)
        _write_json(staging / "release-artifacts.json", release_document)
        _write_json(
            staging / "sandbox-qualification.json",
            _sandbox_qualification(package, source_revision),
        )
        _write_json(
            staging / "inventory-attestation.json",
            _inventory_attestation(staging, dependency_inventory, source_revision),
        )
        _write_json(staging / "training-readiness.json", _training_readiness(source_revision))

        check_results: dict[str, Any] = {
            "schema_version": "v0.1-release-check-results-v1",
            "release_version": RELEASE_VERSION,
            "source_revision": source_revision,
            "overall_status": "PASS",
            "checks": [{"id": check_id, "status": "PASS"} for check_id in REQUIRED_CHECKS],
        }
        check_results["check_set_id"] = _identity("release-checks", check_results)
        _write_json(staging / "check-results.json", check_results)

        _assert_public_safe_json(staging)
        manifest = _seal_manifest(staging, source_revision)
        _write_json(staging / "seal-manifest.json", manifest)

        # Verify the staged bytes using the standalone verifier before publishing
        # them into the reserved evidence location.
        _run(
            [sys.executable, "scripts/verify_v0_1_evidence.py", str(staging)],
            check_id="seal-verification",
            environment=environment,
        )
        if output.exists():
            if not reserved_empty_output or any(output.iterdir()):
                raise SealError("seal output changed while release checks were running")
            output.rmdir()
        os.replace(staging, output)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="preloaded immutable local image digest")
    parser.add_argument("--source-revision", required=True, help="implementation commit object ID")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    try:
        manifest = create_seal(
            output=arguments.output,
            image=arguments.image,
            source_revision=arguments.source_revision,
        )
    except (OSError, SealError, subprocess.SubprocessError) as exc:
        print(f"V0.1 seal failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "output": arguments.output.relative_to(ROOT).as_posix(),
                "seal_id": manifest["seal_id"],
                "status": "SEALED_FOR_REVIEW",
                "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
