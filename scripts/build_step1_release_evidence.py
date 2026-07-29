# SPDX-License-Identifier: Apache-2.0
"""Inspect prebuilt Step 1 distributions and emit bounded release evidence."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "out" / "step1-release-evidence"
TOOL_VERSION = "1"
MAX_MEMBERS = 5_000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
SOURCE_REVISION = re.compile(r"[0-9a-f]{40}")

WEIGHT_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".gguf",
    ".h5",
    ".joblib",
    ".npy",
    ".npz",
    ".onnx",
    ".pickle",
    ".pkl",
    ".pt",
    ".pth",
    ".safetensors",
}
CACHE_PARTS = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}
PRIVATE_PATH_PARTS = {
    "checkpoints",
    "customer-data",
    "customer-evidence",
    "cybergym",
    "evidence",
    "holdback",
    "private-evidence",
    "training-data",
}
EVALUATOR_PATH_PATTERNS = (
    re.compile(r"(?:^|/)(?:eval|trace_eval)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)docs/build-briefs(?:/|$)", re.IGNORECASE),
    re.compile(
        r"(?:^|/)docs/(?:"
        r"model_card|trace_001[^/]*|trace_eval[^/]*|trace_ir[^/]*|"
        r"training_readiness|v0\.[234][^/]*|[^/]*assurance[^/]*|"
        r"[^/]*shadow_pilot[^/]*"
        r")\.md$",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|/)scripts/(?:"
        r"build_v0_|qualify_v0_|record_v0_|run_trace_001|run_v0_|"
        r"screen_v0_|seal_v0_[234]|train_v0_|verify_v0_[234]"
        r")",
        re.IGNORECASE,
    ),
)
SEPARATELY_LICENSED_PATH_PATTERNS = (
    re.compile(
        r"(?:^|/)examples/public-ghsa-8359-h9fx-j6v9(?:/|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|/)share/skylark-lumi-trace/examples/"
        r"public-ghsa-8359-h9fx-j6v9(?:/|$)",
        re.IGNORECASE,
    ),
)
PAYLOAD_PATTERNS = (
    (
        "absolute Windows drive path",
        re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/]"),
    ),
    (
        "absolute user-home path",
        re.compile(rb"(?<![A-Za-z0-9])/(?:home|Users)/[A-Za-z0-9._-]+/"),
    ),
    (
        "UNC host path",
        re.compile(rb"(?<![\\])\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+"),
    ),
    (
        "private key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "AWS access key",
        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "GitHub token",
        re.compile(rb"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "Slack token",
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
)


class ReleaseEvidenceError(ValueError):
    """Raised when an artifact cannot cross the Step 1 release boundary."""


@dataclass(frozen=True)
class ArchiveMember:
    """A normalized regular-file member and its disclosure-safe inventory."""

    path: str
    logical_path: str
    size_bytes: int
    sha256: str

    def record(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": f"sha256:{self.sha256}",
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class PackageMetadata:
    """The release metadata needed for pair and SBOM verification."""

    name: str
    version: str
    license_expression: str
    requires_python: str | None
    runtime_requirements: tuple[str, ...]
    optional_requirements: tuple[str, ...]

    def record(self) -> dict[str, object]:
        return {
            "license_expression": self.license_expression,
            "name": self.name,
            "optional_requirement_count": len(self.optional_requirements),
            "requires_python": self.requires_python,
            "runtime_requirements": list(self.runtime_requirements),
            "version": self.version,
        }


@dataclass(frozen=True)
class ArtifactInspection:
    """A verified artifact plus its bounded inventory."""

    artifact_type: str
    filename: str
    media_type: str
    sha256: str
    size_bytes: int
    members: tuple[ArchiveMember, ...]
    metadata: PackageMetadata

    def record(self) -> dict[str, object]:
        return {
            "artifact_type": self.artifact_type,
            "filename": self.filename,
            "media_type": self.media_type,
            "member_count": len(self.members),
            "members": [member.record() for member in self.members],
            "metadata": self.metadata.record(),
            "sha256": f"sha256:{self.sha256}",
            "size_bytes": self.size_bytes,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _safe_member_path(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or pure.as_posix() != name
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ReleaseEvidenceError(f"unsafe archive member path: {name!r}")
    return pure


def _logical_sdist_path(name: str, root: str) -> str:
    pure = _safe_member_path(name)
    if not pure.parts or pure.parts[0] != root:
        raise ReleaseEvidenceError("sdist members do not share one package root")
    if len(pure.parts) == 1:
        return ""
    return PurePosixPath(*pure.parts[1:]).as_posix()


def _check_member_policy(logical_name: str) -> None:
    if not logical_name:
        return
    pure = _safe_member_path(logical_name)
    lowered = tuple(part.casefold() for part in pure.parts)
    if set(lowered) & CACHE_PARTS:
        raise ReleaseEvidenceError(f"cache content is forbidden: {logical_name}")
    if set(lowered) & PRIVATE_PATH_PARTS:
        raise ReleaseEvidenceError(f"private/evidence content is forbidden: {logical_name}")
    if pure.suffix.casefold() in WEIGHT_SUFFIXES:
        raise ReleaseEvidenceError(f"model/weight artifact is forbidden: {logical_name}")
    if any(pattern.search(logical_name) for pattern in EVALUATOR_PATH_PATTERNS):
        raise ReleaseEvidenceError(f"evaluator-only content is forbidden: {logical_name}")
    if any(pattern.search(logical_name) for pattern in SEPARATELY_LICENSED_PATH_PATTERNS):
        raise ReleaseEvidenceError(
            f"separately licensed review-bundle content is forbidden: {logical_name}"
        )


def _check_payload(logical_name: str, payload: bytes) -> None:
    for description, pattern in PAYLOAD_PATTERNS:
        if pattern.search(payload):
            raise ReleaseEvidenceError(f"{description} found in artifact member: {logical_name}")
    if PurePosixPath(logical_name).suffix.casefold() != ".json":
        return
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(value, dict):
        return
    serialized_fields = {"state_dict", "tensors"}
    if isinstance(value.get("weights"), dict | list) or serialized_fields & value.keys():
        raise ReleaseEvidenceError(
            f"serialized model/checkpoint content is forbidden: {logical_name}"
        )


def _metadata_from_bytes(payload: bytes, *, member_name: str) -> PackageMetadata:
    message = BytesParser(policy=policy.default).parsebytes(payload)
    name = message.get("Name")
    version = message.get("Version")
    license_expression = message.get("License-Expression") or message.get("License")
    if not name or not version or not license_expression:
        raise ReleaseEvidenceError(f"package metadata is incomplete: {member_name}")
    requirements = tuple(sorted(message.get_all("Requires-Dist", [])))
    runtime = tuple(
        requirement
        for requirement in requirements
        if "extra ==" not in requirement and "extra==" not in requirement
    )
    optional = tuple(requirement for requirement in requirements if requirement not in runtime)
    return PackageMetadata(
        name=str(name),
        version=str(version),
        license_expression=str(license_expression),
        requires_python=message.get("Requires-Python"),
        runtime_requirements=runtime,
        optional_requirements=optional,
    )


def _bounded_payload(source: BinaryIO, *, name: str, declared_size: int) -> bytes:
    if declared_size < 0 or declared_size > MAX_MEMBER_BYTES:
        raise ReleaseEvidenceError(f"archive member exceeds the size bound: {name}")
    payload = source.read(MAX_MEMBER_BYTES + 1)
    if len(payload) != declared_size or len(payload) > MAX_MEMBER_BYTES:
        raise ReleaseEvidenceError(f"archive member size is inconsistent: {name}")
    return payload


def _inspect_wheel(path: Path) -> ArtifactInspection:
    if not path.is_file() or path.suffix.casefold() != ".whl":
        raise ReleaseEvidenceError("wheel path must name one existing .whl file")
    seen: set[str] = set()
    members: list[ArchiveMember] = []
    metadata_payloads: list[tuple[str, bytes]] = []
    total_bytes = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ReleaseEvidenceError("wheel exceeds the member bound")
            for info in infos:
                name = info.filename
                _safe_member_path(name.rstrip("/"))
                if name in seen:
                    raise ReleaseEvidenceError(f"duplicate wheel member: {name}")
                seen.add(name)
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == 0o120000:
                    raise ReleaseEvidenceError(f"wheel symlink is forbidden: {name}")
                if info.is_dir():
                    continue
                _check_member_policy(name)
                with archive.open(info) as source:
                    payload = _bounded_payload(
                        source,
                        name=name,
                        declared_size=info.file_size,
                    )
                total_bytes += len(payload)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ReleaseEvidenceError("wheel exceeds the expanded-byte bound")
                _check_payload(name, payload)
                if name.endswith(".dist-info/METADATA"):
                    metadata_payloads.append((name, payload))
                members.append(
                    ArchiveMember(
                        path=name,
                        logical_path=name,
                        size_bytes=len(payload),
                        sha256=_sha256_bytes(payload),
                    )
                )
    except zipfile.BadZipFile as exc:
        raise ReleaseEvidenceError("wheel is not a valid ZIP archive") from exc
    if len(metadata_payloads) != 1:
        raise ReleaseEvidenceError("wheel must contain exactly one dist-info/METADATA")
    metadata = _metadata_from_bytes(
        metadata_payloads[0][1],
        member_name=metadata_payloads[0][0],
    )
    return ArtifactInspection(
        artifact_type="wheel",
        filename=path.name,
        media_type="application/vnd.python.wheel+zip",
        sha256=_sha256_file(path),
        size_bytes=path.stat().st_size,
        members=tuple(sorted(members, key=lambda member: member.path)),
        metadata=metadata,
    )


def _inspect_sdist(path: Path) -> ArtifactInspection:
    if not path.is_file() or not path.name.casefold().endswith(".tar.gz"):
        raise ReleaseEvidenceError("sdist path must name one existing .tar.gz file")
    seen: set[str] = set()
    members: list[ArchiveMember] = []
    metadata_payloads: list[tuple[str, bytes]] = []
    total_bytes = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            entries = archive.getmembers()
            if len(entries) > MAX_MEMBERS:
                raise ReleaseEvidenceError("sdist exceeds the member bound")
            roots = {
                _safe_member_path(member.name).parts[0]
                for member in entries
                if _safe_member_path(member.name).parts
            }
            if len(roots) != 1:
                raise ReleaseEvidenceError("sdist must have exactly one package root")
            root = next(iter(roots))
            for entry in entries:
                name = entry.name
                logical_name = _logical_sdist_path(name, root)
                if name in seen:
                    raise ReleaseEvidenceError(f"duplicate sdist member: {name}")
                seen.add(name)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ReleaseEvidenceError(f"non-regular sdist member is forbidden: {name}")
                _check_member_policy(logical_name)
                source = archive.extractfile(entry)
                if source is None:
                    raise ReleaseEvidenceError(f"sdist member cannot be read: {name}")
                with source:
                    payload = _bounded_payload(
                        source,
                        name=name,
                        declared_size=entry.size,
                    )
                total_bytes += len(payload)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ReleaseEvidenceError("sdist exceeds the expanded-byte bound")
                _check_payload(logical_name, payload)
                if logical_name == "PKG-INFO":
                    metadata_payloads.append((name, payload))
                members.append(
                    ArchiveMember(
                        path=name,
                        logical_path=logical_name,
                        size_bytes=len(payload),
                        sha256=_sha256_bytes(payload),
                    )
                )
    except (gzip.BadGzipFile, tarfile.TarError) as exc:
        raise ReleaseEvidenceError("sdist is not a valid gzip-compressed TAR archive") from exc
    if len(metadata_payloads) != 1:
        raise ReleaseEvidenceError("sdist must contain exactly one root PKG-INFO")
    metadata = _metadata_from_bytes(
        metadata_payloads[0][1],
        member_name=metadata_payloads[0][0],
    )
    return ArtifactInspection(
        artifact_type="sdist",
        filename=path.name,
        media_type="application/gzip",
        sha256=_sha256_file(path),
        size_bytes=path.stat().st_size,
        members=tuple(sorted(members, key=lambda member: member.path)),
        metadata=metadata,
    )


def inspect_release_artifacts(wheel: Path, sdist: Path) -> tuple[ArtifactInspection, ...]:
    """Inspect and cross-check one wheel/sdist pair without changing either."""

    wheel_resolved = wheel.resolve(strict=True)
    sdist_resolved = sdist.resolve(strict=True)
    if wheel_resolved == sdist_resolved:
        raise ReleaseEvidenceError("wheel and sdist must be different files")
    inspections = (_inspect_wheel(wheel_resolved), _inspect_sdist(sdist_resolved))
    wheel_metadata, sdist_metadata = (item.metadata for item in inspections)
    if wheel_metadata != sdist_metadata:
        raise ReleaseEvidenceError("wheel and sdist package metadata differ")
    if wheel_metadata.license_expression != "Apache-2.0":
        raise ReleaseEvidenceError("Step 1 package metadata must declare Apache-2.0")
    if wheel_metadata.runtime_requirements:
        raise ReleaseEvidenceError(
            "Step 1 package declares runtime dependencies: "
            + ", ".join(wheel_metadata.runtime_requirements)
        )
    return inspections


def verify_canonical_sdist(path: Path, *, source_date_epoch: int) -> None:
    """Verify the release sdist uses the documented canonical TAR+gzip profile."""

    if not 0 <= source_date_epoch <= 0xFFFFFFFF:
        raise ReleaseEvidenceError("source date epoch is outside the gzip timestamp range")
    resolved = path.resolve(strict=True)
    with resolved.open("rb") as source:
        header = source.read(10)
    if (
        len(header) != 10
        or header[:3] != b"\x1f\x8b\x08"
        or header[3] != 0
        or int.from_bytes(header[4:8], "little") != source_date_epoch
        or header[9] != 255
    ):
        raise ReleaseEvidenceError("sdist gzip header is not canonical")
    try:
        with tarfile.open(resolved, mode="r:gz") as archive:
            members = archive.getmembers()
    except (gzip.BadGzipFile, tarfile.TarError) as exc:
        raise ReleaseEvidenceError("sdist is not a valid gzip-compressed TAR archive") from exc
    names = [member.name for member in members]
    if names != sorted(names, key=lambda name: name.encode("utf-8")):
        raise ReleaseEvidenceError("sdist members are not in canonical path order")
    for member in members:
        expected_modes = {0o755} if member.isdir() else {0o644, 0o755}
        if (
            member.mtime != source_date_epoch
            or member.uid != 0
            or member.gid != 0
            or member.uname
            or member.gname
            or member.mode not in expected_modes
            or member.pax_headers
        ):
            raise ReleaseEvidenceError(f"sdist member metadata is not canonical: {member.name}")


def _spdx_document(
    inspections: tuple[ArtifactInspection, ...],
    *,
    source_revision: str,
    created_at: str,
) -> dict[str, object]:
    metadata = inspections[0].metadata
    normalized_name = re.sub(r"[-_.]+", "-", metadata.name).lower()
    namespace = f"https://github.com/noqt/Lumi-Trace/spdx/{metadata.version}/{source_revision}"
    packages = []
    relationships = []
    for inspection in inspections:
        spdx_id = f"SPDXRef-Package-{inspection.artifact_type}"
        packages.append(
            {
                "SPDXID": spdx_id,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": inspection.sha256,
                    }
                ],
                "copyrightText": "Copyright 2026 Skylark.AI",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": f"pkg:pypi/{normalized_name}@{metadata.version}",
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": metadata.name,
                "packageFileName": inspection.filename,
                "primaryPackagePurpose": "APPLICATION",
                "supplier": "Organization: Skylark.AI",
                "versionInfo": metadata.version,
            }
        )
        relationships.append(
            {
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-DOCUMENT",
            }
        )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created_at,
            "creators": [
                "Organization: Skylark.AI",
                f"Tool: build_step1_release_evidence.py-{TOOL_VERSION}",
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": namespace,
        "name": f"{metadata.name}-{metadata.version}-release-artifacts",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def _environment_record(
    *,
    source_revision: str,
    source_date_epoch: int,
    created_at: str,
) -> dict[str, object]:
    return {
        "created_at": created_at,
        "network_accessed": False,
        "platform": {
            "machine": platform.machine(),
            "release": platform.release(),
            "system": platform.system(),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "recorded_host_paths": False,
        "schema_version": "lumi-trace-step1-release-environment-v1",
        "source_date_epoch": source_date_epoch,
        "source_revision": source_revision,
        "tool": {
            "name": "build_step1_release_evidence.py",
            "stdlib_only": True,
            "version": TOOL_VERSION,
        },
    }


def _manifest(root: Path, names: tuple[str, ...]) -> dict[str, object]:
    members = [
        {
            "path": name,
            "sha256": f"sha256:{_sha256_file(root / name)}",
            "size_bytes": (root / name).stat().st_size,
        }
        for name in sorted(names)
    ]
    identity_payload = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return {
        "evidence_id": f"lumi-trace-step1-release-evidence:{_sha256_bytes(identity_payload)}",
        "members": members,
        "schema_version": "lumi-trace-step1-release-evidence-manifest-v1",
    }


def build_release_evidence(
    *,
    wheel: Path,
    sdist: Path,
    output: Path,
    source_revision: str,
    source_date_epoch: int,
) -> dict[str, object]:
    """Inspect a pair and atomically create a fresh bounded evidence directory."""

    if SOURCE_REVISION.fullmatch(source_revision) is None:
        raise ReleaseEvidenceError("source revision must be 40 lowercase hexadecimal characters")
    if source_date_epoch < 0:
        raise ReleaseEvidenceError("source date epoch must be non-negative")
    output = output.resolve(strict=False)
    if output.exists():
        raise ReleaseEvidenceError("release evidence output already exists")
    inspections = inspect_release_artifacts(wheel, sdist)
    verify_canonical_sdist(sdist, source_date_epoch=source_date_epoch)
    created_at = datetime.fromtimestamp(source_date_epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        inventory = {
            "artifacts": [inspection.record() for inspection in inspections],
            "package": inspections[0].metadata.record(),
            "schema_version": "lumi-trace-step1-release-artifact-inventory-v1",
            "source_revision": source_revision,
        }
        environment = _environment_record(
            source_revision=source_revision,
            source_date_epoch=source_date_epoch,
            created_at=created_at,
        )
        spdx = _spdx_document(
            inspections,
            source_revision=source_revision,
            created_at=created_at,
        )
        checksums = "".join(
            f"{inspection.sha256}  {inspection.filename}\n"
            for inspection in sorted(inspections, key=lambda item: item.filename)
        )
        (staging / "SHA256SUMS").write_text(
            checksums,
            encoding="ascii",
            newline="\n",
        )
        _write_json(staging / "artifact-inventory.json", inventory)
        _write_json(staging / "environment.json", environment)
        _write_json(staging / "sbom.spdx.json", spdx)
        summary = {
            "checks": [
                {"id": "archive-structure", "status": "PASS"},
                {"id": "canonical-sdist", "status": "PASS"},
                {"id": "package-metadata-match", "status": "PASS"},
                {"id": "apache-2.0-declaration", "status": "PASS"},
                {"id": "zero-runtime-dependencies", "status": "PASS"},
                {"id": "forbidden-member-boundary", "status": "PASS"},
                {"id": "payload-path-and-secret-boundary", "status": "PASS"},
                {"id": "serialized-model-boundary", "status": "PASS"},
                {"id": "sha256-checksums", "status": "PASS"},
                {"id": "spdx-2.3-sbom", "status": "PASS"},
            ],
            "legal_and_semantic_review": "REQUIRED_SEPARATELY",
            "overall_status": "PASS",
            "publication_authorised": False,
            "schema_version": "lumi-trace-step1-release-evidence-summary-v1",
            "source_revision": source_revision,
        }
        _write_json(staging / "summary.json", summary)
        evidence_names = (
            "SHA256SUMS",
            "artifact-inventory.json",
            "environment.json",
            "sbom.spdx.json",
            "summary.json",
        )
        manifest = _manifest(staging, evidence_names)
        _write_json(staging / "manifest.json", manifest)
        os.replace(staging, output)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=(
            int(os.environ["SOURCE_DATE_EPOCH"])
            if os.environ.get("SOURCE_DATE_EPOCH", "").isdigit()
            else None
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.source_date_epoch is None:
        print(
            "build-step1-release-evidence: --source-date-epoch or SOURCE_DATE_EPOCH is required",
            file=sys.stderr,
        )
        return 2
    output = args.output if args.output.is_absolute() else PROJECT_ROOT / args.output
    resolved_output = output.resolve(strict=False)
    ignored_root = (PROJECT_ROOT / "out").resolve(strict=False)
    if ignored_root not in resolved_output.parents:
        print(
            "build-step1-release-evidence: output must be below the ignored out/ directory",
            file=sys.stderr,
        )
        return 2
    try:
        manifest = build_release_evidence(
            wheel=args.wheel,
            sdist=args.sdist,
            output=resolved_output,
            source_revision=args.source_revision,
            source_date_epoch=args.source_date_epoch,
        )
    except (OSError, ReleaseEvidenceError) as exc:
        print(f"build-step1-release-evidence: {exc}", file=sys.stderr)
        return 2
    print(manifest["evidence_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
