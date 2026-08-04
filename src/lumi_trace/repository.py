# SPDX-License-Identifier: Apache-2.0
"""Safe repository snapshots and immutable content identities."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import os
import stat
import struct
import tarfile
import tempfile
import unicodedata
import zipfile
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .canonical import canonical_sha256, sha256_file
from .errors import InputError, IntegrityError, UnsupportedError

DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_METADATA_BYTES = 64 * 1024 * 1024
NORMALIZED_MTIME_SECONDS = 946_684_800
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_WINDOWS_FORBIDDEN_CHARACTERS = set('<>:"|?*\\')


@dataclass(frozen=True)
class RepositoryLimits:
    """Bounds applied before untrusted repository content is processed."""

    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    max_archive_member_bytes: int = DEFAULT_MAX_ARCHIVE_MEMBER_BYTES
    max_archive_metadata_bytes: int = DEFAULT_MAX_ARCHIVE_METADATA_BYTES


def _canonical_relative(path: Path, root: Path) -> str:
    relative = path.relative_to(root).as_posix()
    normalized = unicodedata.normalize("NFC", relative)
    if relative != normalized:
        raise UnsupportedError(f"non-NFC repository path is unsupported in V0.1: {relative!r}")
    return normalized


def _check_collision(relative: str, seen: dict[str, str]) -> None:
    collision_key = unicodedata.normalize("NFC", relative).casefold()
    previous = seen.setdefault(collision_key, relative)
    if previous != relative:
        raise InputError(f"case or Unicode path collision: {previous!r} and {relative!r}")


def _validate_portable_parts(parts: Iterable[str], *, raw_name: str, descriptor: str) -> None:
    """Reject components whose meaning differs on supported host filesystems."""

    for raw_part in parts:
        part = unicodedata.normalize("NFC", raw_part)
        if (
            part.endswith((".", " "))
            or any(character in _WINDOWS_FORBIDDEN_CHARACTERS for character in part)
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise InputError(f"non-portable {descriptor} path: {raw_name!r}")


def _is_link_like(path: Path) -> bool:
    """Detect symbolic links, Windows junctions, and other reparse points."""

    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def repository_manifest(
    root: Path, limits: RepositoryLimits | None = None
) -> tuple[list[dict[str, object]], int]:
    """Hash every regular file below root in stable relative-path order.

    Git administration files are excluded. Symlinks and special files are
    rejected in V0.1 so a snapshot cannot escape or change meaning between
    operating systems.
    """

    limits = limits or RepositoryLimits()
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise InputError("repository root must be a directory")

    paths: list[Path] = []
    pending = [root]
    entry_count = 0
    seen_entries: dict[str, str] = {}
    while pending:
        directory_path = pending.pop()
        entries: list[tuple[str, Path, bool]] = []
        with os.scandir(directory_path) as scanner:
            for entry in scanner:
                if entry.name.casefold() == ".git":
                    continue
                entry_count += 1
                if entry_count > limits.max_files:
                    raise UnsupportedError(f"repository exceeds entry limit of {limits.max_files}")
                candidate = Path(entry.path)
                relative = _canonical_relative(candidate, root)
                _validate_portable_parts(
                    PurePosixPath(relative).parts,
                    raw_name=relative,
                    descriptor="repository",
                )
                _check_collision(relative, seen_entries)
                if _is_link_like(candidate):
                    raise UnsupportedError(
                        f"links or reparse points are unsupported in V0.1: {relative}"
                    )
                # Windows mount points are reparse points and were rejected above.
                # Path.is_mount() itself is unsupported on Windows before Python 3.12.
                if os.name != "nt" and candidate.is_mount():
                    raise UnsupportedError(
                        f"nested filesystem mount points are unsupported in V0.1: {relative}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    entries.append((relative, candidate, True))
                elif entry.is_file(follow_symlinks=False):
                    entries.append((relative, candidate, False))
                else:
                    raise UnsupportedError(f"special files are unsupported in V0.1: {relative}")
        entries.sort(key=lambda item: item[0].encode("utf-8"))
        paths.extend(candidate for _, candidate, is_directory in entries if not is_directory)
        directories = [candidate for _, candidate, is_directory in entries if is_directory]
        pending.extend(reversed(directories))

    records: list[dict[str, object]] = []
    total_bytes = 0
    for path in sorted(paths, key=lambda item: _canonical_relative(item, root).encode("utf-8")):
        relative = _canonical_relative(path, root)
        metadata = path.lstat()
        if _is_link_like(path) or stat.S_ISLNK(metadata.st_mode):
            raise UnsupportedError(f"links or reparse points are unsupported in V0.1: {relative}")
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsupportedError(f"special files are unsupported in V0.1: {relative}")
        total_bytes += metadata.st_size
        if total_bytes > limits.max_bytes:
            raise UnsupportedError(f"repository exceeds expanded byte limit of {limits.max_bytes}")
        records.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
                "size_bytes": metadata.st_size,
            }
        )
    return records, total_bytes


def compute_repository_identity(
    root: Path,
    *,
    source_kind: str = "directory",
    archive_sha256: str | None = None,
    limits: RepositoryLimits | None = None,
) -> dict[str, object]:
    """Return a host-path-free immutable identity for repository content."""

    files, total_bytes = repository_manifest(root, limits)
    manifest = {
        "algorithm": "lumi-tree-sha256-v1",
        "files": files,
    }
    manifest_id = canonical_sha256(manifest)
    identity: dict[str, object] = {
        "repository_id": f"repository:{manifest_id.removeprefix('sha256:')}",
        "manifest_id": manifest_id,
        "algorithm": "lumi-tree-sha256-v1",
        "source_kind": source_kind,
        "file_count": len(files),
        "total_bytes": total_bytes,
    }
    if archive_sha256 is not None:
        identity["archive_sha256"] = archive_sha256
    return identity


def _safe_member_name(raw_name: str) -> PurePosixPath:
    name = raw_name.replace("\\", "/")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise InputError(f"unsafe archive member path: {raw_name!r}")
    raw_parts = name.rstrip("/").split("/")
    if any(not part or part == "." for part in raw_parts):
        raise InputError(f"non-canonical archive member path: {raw_name!r}")
    _validate_portable_parts(
        raw_parts,
        raw_name=raw_name,
        descriptor="archive member",
    )
    return PurePosixPath(*(unicodedata.normalize("NFC", part) for part in path.parts))


def _zip_directory_metadata(archive: Path) -> tuple[int, int, int]:
    """Read ZIP/ZIP64 end records before ZipFile allocates the central directory."""

    size = archive.stat().st_size
    with archive.open("rb") as stream:
        tail_size = min(size, 65_557)
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
        eocd_index = tail.rfind(b"PK\x05\x06")
        if eocd_index < 0 or len(tail) - eocd_index < 22:
            raise InputError("ZIP end-of-central-directory record is missing")
        fields = struct.unpack_from("<4s4H2LH", tail, eocd_index)
        disk_number, central_disk, entries_on_disk, total_entries = fields[1:5]
        central_size, central_offset, comment_length = fields[5:8]
        if eocd_index + 22 + comment_length != len(tail):
            raise InputError("ZIP end record has an invalid comment length")
        if disk_number or central_disk or entries_on_disk != total_entries:
            raise UnsupportedError("multi-disk ZIP archives are unsupported")
        if total_entries != 0xFFFF:
            return total_entries, central_size, central_offset
        locator_index = tail.rfind(b"PK\x06\x07", 0, eocd_index)
        if locator_index < 0 or len(tail) - locator_index < 20:
            raise InputError("ZIP64 locator is missing")
        _, zip64_disk, zip64_offset, disk_count = struct.unpack_from("<4sLQL", tail, locator_index)
        if zip64_disk or disk_count != 1:
            raise UnsupportedError("multi-disk ZIP64 archives are unsupported")
        stream.seek(zip64_offset)
        zip64_record = stream.read(56)
        if len(zip64_record) < 56 or not zip64_record.startswith(b"PK\x06\x06"):
            raise InputError("ZIP64 end-of-central-directory record is invalid")
        total_entries = struct.unpack_from("<Q", zip64_record, 32)[0]
        central_size = struct.unpack_from("<Q", zip64_record, 40)[0]
        central_offset = struct.unpack_from("<Q", zip64_record, 48)[0]
        return total_entries, central_size, central_offset


def _register_archive_member(
    relative: PurePosixPath,
    *,
    is_directory: bool,
    collisions: dict[str, str],
    path_types: dict[str, str],
    explicit_members: set[str],
) -> None:
    """Reject duplicate, colliding, and file/directory-conflicting archive names."""

    member = relative.as_posix()
    if member in explicit_members:
        raise InputError(f"duplicate archive member path: {member!r}")
    explicit_members.add(member)
    for index in range(1, len(relative.parts) + 1):
        prefix = PurePosixPath(*relative.parts[:index]).as_posix()
        _check_collision(prefix, collisions)
        expected_type = "directory" if index < len(relative.parts) or is_directory else "file"
        collision_key = unicodedata.normalize("NFC", prefix).casefold()
        previous_type = path_types.setdefault(collision_key, expected_type)
        if previous_type != expected_type:
            raise InputError(f"archive file/directory path conflict: {member!r}")


def _write_archive_file(source: object, destination: Path, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    with destination.open("wb") as output:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))  # type: ignore[attr-defined]
            if not chunk:
                raise InputError("archive member ended before its declared size")
            output.write(chunk)
            remaining -= len(chunk)
        if source.read(1):  # type: ignore[attr-defined]
            raise InputError("archive member exceeds its declared size")


def _extract_zip(archive: Path, destination: Path, limits: RepositoryLimits) -> None:
    file_count = 0
    total_bytes = 0
    collisions: dict[str, str] = {}
    path_types: dict[str, str] = {}
    explicit_members: set[str] = set()
    declared_members, central_size, central_offset = _zip_directory_metadata(archive)
    if declared_members > limits.max_files:
        raise UnsupportedError(f"archive exceeds entry limit of {limits.max_files}")
    if central_size > limits.max_archive_metadata_bytes:
        raise UnsupportedError(
            f"ZIP central directory exceeds metadata limit of {limits.max_archive_metadata_bytes}"
        )
    if central_offset + central_size > archive.stat().st_size:
        raise InputError("ZIP central directory lies outside the archive")
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) != declared_members:
            raise InputError("ZIP member count does not match its end record")
        for member in sorted(members, key=lambda item: item.filename.encode("utf-8")):
            relative = _safe_member_name(member.filename)
            _register_archive_member(
                relative,
                is_directory=member.is_dir(),
                collisions=collisions,
                path_types=path_types,
                explicit_members=explicit_members,
            )
            if member.flag_bits & 0x1:
                raise UnsupportedError(f"encrypted ZIP member is unsupported: {member.filename}")
            unix_mode = member.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise UnsupportedError(f"archive symlink is unsupported: {member.filename}")
            unix_type = stat.S_IFMT(unix_mode)
            expected_types = {0, stat.S_IFDIR} if member.is_dir() else {0, stat.S_IFREG}
            if unix_type not in expected_types:
                raise UnsupportedError(
                    f"archive links and special members are unsupported: {member.filename}"
                )
            target = destination.joinpath(*relative.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            file_count += 1
            total_bytes += member.file_size
            if file_count > limits.max_files or total_bytes > limits.max_bytes:
                raise UnsupportedError("archive exceeds file or expanded-byte limits")
            if member.file_size > limits.max_archive_member_bytes:
                raise UnsupportedError(f"archive member is too large: {member.filename}")
            with package.open(member, "r") as stream:
                _write_archive_file(stream, target, member.file_size)


def _extract_tar(archive: Path, destination: Path, limits: RepositoryLimits) -> None:
    _preflight_tar(archive, limits)
    file_count = 0
    total_bytes = 0
    collisions: dict[str, str] = {}
    path_types: dict[str, str] = {}
    explicit_members: set[str] = set()
    member_count = 0
    with tarfile.open(archive, mode="r:*") as package:
        for member in package:
            member_count += 1
            if member_count > limits.max_files:
                raise UnsupportedError(f"archive exceeds entry limit of {limits.max_files}")
            relative = _safe_member_name(member.name)
            _register_archive_member(
                relative,
                is_directory=member.isdir(),
                collisions=collisions,
                path_types=path_types,
                explicit_members=explicit_members,
            )
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise UnsupportedError(
                    f"archive links and special members are unsupported: {member.name}"
                )
            file_count += 1
            total_bytes += member.size
            if file_count > limits.max_files or total_bytes > limits.max_bytes:
                raise UnsupportedError("archive exceeds file or expanded-byte limits")
            if member.size > limits.max_archive_member_bytes:
                raise UnsupportedError(f"archive member is too large: {member.name}")
            stream = package.extractfile(member)
            if stream is None:
                raise InputError(f"cannot read archive member: {member.name}")
            with stream:
                _write_archive_file(stream, target, member.size)


def _preflight_tar(archive: Path, limits: RepositoryLimits) -> None:
    """Bound TAR parsing and reject extension headers before tarfile consumes them."""

    lower_name = archive.name.casefold()
    if lower_name.endswith((".tar.gz", ".tgz")):
        opener = gzip.open
    elif lower_name.endswith((".tar.bz2", ".tbz2")):
        opener = bz2.open
    elif lower_name.endswith(".tar.xz"):
        opener = lzma.open
    else:
        opener = Path.open
    member_count = 0
    metadata_bytes = 0
    expanded_bytes = 0
    with opener(archive, "rb") as stream:
        while True:
            header = stream.read(512)
            if not header:
                break
            if len(header) != 512:
                raise InputError("TAR archive has a truncated header")
            if header == b"\0" * 512:
                break
            metadata_bytes += 512
            member_count += 1
            if member_count > limits.max_files:
                raise UnsupportedError(f"archive exceeds entry limit of {limits.max_files}")
            if metadata_bytes > limits.max_archive_metadata_bytes:
                raise UnsupportedError(
                    f"TAR metadata exceeds limit of {limits.max_archive_metadata_bytes}"
                )
            try:
                member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            except tarfile.HeaderError as exc:
                raise InputError(f"TAR archive header is invalid: {exc}") from exc
            if member.type in {
                tarfile.XHDTYPE,
                tarfile.XGLTYPE,
                tarfile.GNUTYPE_LONGNAME,
                tarfile.GNUTYPE_LONGLINK,
                tarfile.GNUTYPE_SPARSE,
            }:
                raise UnsupportedError("PAX and GNU TAR extension headers are unsupported in V0.1")
            if not (member.isfile() or member.isdir()):
                raise UnsupportedError(
                    f"archive links and special members are unsupported: {member.name}"
                )
            if member.size > limits.max_archive_member_bytes:
                raise UnsupportedError(f"archive member is too large: {member.name}")
            if member.isfile():
                expanded_bytes += member.size
                if expanded_bytes > limits.max_bytes:
                    raise UnsupportedError("archive exceeds expanded-byte limit")
            remaining = ((member.size + 511) // 512) * 512
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise InputError("TAR archive member is truncated")
                remaining -= len(chunk)


def _collapse_archive_root(root: Path) -> Path:
    entries = sorted(root.iterdir(), key=lambda item: item.name.encode("utf-8"))
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return root


def _copy_repository(
    source: Path,
    destination: Path,
    records: Iterable[dict[str, object]],
) -> None:
    """Copy one verified manifest and reject any changed copied content."""

    for record in records:
        relative = Path(str(record["path"]))
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with (source / relative).open("rb") as source_stream, target.open("xb") as target_stream:
            while chunk := source_stream.read(1024 * 1024):
                target_stream.write(chunk)
                digest.update(chunk)
        if f"sha256:{digest.hexdigest()}" != record["sha256"]:
            raise IntegrityError("repository changed while its snapshot was created")


def _normalize_snapshot_metadata(root: Path) -> None:
    """Normalize modes and mtimes that are intentionally absent from content identity."""

    directories: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directories.append(directory_path)
        for name in filenames:
            path = directory_path / name
            path.chmod(0o644)
            os.utime(path, (NORMALIZED_MTIME_SECONDS, NORMALIZED_MTIME_SECONDS))
        for name in names:
            (directory_path / name).chmod(0o755)
    for directory in reversed(directories):
        directory.chmod(0o755)
        os.utime(directory, (NORMALIZED_MTIME_SECONDS, NORMALIZED_MTIME_SECONDS))


class RepositoryWorkspace:
    """Materialise an immutable, disposable repository snapshot."""

    def __init__(self, source: Path, limits: RepositoryLimits | None = None) -> None:
        self.source = source
        self.limits = limits or RepositoryLimits()
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.root: Path | None = None
        self.identity: dict[str, object] | None = None
        self.manifest_records: list[dict[str, object]] | None = None

    def __enter__(self) -> RepositoryWorkspace:
        source = self.source.resolve(strict=True)
        try:
            # A source-adjacent workspace avoids cross-volume copy and hash I/O
            # while preserving the immutable disposable snapshot contract.
            self._temporary = tempfile.TemporaryDirectory(
                prefix="lumi-trace-repository-", dir=source.parent
            )
        except OSError:
            # Read-only or policy-restricted source parents retain the existing
            # system-temporary fallback.
            self._temporary = tempfile.TemporaryDirectory(prefix="lumi-trace-repository-")
        materialised = Path(self._temporary.name) / "repository"
        materialised.mkdir()

        if source.is_dir():
            records, total_bytes = repository_manifest(source, self.limits)
            before_manifest = {
                "algorithm": "lumi-tree-sha256-v1",
                "files": records,
            }
            manifest_id = canonical_sha256(before_manifest)
            before = {
                "repository_id": f"repository:{manifest_id.removeprefix('sha256:')}",
                "manifest_id": manifest_id,
                "algorithm": "lumi-tree-sha256-v1",
                "source_kind": "directory",
                "file_count": len(records),
                "total_bytes": total_bytes,
            }
            _copy_repository(source, materialised, records)
            _normalize_snapshot_metadata(materialised)
            self.root = materialised
            self.identity = before
            self.manifest_records = records
        elif source.is_file():
            archive_sha256 = sha256_file(source)
            lower_name = source.name.lower()
            try:
                if lower_name.endswith(".zip"):
                    _extract_zip(source, materialised, self.limits)
                elif any(
                    lower_name.endswith(suffix)
                    for suffix in (
                        ".tar",
                        ".tar.gz",
                        ".tgz",
                        ".tar.bz2",
                        ".tbz2",
                        ".tar.xz",
                    )
                ):
                    _extract_tar(source, materialised, self.limits)
                else:
                    raise UnsupportedError("repository archive must be ZIP or TAR")
            except (
                EOFError,
                OSError,
                UnicodeError,
                lzma.LZMAError,
                struct.error,
                tarfile.TarError,
                zipfile.BadZipFile,
                zipfile.LargeZipFile,
                zlib.error,
            ) as exc:
                raise InputError(f"repository archive is malformed or unreadable: {exc}") from exc
            if sha256_file(source) != archive_sha256:
                raise IntegrityError("repository archive changed while it was extracted")
            self.root = _collapse_archive_root(materialised)
            _normalize_snapshot_metadata(self.root)
            self.identity = compute_repository_identity(
                self.root,
                source_kind="archive",
                archive_sha256=archive_sha256,
                limits=self.limits,
            )
        else:
            raise InputError("repository input must be a directory or immutable archive")

        return self

    def __exit__(self, *_: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


def iter_manifest_paths(root: Path, records: Iterable[dict[str, object]]) -> Iterable[Path]:
    """Resolve manifest paths below a trusted materialised snapshot."""

    for record in records:
        yield root / Path(str(record["path"]))
