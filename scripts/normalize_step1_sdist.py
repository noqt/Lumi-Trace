# SPDX-License-Identifier: Apache-2.0
"""Canonicalize a built Step 1 sdist for byte-reproducible release comparison."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 5_000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class NormalizationError(ValueError):
    """Raised when an sdist cannot cross the canonicalization boundary."""


@dataclass(frozen=True)
class Member:
    """One bounded canonical directory or regular-file member."""

    name: str
    is_directory: bool
    executable: bool
    payload: bytes


def _safe_name(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or pure.as_posix() != name
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise NormalizationError(f"unsafe sdist member path: {name!r}")
    return pure


def _read_members(source: Path) -> list[Member]:
    try:
        with tarfile.open(source, mode="r:gz") as archive:
            entries = archive.getmembers()
            if not entries or len(entries) > MAX_MEMBERS:
                raise NormalizationError("sdist member count is outside the allowed bound")
            roots = {_safe_name(entry.name).parts[0] for entry in entries}
            if len(roots) != 1:
                raise NormalizationError("sdist must contain exactly one package root")
            seen: set[str] = set()
            total_bytes = 0
            members: list[Member] = []
            for entry in entries:
                name = _safe_name(entry.name).as_posix()
                if name in seen:
                    raise NormalizationError(f"duplicate sdist member: {name}")
                seen.add(name)
                if entry.isdir():
                    members.append(
                        Member(
                            name=name,
                            is_directory=True,
                            executable=True,
                            payload=b"",
                        )
                    )
                    continue
                if not entry.isfile():
                    raise NormalizationError(f"sdist link or special member is forbidden: {name}")
                if entry.size < 0 or entry.size > MAX_MEMBER_BYTES:
                    raise NormalizationError(f"sdist member exceeds the size bound: {name}")
                extracted = archive.extractfile(entry)
                if extracted is None:
                    raise NormalizationError(f"sdist member cannot be read: {name}")
                with extracted:
                    payload = extracted.read(MAX_MEMBER_BYTES + 1)
                if len(payload) != entry.size:
                    raise NormalizationError(f"sdist member size is inconsistent: {name}")
                total_bytes += len(payload)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise NormalizationError("sdist exceeds the expanded-byte bound")
                members.append(
                    Member(
                        name=name,
                        is_directory=False,
                        executable=bool(entry.mode & 0o111),
                        payload=payload,
                    )
                )
    except (gzip.BadGzipFile, tarfile.TarError) as exc:
        raise NormalizationError("input is not a readable gzip-compressed TAR archive") from exc
    return sorted(members, key=lambda item: item.name.encode("utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_sdist(
    source: Path,
    output: Path,
    *,
    source_date_epoch: int,
) -> str:
    """Write one fresh canonical USTAR+gzip sdist and return its SHA-256."""

    if not 0 <= source_date_epoch <= 0xFFFFFFFF:
        raise NormalizationError("source date epoch is outside the gzip timestamp range")
    source = source.resolve(strict=True)
    output = output.resolve(strict=False)
    if source == output:
        raise NormalizationError("input and output paths must differ")
    if output.exists():
        raise NormalizationError("normalized sdist output already exists")
    members = _read_members(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with (
            os.fdopen(descriptor, "wb") as raw_output,
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=source_date_epoch,
            ) as compressed,
            tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive,
        ):
            for member in members:
                info = tarfile.TarInfo(member.name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = source_date_epoch
                if member.is_directory:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if member.executable else 0o644
                    info.size = len(member.payload)
                    archive.addfile(info, BytesIO(member.payload))
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return _sha256(output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=(
            int(os.environ["SOURCE_DATE_EPOCH"])
            if os.environ.get("SOURCE_DATE_EPOCH", "").isdigit()
            else None
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.source_date_epoch is None:
        print(
            "normalize-step1-sdist: --source-date-epoch or SOURCE_DATE_EPOCH is required",
            file=sys.stderr,
        )
        return 2
    try:
        digest = normalize_sdist(
            args.input,
            args.output,
            source_date_epoch=args.source_date_epoch,
        )
    except (OSError, NormalizationError) as exc:
        print(f"normalize-step1-sdist: {exc}", file=sys.stderr)
        return 2
    print(f"sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
