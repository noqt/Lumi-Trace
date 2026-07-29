# SPDX-License-Identifier: Apache-2.0
"""Fetch and verify the pinned source archive used by the public example."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

REVISION = "2dbe5b5794472a4cad8e9286c942dffda7359816"
ARCHIVE_NAME = f"datamodel-code-generator-{REVISION}.zip"
ARCHIVE_URL = f"https://codeload.github.com/koxudaxi/datamodel-code-generator/zip/{REVISION}"
ARCHIVE_SHA256 = "12a2eef58a6241b250f87f9a2c0c581a5a6d29be88bf4e5090df0df060fb806c"
ARCHIVE_SIZE = 3_844_899
ARCHIVE_ROOT = f"datamodel-code-generator-{REVISION}"
EXPECTED_FILES = {
    "LICENSE": "2b9e0bc1cebf8ddbb272ccbca051634047924ae122aaf5488c21885ce327b934",
    "docs/assets/playground/THIRD_PARTY_LICENSES.txt": (
        "554dc29604b51ebe1b286ed60a9e21bbfc824c7851b7a2c8a3849ded2f769903"
    ),
    "src/datamodel_code_generator/parser/jsonschema.py": (
        "27c901e05071c494e1fcac98f2394b9415fc120a523105edad846ba908d779d4"
    ),
}
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024


class FetchError(RuntimeError):
    """The pinned public example could not be acquired or verified."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(member, mode="r") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_archive(
    path: Path,
    *,
    expected_sha256: str = ARCHIVE_SHA256,
    expected_size: int = ARCHIVE_SIZE,
    expected_root: str = ARCHIVE_ROOT,
    expected_files: dict[str, str] = EXPECTED_FILES,
) -> dict[str, int | str]:
    try:
        actual_size = path.stat().st_size
        actual_sha256 = _sha256_file(path)
    except OSError as exc:
        raise FetchError(f"archive cannot be read: {exc}") from exc
    if actual_size != expected_size:
        raise FetchError(
            f"archive size mismatch: expected {expected_size} bytes, received {actual_size}"
        )
    if actual_sha256 != expected_sha256:
        raise FetchError(
            f"archive SHA-256 mismatch: expected {expected_sha256}, received {actual_sha256}"
        )

    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise FetchError(
                    f"archive member count is outside the allowed range: {len(members)}"
                )

            names: set[str] = set()
            regular_bytes = 0
            regular_files = 0
            for member in members:
                name = member.filename
                if "\\" in name or "\x00" in name:
                    raise FetchError(f"archive contains a non-canonical member: {name!r}")
                member_path = PurePosixPath(name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != expected_root
                ):
                    raise FetchError(f"archive member escapes the expected root: {name}")
                if name in names:
                    raise FetchError(f"archive contains a duplicate member: {name}")
                names.add(name)
                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise FetchError(f"archive contains a link or special member: {name}")
                if not member.is_dir():
                    regular_files += 1
                    regular_bytes += member.file_size
                    if regular_bytes > MAX_UNCOMPRESSED_BYTES:
                        raise FetchError("archive exceeds the uncompressed byte limit")

            for relative_path, expected_member_sha256 in expected_files.items():
                name = f"{expected_root}/{relative_path}"
                try:
                    member = archive.getinfo(name)
                except KeyError as exc:
                    raise FetchError(f"archive is missing required member: {name}") from exc
                if member.is_dir():
                    raise FetchError(f"required archive member is not a file: {name}")
                actual_member_sha256 = _sha256_member(archive, member)
                if actual_member_sha256 != expected_member_sha256:
                    raise FetchError(
                        f"archive member SHA-256 mismatch for {name}: "
                        f"expected {expected_member_sha256}, received {actual_member_sha256}"
                    )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise FetchError(f"archive is not a readable ZIP file: {exc}") from exc

    return {
        "archive": str(path.resolve()),
        "archive_sha256": actual_sha256,
        "archive_size": actual_size,
        "member_count": len(members),
        "regular_file_count": regular_files,
        "uncompressed_regular_bytes": regular_bytes,
        "revision": REVISION,
    }


def _download(destination: Path) -> None:
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "Lumi-Trace-public-example-fetch/1.0"},
    )
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{ARCHIVE_NAME}.",
            suffix=".part",
        )
        temporary_path = Path(temporary_name)
        with (
            os.fdopen(descriptor, "wb") as output,
            urllib.request.urlopen(request, timeout=30) as response,  # noqa: S310
        ):
            final_url = urlsplit(response.geturl())
            if (
                final_url.scheme != "https"
                or final_url.hostname != "codeload.github.com"
                or response.geturl() != ARCHIVE_URL
            ):
                raise FetchError(
                    f"download resolved to an unexpected location: {response.geturl()}"
                )
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None and int(declared_length) > MAX_DOWNLOAD_BYTES:
                raise FetchError("server declared an archive larger than the download limit")
            downloaded = 0
            while chunk := response.read(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > MAX_DOWNLOAD_BYTES:
                    raise FetchError("archive exceeded the download limit")
                output.write(chunk)
        _validate_archive(temporary_path)
        os.replace(temporary_path, destination)
        temporary_path = None
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise FetchError(f"archive download failed: {exc}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Download the exact rights-reviewed vulnerable source archive used by "
            "the Lumi Trace public example."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help=f"existing or new output directory for {ARCHIVE_NAME}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_directory = args.output.expanduser().resolve()
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
        if not output_directory.is_dir():
            raise FetchError(f"output path is not a directory: {output_directory}")
        destination = output_directory / ARCHIVE_NAME
        downloaded = not destination.exists()
        if downloaded:
            _download(destination)
        summary = _validate_archive(destination)
        summary["downloaded"] = downloaded
        summary["source_url"] = ARCHIVE_URL
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except FetchError as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"fetch failed while preparing the output directory: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
