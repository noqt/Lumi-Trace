# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import tarfile
import unicodedata
import zipfile
from pathlib import Path

import pytest

from lumi_trace.errors import InputError, UnsupportedError
from lumi_trace.repository import (
    NORMALIZED_MTIME_SECONDS,
    RepositoryWorkspace,
    compute_repository_identity,
)


def test_repository_identity_is_stable_and_host_path_free(fixture_repository: Path) -> None:
    first = compute_repository_identity(fixture_repository)
    second = compute_repository_identity(fixture_repository)
    assert first == second
    encoded = json.dumps(first)
    assert str(fixture_repository) not in encoded
    assert first["repository_id"].startswith("repository:")


@pytest.mark.skipif(os.name != "nt", reason="Windows Path.is_mount compatibility")
def test_windows_manifest_does_not_call_unsupported_is_mount(
    fixture_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsupported_is_mount(_path: Path) -> bool:
        raise NotImplementedError("Path.is_mount() is unsupported on this system")

    monkeypatch.setattr(Path, "is_mount", unsupported_is_mount)
    assert compute_repository_identity(fixture_repository)["file_count"] > 0


def test_repository_workspace_is_a_content_identical_snapshot(fixture_repository: Path) -> None:
    source = compute_repository_identity(fixture_repository)
    with RepositoryWorkspace(fixture_repository) as workspace:
        assert workspace.root != fixture_repository
        assert workspace.identity["manifest_id"] == source["manifest_id"]
        assert (workspace.root / "src" / "archive.sh").is_file()
        script = workspace.root / "src" / "archive.sh"
        assert int(script.stat().st_mtime) == NORMALIZED_MTIME_SECONDS
        if os.name != "nt":
            assert stat.S_IMODE(script.stat().st_mode) == 0o644


def test_archive_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("../escape.txt", "no")
    with pytest.raises(InputError, match="unsafe archive member"), RepositoryWorkspace(archive):
        pass


def test_zip_and_directory_have_same_content_identity(
    tmp_path: Path, fixture_repository: Path
) -> None:
    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as package:
        for path in sorted(fixture_repository.rglob("*")):
            if path.is_file():
                package.write(path, f"fixture/{path.relative_to(fixture_repository).as_posix()}")
    directory_identity = compute_repository_identity(fixture_repository)
    with RepositoryWorkspace(archive) as workspace:
        assert workspace.identity["manifest_id"] == directory_identity["manifest_id"]


@pytest.mark.parametrize(
    ("suffix", "mode"),
    [
        (".tar", "w"),
        (".tar.gz", "w:gz"),
        (".tgz", "w:gz"),
        (".tar.bz2", "w:bz2"),
        (".tbz2", "w:bz2"),
        (".tar.xz", "w:xz"),
    ],
)
def test_tar_family_and_directory_have_same_content_identity(
    tmp_path: Path,
    fixture_repository: Path,
    suffix: str,
    mode: str,
) -> None:
    archive = tmp_path / f"fixture{suffix}"
    with tarfile.open(archive, mode=mode, format=tarfile.USTAR_FORMAT) as package:
        for path in sorted(fixture_repository.rglob("*")):
            if path.is_file():
                package.add(
                    path,
                    arcname=f"fixture/{path.relative_to(fixture_repository).as_posix()}",
                    recursive=False,
                )
    directory_identity = compute_repository_identity(fixture_repository)
    with RepositoryWorkspace(archive) as workspace:
        assert workspace.identity["manifest_id"] == directory_identity["manifest_id"]


def test_tar_traversal_and_links_are_rejected(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.tar"
    with tarfile.open(traversal, mode="w", format=tarfile.USTAR_FORMAT) as package:
        member = tarfile.TarInfo("../escape.py")
        payload = b"print('unsafe')\n"
        member.size = len(payload)
        package.addfile(member, io.BytesIO(payload))
    with pytest.raises(InputError, match="unsafe archive member"), RepositoryWorkspace(traversal):
        pass

    linked = tmp_path / "linked.tar"
    with tarfile.open(linked, mode="w", format=tarfile.USTAR_FORMAT) as package:
        member = tarfile.TarInfo("linked.py")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside.py"
        package.addfile(member)
    with (
        pytest.raises(UnsupportedError, match="links and special members"),
        RepositoryWorkspace(linked),
    ):
        pass


def test_archive_case_collisions_are_rejected_on_every_platform(tmp_path: Path) -> None:
    archive = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("A/first.txt", "one")
        package.writestr("a/second.txt", "two")
    with (
        pytest.raises(InputError, match="case or Unicode path collision"),
        RepositoryWorkspace(archive),
    ):
        pass


def test_archive_ntfs_alternate_stream_name_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "alternate-stream.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("source.py:metadata", "no")
    with (
        pytest.raises(InputError, match="non-portable archive member"),
        RepositoryWorkspace(archive),
    ):
        pass


def test_zip_special_member_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "special.zip"
    member = zipfile.ZipInfo("named-pipe")
    member.create_system = 3
    member.external_attr = (stat.S_IFIFO | 0o644) << 16
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(member, b"")
    with (
        pytest.raises(UnsupportedError, match="special members"),
        RepositoryWorkspace(archive),
    ):
        pass


def test_archive_member_names_are_materialised_as_nfc(tmp_path: Path) -> None:
    archive = tmp_path / "unicode.zip"
    decomposed = "cafe\u0301.py"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(decomposed, "print('ok')\n")
    with RepositoryWorkspace(archive) as workspace:
        files = workspace.identity["file_count"]
        assert files == 1
        expected = unicodedata.normalize("NFC", decomposed)
        assert (workspace.root / expected).read_text(encoding="utf-8") == "print('ok')\n"


def test_directory_with_non_nfc_name_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository-non-nfc"
    repository.mkdir()
    (repository / "cafe\u0301.py").write_text("print('no')\n", encoding="utf-8")
    with pytest.raises(UnsupportedError, match="non-NFC"), RepositoryWorkspace(repository):
        pass


@pytest.mark.skipif(os.name == "nt", reason="requires a case-sensitive filesystem")
@pytest.mark.parametrize(
    ("first_name", "second_name"),
    [("A", "a"), ("Straße", "STRASSE")],
)
def test_directory_prefix_case_or_unicode_collisions_are_rejected(
    tmp_path: Path, first_name: str, second_name: str
) -> None:
    repository = tmp_path / "repository-collision"
    repository.mkdir()
    first = repository / first_name
    second = repository / second_name
    first.mkdir()
    if second.exists():
        pytest.skip("filesystem does not preserve the colliding names separately")
    second.mkdir()
    (first / "one.txt").write_text("one\n", encoding="utf-8")
    (second / "two.txt").write_text("two\n", encoding="utf-8")

    with (
        pytest.raises(InputError, match="case or Unicode path collision"),
        RepositoryWorkspace(repository),
    ):
        pass


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot create this path")
@pytest.mark.parametrize("directory_name", ["bad:name", "CON", "trailing."])
def test_nonportable_directory_components_are_rejected(tmp_path: Path, directory_name: str) -> None:
    repository = tmp_path / "repository-nonportable"
    repository.mkdir()
    nested = repository / directory_name
    nested.mkdir()
    (nested / "source.py").write_text("print('no')\n", encoding="utf-8")

    with (
        pytest.raises(InputError, match="non-portable repository path"),
        RepositoryWorkspace(repository),
    ):
        pass


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction behavior is Windows-specific")
def test_windows_junction_directory_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("must not be indexed", encoding="utf-8")
    junction = repository / "linked"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"could not create test junction: {result.stderr.strip()}")
    try:
        with (
            pytest.raises(UnsupportedError, match="reparse points"),
            RepositoryWorkspace(repository),
        ):
            pass
    finally:
        junction.rmdir()
