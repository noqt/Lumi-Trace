# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
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

from lumi_trace import repository as repository_module
from lumi_trace.errors import InputError, IntegrityError, UnsupportedError
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


def test_manifest_digest_and_size_share_the_validated_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.py"
    source.write_bytes(b"old")
    replacement = b"replacement bytes"
    original_open = repository_module._open_regular_no_follow
    replaced = False

    def replace_then_open(path: Path, root: Path) -> io.BufferedReader:
        nonlocal replaced
        if path == source and not replaced:
            source.write_bytes(replacement)
            replaced = True
        return original_open(path, root)

    monkeypatch.setattr(repository_module, "_open_regular_no_follow", replace_then_open)
    records, total_bytes = repository_module.repository_manifest(repository)

    assert total_bytes == len(replacement)
    assert records == [
        {
            "path": "source.py",
            "sha256": f"sha256:{hashlib.sha256(replacement).hexdigest()}",
            "size_bytes": len(replacement),
        }
    ]


def test_copy_rejects_manifest_size_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_bytes(b"trusted")
    original_manifest = repository_module.repository_manifest

    def manifest_with_false_size(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        records, total_bytes = original_manifest(root, limits)
        records[0]["size_bytes"] = int(records[0]["size_bytes"]) + 1
        return records, total_bytes + 1

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_with_false_size)
    with pytest.raises(IntegrityError, match="repository changed"), RepositoryWorkspace(repository):
        pass


def test_manifest_replacement_cannot_bypass_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.py"
    source.write_bytes(b"old")
    original_open = repository_module._open_regular_no_follow
    replaced = False

    def replace_then_open(path: Path, root: Path) -> io.BufferedReader:
        nonlocal replaced
        if path == source and not replaced:
            source.write_bytes(b"larger than limit")
            replaced = True
        return original_open(path, root)

    monkeypatch.setattr(repository_module, "_open_regular_no_follow", replace_then_open)
    limits = repository_module.RepositoryLimits(max_bytes=3)
    with pytest.raises(UnsupportedError, match="expanded byte limit"):
        repository_module.repository_manifest(repository, limits)


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
        assert workspace.root.parent.parent == fixture_repository.parent
        assert workspace.identity["manifest_id"] == source["manifest_id"]
        assert (workspace.root / "src" / "archive.sh").is_file()
        script = workspace.root / "src" / "archive.sh"
        assert int(script.stat().st_mtime) == NORMALIZED_MTIME_SECONDS
        if os.name != "nt":
            assert stat.S_IMODE(script.stat().st_mode) == 0o644


def _symlink_or_skip(target: str | Path, link: Path, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")


def test_internal_file_symlink_becomes_identity_equivalent_git_stub(tmp_path: Path) -> None:
    linked_repository = tmp_path / "linked"
    linked_repository.mkdir()
    (linked_repository / "AGENTS.md").write_text("trusted instructions\n", encoding="utf-8")
    _symlink_or_skip("AGENTS.md", linked_repository / "CLAUDE.md")

    stub_repository = tmp_path / "stub"
    stub_repository.mkdir()
    (stub_repository / "AGENTS.md").write_text("trusted instructions\n", encoding="utf-8")
    (stub_repository / "CLAUDE.md").write_bytes(b"AGENTS.md")

    linked_identity = compute_repository_identity(linked_repository)
    assert linked_identity == compute_repository_identity(stub_repository)
    with RepositoryWorkspace(linked_repository) as workspace:
        assert workspace.identity == linked_identity
        stub = workspace.root / "CLAUDE.md"
        assert not stub.is_symlink()
        assert stub.read_bytes() == b"AGENTS.md"


@pytest.mark.parametrize(
    ("raw_target", "message"),
    [
        (b"", "canonical relative path"),
        (b"./AGENTS.md", "canonical relative path"),
        (b"nested/../AGENTS.md", "canonical relative path"),
        (b"nested\\AGENTS.md", "POSIX separators"),
        ("cafe\u0301.md".encode(), "NFC Unicode"),
        (b"\xff", "valid UTF-8"),
    ],
)
def test_symlink_stub_rejects_noncanonical_target_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw_target: bytes,
    message: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    link = repository / "link"
    monkeypatch.setattr(repository_module.os, "readlink", lambda _path: raw_target)
    with pytest.raises(UnsupportedError, match=message):
        repository_module._symlink_stub_payload(link, repository)


def test_internal_symlink_rejects_nonportable_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setattr(repository_module.os, "readlink", lambda _path: b"CON")
    with pytest.raises(InputError, match="non-portable symbolic link target"):
        repository_module._symlink_stub_payload(repository / "link", repository)


def test_internal_symlink_rejects_git_administration_target(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    git_directory = repository / ".git"
    git_directory.mkdir()
    (git_directory / "config").write_text("private\n", encoding="utf-8")
    _symlink_or_skip(".git/config", repository / "config-link")
    with pytest.raises(UnsupportedError, match="Git administration"):
        compute_repository_identity(repository)


def test_internal_symlink_rejects_directory_broken_chain_and_loop_targets(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    directory = repository / "directory"
    directory.mkdir()
    _symlink_or_skip("directory", repository / "directory-link", target_is_directory=True)
    with pytest.raises(UnsupportedError, match="regular file"):
        compute_repository_identity(repository)

    (repository / "directory-link").unlink()
    _symlink_or_skip("missing.txt", repository / "broken-link")
    with pytest.raises(UnsupportedError, match="must exist"):
        compute_repository_identity(repository)

    (repository / "broken-link").unlink()
    (repository / "target.txt").write_text("target\n", encoding="utf-8")
    _symlink_or_skip("target.txt", repository / "second-link")
    _symlink_or_skip("second-link", repository / "first-link")
    with pytest.raises(UnsupportedError, match="another link"):
        compute_repository_identity(repository)

    (repository / "first-link").unlink()
    (repository / "second-link").unlink()
    _symlink_or_skip("loop", repository / "loop")
    with pytest.raises(UnsupportedError, match="another link"):
        compute_repository_identity(repository)


def test_internal_symlink_rejects_absolute_parent_and_external_targets(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "target.txt").write_text("target\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")

    _symlink_or_skip(str(outside), repository / "absolute-link")
    with pytest.raises(UnsupportedError, match="canonical relative path"):
        compute_repository_identity(repository)

    (repository / "absolute-link").unlink()
    nested = repository / "nested"
    nested.mkdir()
    _symlink_or_skip("../target.txt", nested / "parent-link")
    with pytest.raises(UnsupportedError, match="canonical relative path"):
        compute_repository_identity(repository)

    (nested / "parent-link").unlink()
    _symlink_or_skip("../outside.txt", repository / "external-link")
    with pytest.raises(UnsupportedError, match="canonical relative path"):
        compute_repository_identity(repository)


def test_symlink_retarget_race_fails_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "first.txt").write_text("first\n", encoding="utf-8")
    (repository / "second.txt").write_text("second\n", encoding="utf-8")
    link = repository / "link.txt"
    _symlink_or_skip("first.txt", link)
    original_manifest = repository_module.repository_manifest

    def manifest_then_retarget(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        records, total_bytes = original_manifest(root, limits)
        link.unlink()
        link.symlink_to("second.txt")
        return records, total_bytes

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_then_retarget)
    with pytest.raises(IntegrityError, match="repository changed"), RepositoryWorkspace(repository):
        pass


def test_symlink_to_equivalent_stub_race_preserves_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "AGENTS.md").write_text("trusted instructions\n", encoding="utf-8")
    link = repository / "CLAUDE.md"
    _symlink_or_skip("AGENTS.md", link)
    expected = compute_repository_identity(repository)
    original_manifest = repository_module.repository_manifest

    def manifest_then_replace(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        records, total_bytes = original_manifest(root, limits)
        link.unlink()
        link.write_bytes(b"AGENTS.md")
        return records, total_bytes

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_then_replace)
    with RepositoryWorkspace(repository) as workspace:
        assert workspace.identity == expected
        assert (workspace.root / "CLAUDE.md").read_bytes() == b"AGENTS.md"


def test_repository_workspace_rejects_source_changed_after_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.py"
    source.write_text("value = 'trusted'\n", encoding="utf-8")
    original_manifest = repository_module.repository_manifest

    def manifest_then_change(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        records, total_bytes = original_manifest(root, limits)
        source.write_text("value = 'changed'\n", encoding="utf-8")
        return records, total_bytes

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_then_change)
    with (
        pytest.raises(IntegrityError, match="repository changed while its snapshot was created"),
        RepositoryWorkspace(repository),
    ):
        pass


def test_regular_file_to_symlink_race_is_rejected_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.py"
    source.write_text("value = 'trusted'\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("value = 'private'\n", encoding="utf-8")
    probe = tmp_path / "symlink-probe"
    _symlink_or_skip("outside.py", probe)
    probe.unlink()

    original_manifest = repository_module.repository_manifest
    original_is_symlink = Path.is_symlink
    armed = False
    replaced = False

    def manifest_then_arm(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        nonlocal armed
        records, total_bytes = original_manifest(root, limits)
        armed = True
        return records, total_bytes

    def replace_after_link_check(path: Path) -> bool:
        nonlocal replaced
        result = original_is_symlink(path)
        if armed and not replaced and path == source:
            source.unlink()
            source.symlink_to("../outside.py")
            replaced = True
        return result

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_then_arm)
    monkeypatch.setattr(Path, "is_symlink", replace_after_link_check)
    with pytest.raises(IntegrityError, match="repository changed"), RepositoryWorkspace(repository):
        pass


def test_regular_file_ancestor_to_symlink_race_is_rejected_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    nested = repository / "nested"
    nested.mkdir()
    source = nested / "source.py"
    source.write_text("value = 'trusted'\n", encoding="utf-8")
    outside = tmp_path / "outside-directory"
    probe = tmp_path / "symlink-probe"
    _symlink_or_skip("outside-directory", probe, target_is_directory=True)
    probe.unlink()

    original_manifest = repository_module.repository_manifest
    original_is_symlink = Path.is_symlink
    armed = False
    replaced = False

    def manifest_then_arm(
        root: Path, limits: repository_module.RepositoryLimits | None = None
    ) -> tuple[list[dict[str, object]], int]:
        nonlocal armed
        records, total_bytes = original_manifest(root, limits)
        armed = True
        return records, total_bytes

    def replace_after_link_check(path: Path) -> bool:
        nonlocal replaced
        result = original_is_symlink(path)
        if armed and not replaced and path == source:
            nested.rename(outside)
            nested.symlink_to("../outside-directory", target_is_directory=True)
            replaced = True
        return result

    monkeypatch.setattr(repository_module, "repository_manifest", manifest_then_arm)
    monkeypatch.setattr(Path, "is_symlink", replace_after_link_check)
    with pytest.raises(IntegrityError, match="repository changed"), RepositoryWorkspace(repository):
        pass


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
