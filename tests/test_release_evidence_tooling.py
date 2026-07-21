# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from seal_v0_1 import (  # noqa: E402
    SealError,
    _assert_public_safe_json,
    _normalize_source_distribution,
    _require_bundle_source_revision,
    _seal_manifest,
    _training_readiness,
    _validate_image_reference,
    _verify_owned_fixture_manifest,
    _write_json,
)
from verify_v0_1_evidence import verify_seal_manifest  # noqa: E402

REVISION = "a" * 40


def test_seal_manifest_rejects_tampering_and_extra_files(tmp_path: Path) -> None:
    payload = tmp_path / "payload.json"
    _write_json(payload, {"public": True})
    original = payload.read_bytes()
    _write_json(tmp_path / "seal-manifest.json", _seal_manifest(tmp_path, REVISION))

    manifest, files = verify_seal_manifest(tmp_path)
    assert manifest["source_revision"] == REVISION
    assert set(files) == {"payload.json", "seal-manifest.json"}

    payload.write_text('{"public":false}\n', encoding="utf-8")
    with pytest.raises(SealError, match="does not match"):
        verify_seal_manifest(tmp_path)

    payload.write_bytes(original)
    (tmp_path / "unmanifested.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(SealError, match="unmanifested"):
        verify_seal_manifest(tmp_path)


@pytest.mark.parametrize(
    "reference",
    [
        "alpine:latest",
        "UPPER@sha256:" + "a" * 64,
        "user:password@example.invalid/image@sha256:" + "a" * 64,
        "sha256:" + "A" * 64,
    ],
)
def test_image_reference_must_be_credential_free_and_immutable(reference: str) -> None:
    with pytest.raises(SealError, match="digest reference"):
        _validate_image_reference(reference)
    _validate_image_reference("alpine@sha256:" + "a" * 64)
    _validate_image_reference("sha256:" + "a" * 64)


def test_public_safety_rejects_host_paths_and_recorded_durations(tmp_path: Path) -> None:
    _write_json(tmp_path / "safe.json", {"duration_ms": None})
    _assert_public_safe_json(tmp_path)

    (tmp_path / "safe.json").write_text(
        json.dumps({"host": "C:\\Users\\person\\repository"}), encoding="utf-8"
    )
    with pytest.raises(SealError, match="host-path"):
        _assert_public_safe_json(tmp_path)

    (tmp_path / "safe.json").write_text(json.dumps({"duration_ms": 1}), encoding="utf-8")
    with pytest.raises(SealError, match="recorded duration"):
        _assert_public_safe_json(tmp_path)


def test_training_readiness_is_fail_closed() -> None:
    recommendation = _training_readiness(REVISION)
    assert recommendation["recommendation"] == "DO_NOT_BEGIN_TRACE_001"
    assert recommendation["all_gates_satisfied"] is False
    assert recommendation["training_started"] is False
    assert recommendation["weights_downloaded"] is False
    assert recommendation["checkpoint"] is None
    assert all(gate["satisfied"] is False for gate in recommendation["gates"])


def test_owned_fixture_manifest_is_self_consistent() -> None:
    _verify_owned_fixture_manifest()


def test_source_distribution_normalization_is_byte_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    def write_source(path: Path, mtime: int) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            directory = tarfile.TarInfo("project")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o775
            directory.mtime = mtime
            archive.addfile(directory)
            content = b"public fixture\n"
            member = tarfile.TarInfo("project/fixture.txt")
            member.mode = 0o664
            member.mtime = mtime
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    write_source(first, 100)
    write_source(second, 200)
    _normalize_source_distribution(first, 1_234_567_890)
    _normalize_source_distribution(second, 1_234_567_890)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        assert all(member.mtime == 1_234_567_890 for member in archive.getmembers())
        assert all(member.uid == 0 and member.gid == 0 for member in archive.getmembers())


def test_bundle_source_revision_cross_check_uses_tool_identity() -> None:
    bundle = {
        "tool": {"source_revision": REVISION},
        "provenance": {"source_revision": "not-the-contract-location"},
    }
    _require_bundle_source_revision(bundle, REVISION)
    with pytest.raises(SealError, match="wrong source revision"):
        _require_bundle_source_revision(bundle, "b" * 40)
