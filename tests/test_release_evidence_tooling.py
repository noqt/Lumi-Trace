# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

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
from verify_v0_3_1_evidence import verify as verify_v0_3_1_evidence  # noqa: E402
from verify_v0_3_2_evidence import verify as verify_v0_3_2_evidence  # noqa: E402
from verify_v0_3_evidence import verify as verify_v0_3_evidence  # noqa: E402
from verify_v0_4_1_evidence import verify as verify_v0_4_1_evidence  # noqa: E402
from verify_v0_4_evidence import verify as verify_v0_4_evidence  # noqa: E402

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


def test_sdist_excludes_a_populated_evidence_tree(tmp_path: Path, project_root: Path) -> None:
    source_root = tmp_path / "source"
    shutil.copytree(
        project_root,
        source_root,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".pytest_cache",
            ".ruff_cache",
            "__pycache__",
            "*.egg-info",
            "build",
            "dist",
            "evidence",
            "out",
        ),
    )
    evidence_root = source_root / "evidence" / "v0.1.0"
    evidence_root.mkdir(parents=True)
    for index in range(14):
        (evidence_root / f"partial-{index:02d}.json").write_text(
            '{"incomplete":true}\n', encoding="utf-8"
        )
    for generated in (
        source_root / "eval" / "build" / "lib" / "generated.py",
        source_root / "eval" / ".pytest_cache" / "README.md",
        source_root / "eval" / ".ruff_cache" / "state.json",
        source_root / "eval" / "src" / "skylark_lumi_trace_eval.egg-info" / "SOURCES.txt",
    ):
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text("generated and not distributable\n", encoding="utf-8")

    output = tmp_path / "dist"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(output),
        ],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )

    distributions = list(output.glob("*.tar.gz"))
    assert len(distributions) == 1
    with tarfile.open(distributions[0], mode="r:gz") as archive:
        members = [PurePosixPath(member.name) for member in archive.getmembers()]
    assert any(member.name == "MANIFEST.in" for member in members)
    assert any(member.as_posix().endswith("/src/lumi_trace/__init__.py") for member in members)
    assert not any("evidence" in member.parts for member in members)
    assert not any("build" in member.parts for member in members)
    assert not any(".pytest_cache" in member.parts for member in members)
    assert not any(".ruff_cache" in member.parts for member in members)
    assert not any(member.name == "skylark_lumi_trace_eval.egg-info" for member in members)


def test_v0_3_public_evidence_verifies_and_detects_tamper(
    tmp_path: Path, project_root: Path
) -> None:
    evidence = project_root / "evidence" / "v0.3.0"
    if not evidence.is_dir():
        pytest.skip("V0.3 seal is generated after the implementation revision is committed")
    manifest = verify_v0_3_evidence(evidence)
    assert manifest["source_revision"]

    copied = tmp_path / "v0.3.0"
    shutil.copytree(evidence, copied)
    summary = copied / "natural-corpus-summary.json"
    value = json.loads(summary.read_text(encoding="utf-8"))
    value["accepted_groups"] = 1
    summary.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact mismatch"):
        verify_v0_3_evidence(copied)


def test_v0_3_1_public_evidence_verifies_and_detects_tamper(
    tmp_path: Path, project_root: Path
) -> None:
    evidence = project_root / "evidence" / "v0.3.1"
    if not evidence.is_dir():
        pytest.skip("V0.3.1 seal is generated after the implementation revision is committed")
    manifest = verify_v0_3_1_evidence(evidence)
    assert manifest["source_revision"]

    copied = tmp_path / "v0.3.1"
    shutil.copytree(evidence, copied)
    resource = copied / "resource-summary.json"
    value = json.loads(resource.read_text(encoding="utf-8"))
    value["development"]["completed_attempts"] = 40
    resource.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact mismatch"):
        verify_v0_3_1_evidence(copied)


def test_v0_3_2_public_evidence_verifies_and_detects_tamper(
    tmp_path: Path, project_root: Path
) -> None:
    evidence = project_root / "evidence" / "v0.3.2"
    if not evidence.is_dir():
        pytest.skip("V0.3.2 seal is generated after the qualification decision")
    manifest = verify_v0_3_2_evidence(evidence)
    assert manifest["source_revision"]

    copied = tmp_path / "v0.3.2"
    shutil.copytree(evidence, copied)
    resource = copied / "resource-summary.json"
    value = json.loads(resource.read_text(encoding="utf-8"))
    value["development"]["completed_attempts"] = 39
    resource.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact mismatch"):
        verify_v0_3_2_evidence(copied)


def test_v0_4_public_evidence_verifies_and_detects_tamper(
    tmp_path: Path, project_root: Path
) -> None:
    evidence = project_root / "evidence" / "v0.4"
    if not evidence.is_dir():
        pytest.skip("V0.4 seal is generated after the qualification decision")
    manifest = verify_v0_4_evidence(evidence)
    assert manifest["source_revision"]

    copied = tmp_path / "v0.4"
    shutil.copytree(evidence, copied)
    closure = copied / "closure-record.json"
    value = json.loads(closure.read_text(encoding="utf-8"))
    value["public_release"] = True
    closure.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact mismatch"):
        verify_v0_4_evidence(copied)


def test_v0_4_1_public_evidence_verifies_and_detects_tamper(
    tmp_path: Path, project_root: Path
) -> None:
    evidence = project_root / "evidence" / "v0.4.1"
    if not evidence.is_dir():
        pytest.skip("V0.4.1 seal is generated after final development evidence")
    manifest = verify_v0_4_1_evidence(evidence)
    assert manifest["seal_id"].startswith("lumi-trace-v0.4.1-public-evidence:")

    copied = tmp_path / "v0.4.1"
    shutil.copytree(evidence, copied)
    payload = copied / "closure-record.json"
    payload.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(Exception, match="does not match"):
        verify_v0_4_1_evidence(copied)
