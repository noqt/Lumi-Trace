# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from scripts.build_step1_release_evidence import (
    ReleaseEvidenceError,
    build_release_evidence,
    inspect_release_artifacts,
    verify_canonical_sdist,
)
from scripts.normalize_step1_sdist import NormalizationError, normalize_sdist

REVISION = "a" * 40
SOURCE_DATE_EPOCH = 1_784_995_200
PACKAGE_ROOT = "skylark_lumi_trace-0.4.1"
METADATA = (
    b"Metadata-Version: 2.4\n"
    b"Name: skylark-lumi-trace\n"
    b"Version: 0.4.1\n"
    b"License-Expression: Apache-2.0\n"
    b"Requires-Python: <3.13,>=3.11\n"
    b"\n"
)


def _wheel(path: Path, extra: dict[str, bytes] | None = None) -> None:
    members = {
        "lumi_trace/__init__.py": b'__version__ = "0.4.1"\n',
        f"{PACKAGE_ROOT}.dist-info/METADATA": METADATA,
        f"{PACKAGE_ROOT}.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{PACKAGE_ROOT}.dist-info/licenses/LICENSE": b"Apache License\nVersion 2.0\n",
    }
    members.update(extra or {})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(members.items()):
            archive.writestr(name, payload)


def _sdist(
    path: Path,
    extra: dict[str, bytes] | None = None,
    *,
    member_mtime: int = SOURCE_DATE_EPOCH,
) -> None:
    members = {
        f"{PACKAGE_ROOT}/PKG-INFO": METADATA,
        f"{PACKAGE_ROOT}/LICENSE": b"Apache License\nVersion 2.0\n",
        f"{PACKAGE_ROOT}/src/lumi_trace/__init__.py": b'__version__ = "0.4.1"\n',
    }
    members.update({f"{PACKAGE_ROOT}/{name}": payload for name, payload in (extra or {}).items()})
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in sorted(members.items()):
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = member_mtime
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def _pair(tmp_path: Path) -> tuple[Path, Path]:
    wheel = tmp_path / f"{PACKAGE_ROOT}-py3-none-any.whl"
    sdist = tmp_path / f"{PACKAGE_ROOT}.tar.gz"
    raw_sdist = tmp_path / f"raw-{PACKAGE_ROOT}.tar.gz"
    _wheel(wheel)
    _sdist(raw_sdist)
    normalize_sdist(raw_sdist, sdist, source_date_epoch=SOURCE_DATE_EPOCH)
    return wheel, sdist


def test_builds_hash_bound_spdx_release_evidence(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    output = tmp_path / "evidence"

    manifest = build_release_evidence(
        wheel=wheel,
        sdist=sdist,
        output=output,
        source_revision=REVISION,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )

    assert manifest["evidence_id"].startswith("lumi-trace-step1-release-evidence:")
    assert {item["path"] for item in manifest["members"]} == {
        "SHA256SUMS",
        "artifact-inventory.json",
        "environment.json",
        "sbom.spdx.json",
        "summary.json",
    }
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["overall_status"] == "PASS"
    assert summary["publication_authorised"] is False
    sbom = json.loads((output / "sbom.spdx.json").read_text(encoding="utf-8"))
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert {item["packageFileName"] for item in sbom["packages"]} == {
        wheel.name,
        sdist.name,
    }
    assert all(item["licenseDeclared"] == "Apache-2.0" for item in sbom["packages"])
    assert "C:\\" not in (output / "environment.json").read_text(encoding="utf-8")


def test_sdist_normalization_removes_build_and_checkout_timestamps(tmp_path: Path) -> None:
    first_raw = tmp_path / "first-raw.tar.gz"
    second_raw = tmp_path / "second-raw.tar.gz"
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _sdist(first_raw, member_mtime=SOURCE_DATE_EPOCH + 1)
    _sdist(second_raw, member_mtime=SOURCE_DATE_EPOCH + 999)

    first_hash = normalize_sdist(
        first_raw,
        first,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )
    second_hash = normalize_sdist(
        second_raw,
        second,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )

    assert first_hash == second_hash
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        assert archive.getmembers()
        assert all(member.mtime == SOURCE_DATE_EPOCH for member in archive.getmembers())
        assert all(member.uid == 0 and member.gid == 0 for member in archive.getmembers())
        assert all(not member.pax_headers for member in archive.getmembers())
    verify_canonical_sdist(first, source_date_epoch=SOURCE_DATE_EPOCH)


def test_sdist_normalization_rejects_traversal(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.tar.gz"
    output = tmp_path / "normalized.tar.gz"
    with tarfile.open(source, mode="w:gz") as archive:
        payload = b"escape\n"
        member = tarfile.TarInfo("../escape.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(NormalizationError, match="unsafe sdist member"):
        normalize_sdist(source, output, source_date_epoch=SOURCE_DATE_EPOCH)


@pytest.mark.parametrize(
    "forbidden_member",
    (
        "eval/src/trace_eval/runner.py",
        "docs/TRACE_EVAL_RECREATION.md",
        "docs/build-briefs/internal.md",
        "weights/private.safetensors",
        "__pycache__/cached.pyc",
    ),
)
def test_rejects_forbidden_wheel_members(
    tmp_path: Path,
    forbidden_member: str,
) -> None:
    wheel, sdist = _pair(tmp_path)
    _wheel(wheel, {forbidden_member: b"not releasable\n"})

    with pytest.raises(ReleaseEvidenceError, match="forbidden"):
        inspect_release_artifacts(wheel, sdist)


def test_rejects_local_host_paths_in_payloads(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    _wheel(wheel, {"lumi_trace/config.py": b'PRIVATE_ROOT = "G:/Data/private"\n'})

    with pytest.raises(ReleaseEvidenceError, match="absolute Windows drive path"):
        inspect_release_artifacts(wheel, sdist)


def test_rejects_example_content_in_package(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    _wheel(
        wheel,
        {"share/skylark-lumi-trace/examples/finding.json": b'{"title":"sample"}\n'},
    )

    with pytest.raises(ReleaseEvidenceError, match="forbidden"):
        inspect_release_artifacts(wheel, sdist)


def test_rejects_serialized_model_json(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    _wheel(
        wheel,
        {
            "share/model.json": json.dumps(
                {
                    "schema_version": "local-linear-model-v1",
                    "weights": [1, 2, 3],
                }
            ).encode()
        },
    )

    with pytest.raises(ReleaseEvidenceError, match="serialized model"):
        inspect_release_artifacts(wheel, sdist)


def test_rejects_runtime_dependencies(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    dependent_metadata = METADATA.replace(
        b"\n\n",
        b"\nRequires-Dist: requests==2.0\n\n",
    )
    _wheel(wheel, {f"{PACKAGE_ROOT}.dist-info/METADATA": dependent_metadata})
    _sdist(sdist, {"PKG-INFO": dependent_metadata})

    with pytest.raises(ReleaseEvidenceError, match="runtime dependencies"):
        inspect_release_artifacts(wheel, sdist)


def test_rejects_unsupported_python_range(tmp_path: Path) -> None:
    wheel, sdist = _pair(tmp_path)
    unsupported_metadata = METADATA.replace(
        b"Requires-Python: <3.13,>=3.11",
        b"Requires-Python: >=3.11",
    )
    _wheel(wheel, {f"{PACKAGE_ROOT}.dist-info/METADATA": unsupported_metadata})
    _sdist(sdist, {"PKG-INFO": unsupported_metadata})

    with pytest.raises(ReleaseEvidenceError, match="Requires-Python"):
        inspect_release_artifacts(wheel, sdist)


def test_project_distributions_have_a_minimal_product_boundary(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(
        project_root,
        source,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".pytest_cache",
            ".ruff_cache",
            "__pycache__",
            "*.egg-info",
            "build",
            "dist",
            "out",
        ),
    )
    output = tmp_path / "dist"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(output),
        ],
        cwd=source,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr

    wheel = next(output.glob("*.whl"))
    sdist = next(output.glob("*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_payloads = {
            name: archive.read(name) for name in archive.namelist() if not name.endswith("/")
        }
    with tarfile.open(sdist, mode="r:gz") as archive:
        source_payloads = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            source_payloads[member.name] = extracted.read()

    source_root = PurePosixPath(next(iter(source_payloads))).parts[0]
    logical_source_names = {
        PurePosixPath(*PurePosixPath(name).parts[1:]).as_posix()
        for name in source_payloads
        if PurePosixPath(name).parts[0] == source_root
    }
    all_names = {*wheel_payloads, *logical_source_names}
    lowered_names = {name.casefold() for name in all_names}
    assert any(name.endswith("lumi_trace/cli.py") for name in all_names)
    for document in (
        "ARCHITECTURE.md",
        "GETTING_STARTED.md",
        "INPUTS_AND_OUTPUTS.md",
        "PRIVACY.md",
        "PRODUCT_SCOPE.md",
        "README.md",
        "REPRODUCTION.md",
        "THREAT_MODEL.md",
    ):
        assert any(name.endswith(f"docs/{document}") for name in all_names)
    assert any(name.endswith("docs/reference/SCHEMA_COMPATIBILITY.md") for name in all_names)
    assert {name for name in logical_source_names if name.startswith("examples/quickstart/")} == {
        "examples/quickstart/README.md",
        "examples/quickstart/finding.json",
        "examples/quickstart/repository/src/archive.py",
    }
    assert not any("examples/" in name for name in wheel_payloads)
    assert any(name.endswith("schemas/evidence-bundle-v1.json") for name in all_names)

    forbidden_parts = {
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build-briefs",
        "eval",
        "evidence",
        "tests",
        "trace_eval",
    }
    assert not any(
        forbidden_parts & {part.casefold() for part in PurePosixPath(name).parts}
        for name in all_names
    )
    assert not any(name.startswith("scripts/") for name in logical_source_names)
    assert not any("docs/research/" in name.casefold() for name in all_names)
    assert not any(".github/maintainers/" in name.casefold() for name in all_names)
    assert not any("step_1_release_gate" in name.casefold() for name in all_names)
    assert not any(
        PurePosixPath(name).suffix.casefold()
        in {
            ".bin",
            ".ckpt",
            ".gguf",
            ".onnx",
            ".pt",
            ".pth",
            ".safetensors",
        }
        for name in all_names
    )
    assert not any("trace_eval" in name or "training_readiness" in name for name in lowered_names)

    forbidden_payload_terms = (
        b"step_1_release_gate",
        b"docs/build-briefs",
        b"ckpt-003",
        b"no_go_pending_user_review",
        b"do_not_begin_trace_001",
        b"employment-contract",
        b"employer-time contribution",
        b"employment/ip",
    )
    packaged_payloads = [*wheel_payloads.values(), *source_payloads.values()]
    assert not any(
        term in payload.lower() for payload in packaged_payloads for term in forbidden_payload_terms
    )

    host_path = re.compile(
        rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|"
        rb"(?<![A-Za-z0-9])/(?:home|Users)/[A-Za-z0-9._-]+/"
    )
    assert not any(host_path.search(payload) for payload in wheel_payloads.values())
    assert not any(host_path.search(payload) for payload in source_payloads.values())
