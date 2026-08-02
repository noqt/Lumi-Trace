# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PRODUCT_DOCUMENTS = (
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("DISCLAIMER.md"),
    Path("docs/README.md"),
    Path("docs/GETTING_STARTED.md"),
    Path("docs/PRODUCT_SCOPE.md"),
    Path("docs/INPUTS_AND_OUTPUTS.md"),
    Path("docs/REPRODUCTION.md"),
    Path("docs/PRIVACY.md"),
    Path("docs/THREAT_MODEL.md"),
    Path("docs/ARCHITECTURE.md"),
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def test_public_document_links_resolve(project_root: Path) -> None:
    failures: list[str] = []
    documents = set(PRODUCT_DOCUMENTS)
    for root in ("docs", ".github/maintainers", "examples/quickstart"):
        documents.update(
            path.relative_to(project_root) for path in (project_root / root).rglob("*.md")
        )
    for relative in sorted(documents):
        document = project_root / relative
        assert document.is_file(), relative
        text = document.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().strip("<>")
            if (
                not target
                or target.startswith("#")
                or target.startswith(("https://", "http://", "mailto:"))
            ):
                continue
            path_text = target.split("#", 1)[0]
            resolved = (document.parent / path_text).resolve()
            if not resolved.exists():
                failures.append(f"{relative}: {target}")
    assert not failures, "broken local documentation links:\n" + "\n".join(failures)


def test_internal_programme_material_is_outside_the_product_path(project_root: Path) -> None:
    combined = "\n".join(
        (project_root / relative).read_text(encoding="utf-8") for relative in PRODUCT_DOCUMENTS
    ).casefold()
    assert "step_1_release_gate" not in combined
    assert "docs/build-briefs" not in combined
    assert not (project_root / "docs" / "STEP_1_RELEASE_GATE.md").exists()
    assert not (project_root / "docs" / "build-briefs").exists()


def test_quickstart_is_ascii_apache_licensed_and_inert(project_root: Path) -> None:
    quickstart = project_root / "examples" / "quickstart"
    files = (
        quickstart / "README.md",
        quickstart / "finding.json",
        quickstart / "repository" / "src" / "archive.py",
    )
    for path in files:
        payload = path.read_bytes()
        assert payload
        assert all(byte < 128 for byte in payload), path
    assert "Apache-2.0" in files[0].read_text(encoding="ascii")
    assert "SPDX-License-Identifier: Apache-2.0" in files[2].read_text(encoding="ascii")
    assert "open(" not in files[2].read_text(encoding="ascii")


@pytest.mark.skipif(sys.implementation.name != "cpython", reason="CPython is the supported runtime")
def test_clean_source_install_runs_and_verifies_public_quickstart(
    project_root: Path,
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "site"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-build-isolation",
            "--target",
            str(install_root),
            str(project_root),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert install.returncode == 0, install.stderr

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(install_root)
    environment["PYTHONNOUSERSITE"] = "1"
    output = tmp_path / "quickstart-evidence"
    trace = subprocess.run(
        [
            sys.executable,
            "-m",
            "lumi_trace",
            "trace",
            "--finding",
            "examples/quickstart/finding.json",
            "--finding-format",
            "manual",
            "--repository",
            "examples/quickstart/repository",
            "--output",
            str(output),
        ],
        cwd=project_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert trace.returncode == 0, trace.stderr
    summary = json.loads(trace.stdout)
    assert summary["classification"] == "INSUFFICIENT_EVIDENCE"
    assert summary["reason_codes"] == ["NO_REPRODUCTION_PLAN"]
    assert summary["top_implementation_locations"][0] == {
        "integer_score": 205272,
        "path": "src/archive.py",
        "rank": 1,
        "role": "implementation",
        "symbol": "extraction_target",
    }
    assert "Localisation: complete" in trace.stderr
    assert "Confirmation: not attempted (NO_REPRODUCTION_PLAN)" in trace.stderr

    candidates = json.loads((output / "candidates.json").read_text(encoding="utf-8"))
    assert candidates["candidates"][0]["path"] == "src/archive.py"
    assert candidates["candidates"][0]["symbol"]["qualified_name"] == "extraction_target"

    verify = subprocess.run(
        [sys.executable, "-m", "lumi_trace", "verify", str(output)],
        cwd=project_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert verify.returncode == 0, verify.stderr
    assert json.loads(verify.stdout) == {"input": str(output), "valid": True}


def test_release_install_example_matches_source_version(project_root: Path) -> None:
    project = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    readme = (project_root / "README.md").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"$', project, flags=re.MULTILINE)
    assert version is not None
    release_version = version.group(1)
    assert f"releases/tag/v{release_version}" in readme
    assert f"skylark_lumi_trace-{release_version}-py3-none-any.whl" in readme
