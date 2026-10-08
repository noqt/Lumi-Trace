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
# Published v0.10.0 release asset 500802915; SHA-256:
# fb788f981dbf681d08f2edf2513e1b2f3dceb69bc3f9f8d270a42f6d430035920.
PUBLISHED_RELEASE_VERSION = "v0.10.0"
PUBLISHED_RELEASE_WHEEL = "skylark_lumi_trace-0.10.0-py3-none-any.whl"
PUBLISHED_RELEASE_WARNING = (
    "Use the filename from the release you downloaded. Do not copy the "
    f"`{PUBLISHED_RELEASE_VERSION.removeprefix('v')}` command against a different release."
)
BASH_RELEASE_INSTALL = f"python -m pip install --no-deps ./{PUBLISHED_RELEASE_WHEEL}"
POWERSHELL_RELEASE_INSTALL = (
    f".\\.venv\\Scripts\\python.exe -m pip install --no-deps `\n  .\\{PUBLISHED_RELEASE_WHEEL}"
)


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


def test_component_scoped_guidance_preserves_the_evidence_boundary(project_root: Path) -> None:
    getting_started = " ".join(
        (project_root / "docs/GETTING_STARTED.md").read_text(encoding="utf-8").split()
    )
    inputs = " ".join(
        (project_root / "docs/INPUTS_AND_OUTPUTS.md").read_text(encoding="utf-8").split()
    )
    scope = " ".join((project_root / "docs/PRODUCT_SCOPE.md").read_text(encoding="utf-8").split())

    assert "known fix file" in getting_started
    assert "full repository" in getting_started
    assert "covers only the directory" in getting_started
    assert "known remediation path" in inputs
    assert "only the supplied tree" in inputs
    assert "Lumi Trace does not select or infer the component" in scope
    assert "does not establish that other repository areas" in scope


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


def _release_install_section(readme: str) -> str:
    headings = list(re.finditer(r"(?m)^### From a GitHub Release[ \t]*\r?$", readme))
    assert len(headings) == 1, "expected one '### From a GitHub Release' section"

    section_start = headings[0].end()
    next_heading = re.search(r"(?m)^#{1,3}[ \t]+", readme[section_start:])
    section_end = section_start + next_heading.start() if next_heading else len(readme)
    return readme[section_start:section_end]


def _assert_published_release_install_contract(readme: str) -> None:
    section = _release_install_section(readme)

    bash_blocks = re.findall(r"(?ms)^```sh[ \t]*\r?\n(.*?)^```[ \t]*\r?$", section)
    assert len(bash_blocks) == 1, "expected one Bash install code block in the release section"
    bash_commands = [
        line.strip() for line in bash_blocks[0].splitlines() if "-m pip install" in line
    ]
    assert bash_commands == [BASH_RELEASE_INSTALL]

    powershell_blocks = re.findall(r"(?ms)^```powershell[ \t]*\r?\n(.*?)^```[ \t]*\r?$", section)
    assert len(powershell_blocks) == 1, (
        "expected one PowerShell install code block in the release section"
    )
    powershell_lines = powershell_blocks[0].splitlines()
    powershell_commands: list[str] = []
    for index, line in enumerate(powershell_lines):
        if "-m pip install" not in line:
            continue
        command = line.strip()
        if command.endswith("`") and index + 1 < len(powershell_lines):
            command += "\n" + powershell_lines[index + 1]
        powershell_commands.append(command)
    assert powershell_commands == [POWERSHELL_RELEASE_INSTALL]

    warning_lines = [
        " ".join(line.split())
        for line in section.splitlines()
        if "filename" in line.casefold() or "different release" in line.casefold()
    ]
    assert warning_lines == [PUBLISHED_RELEASE_WARNING]


def _valid_release_install_example() -> str:
    return f"""### From a GitHub Release

Download the wheel for the version you want from GitHub Releases.

Bash:

```sh
python3 -m venv .venv
. .venv/bin/activate
{BASH_RELEASE_INSTALL}
lumi-trace version
```

PowerShell:

```powershell
py -3.12 -m venv .venv
{POWERSHELL_RELEASE_INSTALL}
.\\.venv\\Scripts\\lumi-trace.exe version
```

{PUBLISHED_RELEASE_WARNING}

### Verify a downloaded release
"""


@pytest.mark.parametrize(
    "invalid_case",
    (
        "wrong-bash-wheel",
        "wrong-powershell-wheel",
        "wrong-warning",
        "missing-section",
        "duplicate-section",
        "correct-wheel-elsewhere",
    ),
)
def test_release_install_contract_rejects_invalid_examples(invalid_case: str) -> None:
    readme = _valid_release_install_example()
    wrong_wheel = "skylark_lumi_trace-0.10.1-py3-none-any.whl"

    if invalid_case == "wrong-bash-wheel":
        readme = readme.replace(
            BASH_RELEASE_INSTALL,
            BASH_RELEASE_INSTALL.replace(PUBLISHED_RELEASE_WHEEL, wrong_wheel),
            1,
        )
    elif invalid_case == "wrong-powershell-wheel":
        readme = readme.replace(
            POWERSHELL_RELEASE_INSTALL,
            POWERSHELL_RELEASE_INSTALL.replace(PUBLISHED_RELEASE_WHEEL, wrong_wheel),
            1,
        )
    elif invalid_case == "wrong-warning":
        readme = readme.replace(
            PUBLISHED_RELEASE_WARNING,
            "Use the 0.10.1 wheel for this release.",
            1,
        )
    elif invalid_case == "missing-section":
        readme = readme.replace("### From a GitHub Release", "### From source", 1)
    elif invalid_case == "duplicate-section":
        readme += "\n### From a GitHub Release\n"
    elif invalid_case == "correct-wheel-elsewhere":
        readme = readme.replace(
            BASH_RELEASE_INSTALL,
            BASH_RELEASE_INSTALL.replace(PUBLISHED_RELEASE_WHEEL, wrong_wheel),
            1,
        )
        readme = readme.replace(
            POWERSHELL_RELEASE_INSTALL,
            POWERSHELL_RELEASE_INSTALL.replace(PUBLISHED_RELEASE_WHEEL, wrong_wheel),
            1,
        )
        readme += f"\nThe published asset is {PUBLISHED_RELEASE_WHEEL}.\n"

    with pytest.raises(AssertionError):
        _assert_published_release_install_contract(readme)


def test_release_install_example_is_pinned_to_published_release_not_source_version(
    project_root: Path,
) -> None:
    project = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    source_version = re.search(r'^version = "([^"]+)"$', project, flags=re.MULTILINE)
    assert source_version is not None
    assert source_version.group(1) == "0.10.1"

    readme = (project_root / "README.md").read_text(encoding="utf-8")
    assert "https://github.com/noqt/Lumi-Trace/releases" in readme
    _assert_published_release_install_contract(readme)
