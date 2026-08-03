# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import yaml

from lumi_trace.triage import verify_triage_package


def _action_module(project_root: Path) -> ModuleType:
    path = project_root / "tools" / "github_action.py"
    spec = importlib.util.spec_from_file_location("lumi_trace_github_action_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _consumer_workspace(project_root: Path, tmp_path: Path, *, partial: bool = False) -> Path:
    workspace = tmp_path / "consumer"
    workspace.mkdir(parents=True)
    shutil.copytree(
        project_root / "tests" / "fixtures" / "localization-repository",
        workspace / "repository",
    )
    source = json.loads((project_root / "tests" / "data" / "finding.sarif").read_text("utf-8"))
    if partial:
        original = source["runs"][0]["results"][0]
        invalid = deepcopy(original)
        invalid["locations"] = "not-an-array"
        source["runs"][0]["results"].append(invalid)
    (workspace / "findings.sarif").write_text(json.dumps(source), encoding="utf-8")
    return workspace


def _parse_outputs(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text("utf-8").splitlines() if line)


def _run_action(
    project_root: Path,
    workspace: Path,
    tmp_path: Path,
    **inputs: str,
) -> tuple[subprocess.CompletedProcess[str], dict[str, str], str]:
    output = tmp_path / "github-output.txt"
    summary = tmp_path / "github-summary.md"
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "LUMI_TRACE_ACTION_SARIF": "findings.sarif",
            "LUMI_TRACE_ACTION_REPOSITORY": "repository",
            "LUMI_TRACE_ACTION_OUTPUT": ".lumi-trace",
            "LUMI_TRACE_ACTION_TOP_K": "10",
            "LUMI_TRACE_ACTION_MAX_FINDINGS": "100",
            "LUMI_TRACE_ACTION_FAIL_ON_PARTIAL": "true",
            "LUMI_TRACE_ACTION_FAIL_ON_SEVERITY": "none",
            "LUMI_TRACE_ACTION_ARTIFACT_NAME": "lumi-trace-evidence",
        }
    )
    action_inputs = {
        f"LUMI_TRACE_ACTION_{name.upper().replace('-', '_')}": value
        for name, value in inputs.items()
    }
    environment.update(action_inputs)
    completed = subprocess.run(
        [sys.executable, str(project_root / "tools" / "github_action.py")],
        cwd=workspace,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
        timeout=90,
    )
    return completed, _parse_outputs(output), summary.read_text("utf-8")


def test_action_produces_verified_complete_package_and_bounded_summary(
    project_root: Path, tmp_path: Path
) -> None:
    workspace = _consumer_workspace(project_root, tmp_path)

    completed, outputs, summary = _run_action(project_root, workspace, tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert outputs == {
        "status": "complete",
        "exit-code": "0",
        "selected-results": "1",
        "completed-localizations": "1",
        "result-local-errors": "0",
        "unique-review-paths": "2",
        "evidence-path": ".lumi-trace",
        "package-ready": "true",
        "artifact-name": "lumi-trace-evidence",
    }
    verify_triage_package(workspace / ".lumi-trace")
    assert "## Lumi Trace review summary" in summary
    assert (
        "Queue order is review priority, not vulnerability probability or exploitability."
        in summary
    )
    assert str(workspace) not in summary
    assert "unsafe_join accepts" not in summary


def test_action_preserves_verified_partial_package_before_policy_failure(
    project_root: Path, tmp_path: Path
) -> None:
    workspace = _consumer_workspace(project_root, tmp_path, partial=True)

    completed, outputs, summary = _run_action(project_root, workspace, tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "partial-failed"
    assert outputs["exit-code"] == "5"
    assert outputs["package-ready"] == "true"
    verify_triage_package(workspace / ".lumi-trace")
    assert "Result errors" in summary


def test_action_can_allow_partial_package_and_enforce_scanner_severity(
    project_root: Path, tmp_path: Path
) -> None:
    partial_workspace = _consumer_workspace(project_root, tmp_path / "partial", partial=True)
    completed, outputs, _ = _run_action(
        project_root,
        partial_workspace,
        tmp_path / "partial",
        **{"fail-on-partial": "false"},
    )
    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "partial-success"
    assert outputs["exit-code"] == "0"

    severity_workspace = _consumer_workspace(project_root, tmp_path / "severity")
    completed, outputs, summary = _run_action(
        project_root,
        severity_workspace,
        tmp_path / "severity",
        **{"fail-on-severity": "low"},
    )
    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "policy-failed"
    assert outputs["exit-code"] == "1"
    assert outputs["package-ready"] == "true"
    assert "configured scanner-severity threshold triggered" in summary


def test_action_rejects_workspace_escape_without_echoing_untrusted_input(
    project_root: Path, tmp_path: Path
) -> None:
    workspace = _consumer_workspace(project_root, tmp_path)

    completed, outputs, summary = _run_action(
        project_root,
        workspace,
        tmp_path,
        **{"sarif": "../::warning::not-a-report"},
    )

    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "input-error"
    assert outputs["exit-code"] == "2"
    assert outputs["package-ready"] == "false"
    assert "::warning::" not in summary
    assert not (workspace / ".lumi-trace").exists()


def test_action_escapes_summary_cells_and_declares_only_safe_shelling(project_root: Path) -> None:
    module = _action_module(project_root)
    rendered = module._escape_markdown_cell("<img src=x>|`[x](y)\n::warning::")
    assert "<" not in rendered
    assert "|" not in rendered.replace("\\|", "")
    assert "\n" not in rendered
    source = (project_root / "tools" / "github_action.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "os.system" not in source


def test_composite_action_is_pinned_and_uses_adapter_outputs(project_root: Path) -> None:
    action = yaml.safe_load((project_root / "action.yml").read_text(encoding="utf-8"))
    assert action["name"] == "Lumi Trace"
    assert set(action["inputs"]) == {
        "sarif",
        "repository",
        "output",
        "top-k",
        "max-findings",
        "fail-on-partial",
        "fail-on-severity",
        "upload-artifact",
        "artifact-name",
    }
    steps = action["runs"]["steps"]
    referenced_actions = [step["uses"] for step in steps if "uses" in step]
    reference = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")
    assert all(reference.fullmatch(value.split()[0]) for value in referenced_actions)
    assert "steps.triage.outputs.evidence-path" in steps[2]["with"]["path"]
    assert "github.workspace" in steps[2]["with"]["path"]
    assert steps[2]["with"]["include-hidden-files"] is True
    assert "github_action.py" in steps[1]["run"]


def test_action_source_is_retained_in_the_source_distribution(project_root: Path) -> None:
    manifest = (project_root / "MANIFEST.in").read_text(encoding="utf-8")
    assert "include action.yml" in manifest
    assert "include tools/github_action.py" in manifest
