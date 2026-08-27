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
    assert action["branding"] == {"icon": "search", "color": "purple"}
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


def test_python_appsec_demo_is_manual_read_only_and_uses_verified_release(
    project_root: Path,
) -> None:
    workflow_path = project_root / ".github" / "workflows" / "python-appsec-demo.yml"
    source = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["run-synthetic-example"]
    assert job["timeout-minutes"] == "10"
    steps = job["steps"]
    assert steps[0]["uses"] == ("actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405")
    assert "--no-deps --no-index" in source
    assert "sha256sum --check expected-release-sha256.txt" in source
    assert "sha256sum --check SHA256SUMS" in source
    assert 'filter="data"' in source
    assert "fb788f981dbf681d08f2edf2515db8e968669ef23f5109cac31bfad866cce11d" in source
    assert "a28123e75fd4a47bd551a0c300d043b0156badba61843c3769a649b8017fe690" in source
    assert "cf5cb839baf28fe6cae7691ec8832db03d92dd924f65ab59b988ec1bb8152268" in source
    assert "actions/checkout" not in source
    assert "actions/upload-artifact" not in source
    assert "pull_request:" not in source
    assert "push:" not in source


def test_python_appsec_worked_example_links_fork_and_run_workflow(project_root: Path) -> None:
    page = (project_root / "docs" / "experiments" / "lumi-python-appsec-context-v1.md").read_text(
        encoding="utf-8"
    )
    link = "../../.github/workflows/python-appsec-demo.yml"
    assert page.index(link) < page.index("This worked example")
    assert "enable Actions for the fork" in page
    assert "uploads no evidence artifact" in page
    assert "No local installation is required" in page
    assert "2026-08-24T05:57:53Z" in page
    assert "9f4c566c9298be7c4973054c1dbb8057c57f40c2" in page
    assert "9f3572c6f2d951587df1c9ac49d1fedf996054a0" in page
    assert "does not create a second activation" in page


def test_bandit_demo_fixture_produces_one_verified_review_path(
    project_root: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "bandit-demo"
    workspace.mkdir(parents=True)
    fixture = project_root / "examples" / "bandit-demo"
    shutil.copy2(fixture / "bandit.sarif", workspace / "findings.sarif")
    shutil.copytree(fixture / "repository", workspace / "repository")

    completed, outputs, summary = _run_action(project_root, workspace, tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "complete"
    assert outputs["selected-results"] == "1"
    assert outputs["completed-localizations"] == "1"
    assert outputs["unique-review-paths"] == "1"
    assert "app.py" in summary
    assert "Synthetic example" not in summary


def test_bandit_demo_workflow_is_manual_read_only_and_uploads_nothing(
    project_root: Path,
) -> None:
    path = project_root / ".github" / "workflows" / "bandit-sarif-demo.yml"
    source = path.read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["run-synthetic-bandit-example"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "10"
    assert job["steps"][0]["uses"] == ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
    assert job["steps"][1]["uses"] == (
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
    )
    bandit_step = job["steps"][2]
    assert bandit_step["name"] == "Generate a real Bandit SARIF report"
    assert bandit_step["working-directory"] == "examples/bandit-demo/repository"
    assert bandit_step["env"]["BANDIT_SARIF"] == ("${{ github.workspace }}/.lumi-bandit-demo.sarif")
    assert '"bandit[sarif]==1.9.4"' in bandit_step["run"]
    assert "--ignore-nosec" in bandit_step["run"]
    assert "--tests B602" in bandit_step["run"]
    assert "--recursive ." in bandit_step["run"]
    assert 'test "$bandit_exit_code" -eq 1' in bandit_step["run"]
    assert job["steps"][3]["uses"] == "./"
    assert job["steps"][3]["with"]["sarif"] == ".lumi-bandit-demo.sarif"
    assert job["steps"][3]["with"]["upload-artifact"] == "false"
    assert job["steps"][5]["name"] == "Make the next step obvious"
    assert job["steps"][5]["env"]["RUN_URL"] == (
        "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
    )
    assert 'echo "$RUN_URL"' in source
    assert '} >> "$GITHUB_STEP_SUMMARY"' in source
    assert "Copy that link into the short Bandit demo result form" in source
    assert "https://github.com/noqt/Lumi-Trace/issues/new?template=bandit_demo_result.yml" in source
    assert "Don't include secrets" in source
    assert "pull_request:" not in source
    assert "push:" not in source
