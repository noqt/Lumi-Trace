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

import pytest
import yaml

from lumi_trace.errors import InputError, IntegrityError
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


def _bandit_workspace(project_root: Path, tmp_path: Path, *, result_count: int) -> Path:
    workspace = tmp_path / "consumer"
    workspace.mkdir(parents=True)
    fixture = project_root / "examples" / "bandit-demo"
    shutil.copytree(fixture / "repository", workspace / "repository")
    source = json.loads((fixture / "bandit.sarif").read_text("utf-8"))
    source["runs"][0]["results"] = source["runs"][0]["results"][:result_count]
    (workspace / "findings.sarif").write_text(json.dumps(source), encoding="utf-8")
    return workspace


def _package_bytes(path: Path) -> dict[str, bytes]:
    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in sorted(path.rglob("*"))
        if item.is_file()
    }


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
    assert "Check the Action paths and bounded input values" in summary
    assert "::warning::" not in summary
    assert str(workspace) not in summary
    assert not (workspace / ".lumi-trace").exists()


def test_action_fatal_failure_excludes_sarif_content_credentials_and_paths(
    project_root: Path, tmp_path: Path
) -> None:
    workspace = _consumer_workspace(project_root, tmp_path)
    secret = "credential-value-must-not-appear-7421"
    (workspace / "findings.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [], "credential": secret}), encoding="utf-8"
    )

    completed, outputs, summary = _run_action(project_root, workspace, tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert outputs["status"] == "fatal-error"
    assert outputs["exit-code"] == "2"
    assert outputs["package-ready"] == "false"
    assert "Validate the local SARIF 2.1.0 input and repository" in summary
    assert secret not in summary
    assert str(workspace) not in summary
    assert "traceback" not in summary.casefold()


def test_action_integrity_failure_excludes_verifier_exception(
    project_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _action_module(project_root)
    workspace = _consumer_workspace(project_root, tmp_path)
    secret = "credential=integrity-secret"
    output = tmp_path / "github-output.txt"
    summary_path = tmp_path / "github-summary.md"
    for name, value in {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary_path),
        "LUMI_TRACE_ACTION_SARIF": "findings.sarif",
        "LUMI_TRACE_ACTION_REPOSITORY": "repository",
        "LUMI_TRACE_ACTION_OUTPUT": ".lumi-trace",
        "LUMI_TRACE_ACTION_TOP_K": "10",
        "LUMI_TRACE_ACTION_MAX_FINDINGS": "100",
        "LUMI_TRACE_ACTION_FAIL_ON_PARTIAL": "true",
        "LUMI_TRACE_ACTION_FAIL_ON_SEVERITY": "none",
        "LUMI_TRACE_ACTION_ARTIFACT_NAME": "lumi-trace-evidence",
    }.items():
        monkeypatch.setenv(name, value)

    def reject_package(_path: Path) -> None:
        raise ValueError(f"{secret}\n{workspace}")

    monkeypatch.setattr(module, "verify_triage_package", reject_package)
    assert module.main() == 0

    outputs = _parse_outputs(output)
    summary = summary_path.read_text("utf-8")
    assert outputs["status"] == "integrity-failure"
    assert outputs["package-ready"] == "false"
    assert "could not verify the generated evidence package" in summary
    assert secret not in summary
    assert str(workspace) not in summary


@pytest.mark.parametrize(
    ("invalid_state", "expected_exception"),
    [
        ("missing-package", None),
        ("missing-manifest", InputError),
        ("tampered-manifest", IntegrityError),
    ],
)
def test_action_maps_real_package_integrity_failures_to_safe_remediation(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_state: str,
    expected_exception: type[Exception] | None,
) -> None:
    module = _action_module(project_root)
    workspace = _consumer_workspace(project_root, tmp_path)
    output = tmp_path / "github-output.txt"
    summary_path = tmp_path / "github-summary.md"
    for name, value in {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary_path),
        "LUMI_TRACE_ACTION_SARIF": "findings.sarif",
        "LUMI_TRACE_ACTION_REPOSITORY": "repository",
        "LUMI_TRACE_ACTION_OUTPUT": ".lumi-trace",
        "LUMI_TRACE_ACTION_TOP_K": "10",
        "LUMI_TRACE_ACTION_MAX_FINDINGS": "100",
        "LUMI_TRACE_ACTION_FAIL_ON_PARTIAL": "true",
        "LUMI_TRACE_ACTION_FAIL_ON_SEVERITY": "none",
        "LUMI_TRACE_ACTION_ARTIFACT_NAME": "lumi-trace-evidence",
    }.items():
        monkeypatch.setenv(name, value)

    real_cli_main = module.cli_main
    package_path = workspace / ".lumi-trace"

    def cli_with_invalid_package(argv: list[str]) -> int:
        exit_code = real_cli_main(argv)
        assert exit_code == 0
        if invalid_state == "missing-package":
            package_path.rename(workspace / ".withheld-lumi-trace")
        elif invalid_state == "missing-manifest":
            (package_path / "manifest.json").rename(workspace / "withheld-manifest.json")
        else:
            manifest_path = package_path / "manifest.json"
            manifest = json.loads(manifest_path.read_text("utf-8"))
            manifest["package_id"] = f"triage-package:{'0' * 64}"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return exit_code

    observed_exceptions: list[Exception] = []
    real_verify_package = module.verify_triage_package

    def observe_verification(path: Path) -> None:
        try:
            real_verify_package(path)
        except (InputError, IntegrityError) as error:
            observed_exceptions.append(error)
            raise

    monkeypatch.setattr(module, "cli_main", cli_with_invalid_package)
    monkeypatch.setattr(module, "verify_triage_package", observe_verification)
    assert module.main() == 0

    outputs = _parse_outputs(output)
    summary = summary_path.read_text("utf-8")
    assert outputs == {
        "status": "integrity-failure",
        "exit-code": "2",
        "selected-results": "",
        "completed-localizations": "",
        "result-local-errors": "",
        "unique-review-paths": "",
        "evidence-path": "",
        "package-ready": "false",
        "artifact-name": "lumi-trace-evidence",
    }
    if expected_exception is None:
        assert observed_exceptions == []
    else:
        assert [type(error) for error in observed_exceptions] == [expected_exception]
        assert all(str(error) not in summary for error in observed_exceptions)
    assert "could not verify the generated evidence package" in summary
    assert str(workspace) not in summary
    assert "traceback" not in summary.casefold()


def test_action_unexpected_failure_uses_only_generic_allowlisted_reason(
    project_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _action_module(project_root)
    workspace = _consumer_workspace(project_root, tmp_path)
    secret = "adapter-secret-must-not-appear"
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", secret)
    output = tmp_path / "github-output.txt"
    summary_path = tmp_path / "github-summary.md"
    for name, value in {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary_path),
        "LUMI_TRACE_ACTION_SARIF": "findings.sarif",
        "LUMI_TRACE_ACTION_REPOSITORY": "repository",
        "LUMI_TRACE_ACTION_OUTPUT": ".lumi-trace",
        "LUMI_TRACE_ACTION_TOP_K": "10",
        "LUMI_TRACE_ACTION_MAX_FINDINGS": "100",
        "LUMI_TRACE_ACTION_FAIL_ON_PARTIAL": "true",
        "LUMI_TRACE_ACTION_FAIL_ON_SEVERITY": "none",
        "LUMI_TRACE_ACTION_ARTIFACT_NAME": "lumi-trace-evidence",
    }.items():
        monkeypatch.setenv(name, value)

    def fail_unexpectedly(_argv: list[str]) -> int:
        raise RuntimeError(
            f"ACTIONS_RUNTIME_TOKEN={os.environ['ACTIONS_RUNTIME_TOKEN']}\n"
            f"{workspace}\n::error::do not render"
        )

    monkeypatch.setattr(module, "cli_main", fail_unexpectedly)
    assert module.main() == 0

    outputs = _parse_outputs(output)
    summary = summary_path.read_text("utf-8")
    assert outputs["status"] == "adapter-error"
    assert outputs["package-ready"] == "false"
    assert "The Lumi Trace Action stopped unexpectedly" in summary
    assert secret not in summary
    assert str(workspace) not in summary
    assert "::error::" not in summary
    assert "traceback" not in summary.casefold()


def test_failure_reason_rendering_is_allowlisted_escaped_single_line_and_bounded(
    project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _action_module(project_root)
    injected = "<tag>|`[x](y)\r\n::error::" + ("x" * 1_000)
    monkeypatch.setitem(module.FAILURE_REASON_TEMPLATES, "adapter-error", injected)

    rendered = module._render_failure_reason("adapter-error")

    assert len(rendered) <= module.MAX_FAILURE_REASON_LENGTH
    assert "\n" not in rendered and "\r" not in rendered
    assert "<" not in rendered
    assert "|" not in rendered.replace("\\|", "")
    assert "`" not in rendered.replace("\\`", "")
    assert module._render_failure_reason("unknown-secret-code") == module._render_failure_reason(
        "adapter-error-unknown"
    )


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
    assert action["outputs"]["package-ready"]["value"] == (
        "${{ steps.triage.outputs.package-ready }}"
    )


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


@pytest.mark.parametrize(("result_count", "expected_paths"), [(0, 0), (1, 1)])
def test_bandit_action_is_deterministic_for_empty_and_nonempty_sarif(
    project_root: Path, tmp_path: Path, result_count: int, expected_paths: int
) -> None:
    attempts: list[tuple[dict[str, str], str, dict[str, bytes]]] = []
    for label in ("first", "second"):
        attempt = tmp_path / label
        workspace = _bandit_workspace(project_root, attempt, result_count=result_count)
        completed, outputs, summary = _run_action(project_root, workspace, attempt)
        assert completed.returncode == 0, completed.stderr
        package = workspace / ".lumi-trace"
        verify_triage_package(package)
        attempts.append((outputs, summary, _package_bytes(package)))

    outputs, summary, package = attempts[0]
    assert outputs["status"] == "complete"
    assert outputs["exit-code"] == "0"
    assert outputs["selected-results"] == str(result_count)
    assert outputs["completed-localizations"] == str(result_count)
    assert outputs["result-local-errors"] == "0"
    assert outputs["unique-review-paths"] == str(expected_paths)
    assert outputs["package-ready"] == "true"
    assert attempts[1][0] == outputs
    assert attempts[1][1] == summary
    assert attempts[1][2] == package
    if result_count == 0:
        assert json.loads(package["review-queue.json"])["entries"] == []
        assert "Bandit reported no findings" in summary
        assert "does not mean the repository is secure" in summary
    else:
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
    assert job["steps"][5]["name"] == "Explain the result and invite feedback"
    assert job["steps"][5]["env"]["LUMI_SELECTED"] == ("${{ steps.lumi.outputs.selected-results }}")
    assert job["steps"][5]["env"]["LUMI_COMPLETED"] == (
        "${{ steps.lumi.outputs.completed-localizations }}"
    )
    assert job["steps"][5]["env"]["LUMI_REVIEW_PATHS"] == (
        "${{ steps.lumi.outputs.unique-review-paths }}"
    )
    assert job["steps"][5]["env"]["RUN_URL"] == (
        "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
    )
    assert 'echo "$RUN_URL"' in source
    assert '} >> "$GITHUB_STEP_SUMMARY"' in source
    assert "## What Lumi did" in source
    assert "Scanner finding in. Focused review queue out." in source
    assert "This walkthrough doesn't claim a real vulnerability exists." in source
    assert "Copy that link into the short Bandit demo result form" in source
    assert "https://github.com/noqt/Lumi-Trace/issues/new?template=bandit_demo_result.yml" in source
    assert "Don't include secrets" in source
    assert "pull_request:" not in source
    assert "push:" not in source
