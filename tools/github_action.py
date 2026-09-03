# SPDX-License-Identifier: Apache-2.0
"""Safe GitHub Actions adapter for the local Lumi Trace batch command.

This module is intentionally an action-side adapter, not a second product
pipeline. It validates the action boundary, calls the existing CLI with an
argument list, verifies any completed package, and emits bounded summaries.
"""

from __future__ import annotations

import contextlib
import html
import io
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ACTION_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ACTION_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from lumi_trace.canonical import load_json  # noqa: E402
from lumi_trace.cli import main as cli_main  # noqa: E402
from lumi_trace.errors import InputError, IntegrityError  # noqa: E402
from lumi_trace.triage import TRIAGE_PARTIAL_SUCCESS_EXIT_CODE, verify_triage_package  # noqa: E402

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
OUTPUT_KEYS = (
    "status",
    "exit-code",
    "selected-results",
    "completed-localizations",
    "result-local-errors",
    "unique-review-paths",
    "evidence-path",
    "package-ready",
    "artifact-name",
)
MAX_FAILURE_REASON_LENGTH = 240
FAILURE_REASON_TEMPLATES = {
    "action-input": (
        "Check the Action paths and bounded input values against the documented inputs, then rerun."
    ),
    "triage-input": (
        "Lumi Trace could not process the supplied inputs. Validate the local SARIF 2.1.0 "
        "input and repository, then rerun."
    ),
    "triage-unsupported": (
        "Lumi Trace does not support part of the supplied local input. Check the documented "
        "SARIF and repository limits, then rerun."
    ),
    "triage-integrity": (
        "Lumi Trace detected an input integrity failure. Recreate the local inputs from a "
        "trusted source, then rerun."
    ),
    "package-integrity": (
        "Lumi Trace could not verify the generated evidence package. Remove the output "
        "directory and rerun; if this persists, report a bug without attaching evidence."
    ),
    "adapter-error": (
        "The Lumi Trace Action stopped unexpectedly. Rerun the job; if this persists, report "
        "a bug without attaching logs, findings, credentials, or private paths."
    ),
    "adapter-error-unknown": (
        "The Lumi Trace Action stopped unexpectedly. Rerun the job; if this persists, report "
        "a bug without attaching logs, findings, credentials, or private paths."
    ),
}
ALLOWLISTED_SCANNER_NAMES = {"bandit": "Bandit"}


class ActionConfigurationError(ValueError):
    """Raised for an invalid GitHub Action input before triage starts."""


@dataclass(frozen=True)
class ActionConfig:
    workspace: Path
    sarif: Path
    repository: Path
    output: Path
    top_k: int
    max_findings: int
    fail_on_partial: bool
    fail_on_severity: str | None
    artifact_name: str
    github_output: Path
    github_summary: Path


@dataclass(frozen=True)
class VerifiedPackage:
    summary: dict[str, object]
    queue: list[dict[str, object]]
    normalized_findings: list[dict[str, object]]


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise ActionConfigurationError(f"required GitHub Actions environment {name} is missing")
    return value


def _input(name: str, default: str | None = None) -> str:
    value = os.environ.get(f"LUMI_TRACE_ACTION_{name}", default)
    if value is None or not value:
        raise ActionConfigurationError(f"action input {name.lower().replace('_', '-')} is required")
    if "\x00" in value:
        raise ActionConfigurationError(
            f"action input {name.lower().replace('_', '-')} contains NUL"
        )
    return value


def _workspace_path(workspace: Path, raw: str, name: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ActionConfigurationError(
            f"action input {name} must stay inside GITHUB_WORKSPACE"
        ) from exc
    return resolved


def _boolean(name: str, default: str) -> bool:
    value = _input(name, default)
    if value == "true":
        return True
    if value == "false":
        return False
    raise ActionConfigurationError(
        f"action input {name.lower().replace('_', '-')} must be true or false"
    )


def _positive_int(name: str, default: str, maximum: int) -> int:
    value = _input(name, default)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ActionConfigurationError(
            f"action input {name.lower().replace('_', '-')} must be an integer"
        ) from exc
    if parsed < 1 or parsed > maximum:
        raise ActionConfigurationError(
            f"action input {name.lower().replace('_', '-')} must be between 1 and {maximum}"
        )
    return parsed


def _load_config() -> ActionConfig:
    workspace = Path(_required_environment("GITHUB_WORKSPACE")).resolve(strict=True)
    if not workspace.is_dir() or workspace.is_symlink():
        raise ActionConfigurationError("GITHUB_WORKSPACE must be a regular directory")
    github_output = Path(_required_environment("GITHUB_OUTPUT"))
    github_summary = Path(_required_environment("GITHUB_STEP_SUMMARY"))
    sarif = _workspace_path(workspace, _input("SARIF"), "sarif")
    repository = _workspace_path(workspace, _input("REPOSITORY", "."), "repository")
    output = _workspace_path(workspace, _input("OUTPUT", ".lumi-trace"), "output")
    if not sarif.is_file() or sarif.is_symlink():
        raise ActionConfigurationError("action input sarif must name a regular file")
    if not (repository.is_file() or repository.is_dir()) or repository.is_symlink():
        raise ActionConfigurationError(
            "action input repository must name a regular directory or archive"
        )
    if output.exists() or output.is_symlink():
        raise ActionConfigurationError("action input output must name a new directory")
    artifact_name = _input("ARTIFACT_NAME", "lumi-trace-evidence")
    if ARTIFACT_NAME.fullmatch(artifact_name) is None:
        raise ActionConfigurationError("action input artifact-name is unsafe")
    severity_input = _input("FAIL_ON_SEVERITY", "none").upper()
    if severity_input == "NONE":
        fail_on_severity = None
    elif severity_input in SEVERITY_ORDER:
        fail_on_severity = severity_input
    else:
        raise ActionConfigurationError(
            "action input fail-on-severity must be none, critical, high, medium, or low"
        )
    return ActionConfig(
        workspace=workspace,
        sarif=sarif,
        repository=repository,
        output=output,
        top_k=_positive_int("TOP_K", "10", 1_000),
        max_findings=_positive_int("MAX_FINDINGS", "100", 1_000),
        fail_on_partial=_boolean("FAIL_ON_PARTIAL", "true"),
        fail_on_severity=fail_on_severity,
        artifact_name=artifact_name,
        github_output=github_output,
        github_summary=github_summary,
    )


def _load_verified_package(output: Path, cli_exit_code: int) -> VerifiedPackage | None:
    if cli_exit_code not in {0, TRIAGE_PARTIAL_SUCCESS_EXIT_CODE}:
        return None
    if output.is_symlink() or not output.is_dir():
        return None
    try:
        verify_triage_package(output)
        summary = load_json(output / "triage-summary.json")
        queue_document = load_json(output / "review-queue.json")
        normalized_document = load_json(output / "normalized-findings.json")
    except (InputError, IntegrityError, OSError, ValueError):
        return None
    if (
        not isinstance(summary, dict)
        or not isinstance(queue_document, dict)
        or not isinstance(normalized_document, dict)
        or not isinstance(queue_document.get("entries"), list)
        or not isinstance(normalized_document.get("findings"), list)
    ):
        return None
    queue = queue_document["entries"]
    findings = normalized_document["findings"]
    if not all(isinstance(item, dict) for item in queue + findings):
        return None
    return VerifiedPackage(summary=summary, queue=queue, normalized_findings=findings)


def _triggered_by_severity(package: VerifiedPackage, threshold: str | None) -> bool:
    if threshold is None:
        return False
    threshold_order = SEVERITY_ORDER[threshold]
    for record in package.normalized_findings:
        finding = record.get("finding")
        severity = finding.get("severity") if isinstance(finding, dict) else None
        normalized = severity.get("normalized") if isinstance(severity, dict) else None
        if (
            isinstance(normalized, str)
            and SEVERITY_ORDER.get(normalized.upper(), 99) <= threshold_order
        ):
            return True
    return False


def _summary_number(summary: dict[str, object], name: str) -> int:
    value = summary.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"verified package summary field {name} is invalid")
    return value


def _escape_markdown_cell(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=False)
    for token in ("\\", "|", "`", "[", "]", "(", ")"):
        text = text.replace(token, f"\\{token}")
    return text


def _render_failure_reason(reason_code: str) -> str:
    """Render only a source-owned reason template, never exception or input text."""

    template = FAILURE_REASON_TEMPLATES.get(
        reason_code, FAILURE_REASON_TEMPLATES["adapter-error-unknown"]
    )
    single_line = " ".join(str(template).splitlines()).strip()
    rendered = _escape_markdown_cell(single_line)
    if len(rendered) > MAX_FAILURE_REASON_LENGTH:
        rendered = rendered[: MAX_FAILURE_REASON_LENGTH - 1].rstrip("\\") + "…"
    return rendered


def _cli_failure_reason(cli_exit_code: int) -> str:
    return {
        2: "triage-input",
        3: "triage-unsupported",
        4: "triage-integrity",
    }.get(cli_exit_code, "adapter-error-unknown")


def _allowlisted_scanner_subject(sarif_path: Path) -> str:
    """Return a fixed scanner label without rendering untrusted SARIF metadata."""

    try:
        document = load_json(sarif_path)
    except (OSError, ValueError):
        return "The upstream scanner"
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list) or not runs:
        return "The upstream scanner"
    labels: list[str] = []
    for run in runs:
        tool = run.get("tool") if isinstance(run, dict) else None
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name = driver.get("name") if isinstance(driver, dict) else None
        label = ALLOWLISTED_SCANNER_NAMES.get(name.casefold()) if isinstance(name, str) else None
        if label is None:
            return "The upstream scanner"
        labels.append(label)
    if labels and len(set(labels)) == 1:
        return labels[0]
    return "The upstream scanners"


def _write_job_summary(
    config: ActionConfig,
    package: VerifiedPackage | None,
    *,
    status: str,
    policy_triggered: bool,
    failure_reason_code: str | None,
) -> None:
    config.github_summary.parent.mkdir(parents=True, exist_ok=True)
    lines = ["## Lumi Trace review summary", "", f"**Status:** `{status}`", ""]
    if package is None:
        reason = _render_failure_reason(failure_reason_code or "adapter-error-unknown")
        lines.extend(
            [
                f"**Why it stopped:** {reason}",
                "",
                "Lumi Trace did not produce a verified evidence package.",
            ]
        )
    else:
        summary = package.summary
        selected = _summary_number(summary, "selected_results")
        completed = _summary_number(summary, "completed_localizations")
        abstained = _summary_number(summary, "localization_abstentions")
        errors = _summary_number(summary, "result_local_errors")
        unique_paths = _summary_number(summary, "unique_review_paths")
        relative_output = config.output.relative_to(config.workspace).as_posix()
        lines.extend(
            [
                "| Selected | Completed | Abstained | Result errors | Unique review paths |",
                "| ---: | ---: | ---: | ---: | ---: |",
                f"| {selected} | {completed} | {abstained} | {errors} | {unique_paths} |",
                "",
            ]
        )
        if package.queue:
            lines.extend(
                [
                    "### Review first",
                    "",
                    "| # | Path | Scanner severity | Findings | Best shortlist rank |",
                    "| ---: | --- | --- | ---: | ---: |",
                ]
            )
            for item in package.queue[:10]:
                rank = _summary_number(item, "queue_rank")
                finding_count = _summary_number(item, "finding_count")
                best_rank = _summary_number(item, "best_shortlist_rank")
                path = _escape_markdown_cell(item.get("path", ""))
                severity = _escape_markdown_cell(item.get("highest_severity", "unknown"))
                lines.append(f"| {rank} | {path} | {severity} | {finding_count} | {best_rank} |")
            lines.append("")
        lines.append(f"**Verified evidence:** `{_escape_markdown_cell(relative_output)}`")
        if selected == 0:
            scanner = _allowlisted_scanner_subject(config.sarif)
            lines.extend(
                [
                    "",
                    f"**No findings:** {scanner} reported no findings in the supplied SARIF. "
                    "This does not mean the repository is secure.",
                ]
            )
        if policy_triggered:
            lines.append("**CI policy:** configured scanner-severity threshold triggered.")
        lines.extend(
            [
                "",
                "Queue order is review priority, not vulnerability probability or exploitability.",
            ]
        )
    config.github_summary.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_outputs(config: ActionConfig, values: dict[str, object]) -> None:
    rendered = {key: str(values.get(key, "")) for key in OUTPUT_KEYS}
    if any("\n" in value or "\r" in value for value in rendered.values()):
        raise RuntimeError("action output value contains a line break")
    config.github_output.parent.mkdir(parents=True, exist_ok=True)
    with config.github_output.open("a", encoding="utf-8", newline="\n") as stream:
        for key in OUTPUT_KEYS:
            stream.write(f"{key}={rendered[key]}\n")


def _minimal_config_for_error() -> ActionConfig | None:
    try:
        workspace = Path(_required_environment("GITHUB_WORKSPACE")).resolve(strict=True)
        return ActionConfig(
            workspace=workspace,
            sarif=workspace,
            repository=workspace,
            output=workspace / ".lumi-trace",
            top_k=10,
            max_findings=100,
            fail_on_partial=True,
            fail_on_severity=None,
            artifact_name="lumi-trace-evidence",
            github_output=Path(_required_environment("GITHUB_OUTPUT")),
            github_summary=Path(_required_environment("GITHUB_STEP_SUMMARY")),
        )
    except (ActionConfigurationError, OSError):
        return None


def _finish(
    config: ActionConfig,
    package: VerifiedPackage | None,
    *,
    status: str,
    exit_code: int,
    policy_triggered: bool,
    failure_reason_code: str | None,
) -> None:
    _write_job_summary(
        config,
        package,
        status=status,
        policy_triggered=policy_triggered,
        failure_reason_code=failure_reason_code,
    )
    summary = package.summary if package is not None else {}
    relative_output = ""
    if package is not None:
        relative_output = config.output.relative_to(config.workspace).as_posix()
    _write_outputs(
        config,
        {
            "status": status,
            "exit-code": exit_code,
            "selected-results": summary.get("selected_results", ""),
            "completed-localizations": summary.get("completed_localizations", ""),
            "result-local-errors": summary.get("result_local_errors", ""),
            "unique-review-paths": summary.get("unique_review_paths", ""),
            "evidence-path": relative_output,
            "package-ready": str(package is not None).lower(),
            "artifact-name": config.artifact_name,
        },
    )


def main() -> int:
    """Run the adapter and reserve the process result for adapter failures only."""

    config: ActionConfig | None = None
    try:
        config = _load_config()
        argv = [
            "triage",
            "--sarif",
            str(config.sarif),
            "--repository",
            str(config.repository),
            "--output",
            str(config.output),
            "--top-k",
            str(config.top_k),
            "--max-findings",
            str(config.max_findings),
        ]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli_exit_code = cli_main(argv)
        package = _load_verified_package(config.output, cli_exit_code)
        if package is None:
            status = (
                "integrity-failure"
                if cli_exit_code in {0, TRIAGE_PARTIAL_SUCCESS_EXIT_CODE}
                else "fatal-error"
            )
            failure_reason_code = (
                "package-integrity"
                if status == "integrity-failure"
                else _cli_failure_reason(cli_exit_code)
            )
            _finish(
                config,
                None,
                status=status,
                exit_code=2,
                policy_triggered=False,
                failure_reason_code=failure_reason_code,
            )
            return 0
        policy_triggered = _triggered_by_severity(package, config.fail_on_severity)
        if cli_exit_code == TRIAGE_PARTIAL_SUCCESS_EXIT_CODE and config.fail_on_partial:
            status, final_exit_code = "partial-failed", TRIAGE_PARTIAL_SUCCESS_EXIT_CODE
        elif policy_triggered:
            status, final_exit_code = "policy-failed", 1
        elif cli_exit_code == TRIAGE_PARTIAL_SUCCESS_EXIT_CODE:
            status, final_exit_code = "partial-success", 0
        else:
            status, final_exit_code = "complete", 0
        _finish(
            config,
            package,
            status=status,
            exit_code=final_exit_code,
            policy_triggered=policy_triggered,
            failure_reason_code=None,
        )
    except ActionConfigurationError:
        fallback = config or _minimal_config_for_error()
        if fallback is None:
            return 2
        _finish(
            fallback,
            None,
            status="input-error",
            exit_code=2,
            policy_triggered=False,
            failure_reason_code="action-input",
        )
    except Exception:
        fallback = config or _minimal_config_for_error()
        if fallback is None:
            return 2
        _finish(
            fallback,
            None,
            status="adapter-error",
            exit_code=2,
            policy_triggered=False,
            failure_reason_code="adapter-error",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
