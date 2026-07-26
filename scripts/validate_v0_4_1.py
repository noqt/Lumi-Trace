# SPDX-License-Identifier: Apache-2.0
"""Run and record the final V0.4.1 source and local-runtime validation lanes."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from lumi_trace.canonical import dump_json, load_json, sha256_file, stable_id

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STARTING_REVISION = "c93d3c792190435cb82e28f01af532be97d9a06a"
DOCKER_IMAGE = "alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"


def _source_state_id() -> str:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    members = []
    for relative in sorted(completed.stdout.splitlines()):
        normalized = relative.replace("\\", "/")
        if normalized.startswith("evidence/v0.4.1/"):
            continue
        path = PROJECT_ROOT / relative
        if path.is_file():
            members.append(
                {
                    "path": normalized,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return stable_id(
        "lumi-trace-v0.4.1-source-state",
        {
            "starting_revision": STARTING_REVISION,
            "members": members,
        },
    )


def _governed_root(path: Path, drive: str, *, create: bool = False) -> Path:
    resolved = path.resolve(strict=not create)
    if resolved.drive.casefold() != drive.casefold():
        raise ValueError(f"governed root must remain on {drive}")
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError("governed root is not a directory")
    return resolved


def _write_once(path: Path, value: dict) -> None:
    if path.exists():
        if load_json(path) != value:
            raise ValueError(f"append-only validation artifact differs: {path.name}")
        return
    dump_json(path, value)


def _run(
    *,
    name: str,
    command: list[str],
    environment: dict[str, str],
    log_root: Path,
    timeout_seconds: int,
) -> dict:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )
    log_path = log_root / f"{name}.log"
    log_path.write_text(completed.stdout, encoding="utf-8", newline="\n")
    result = {
        "name": name,
        "command": command,
        "exit_code": completed.returncode,
        "passed": completed.returncode == 0,
        "log_sha256": sha256_file(log_path),
        "log_size_bytes": log_path.stat().st_size,
    }
    result["result_id"] = stable_id("v0.4.1-validation-command", result)
    return result


def validate(args: argparse.Namespace) -> dict:
    work_root = _governed_root(args.work_root, "F:", create=True)
    private_root = _governed_root(args.private_root, "G:", create=True)
    if PROJECT_ROOT.resolve().drive.casefold() != "f:":
        raise ValueError("source checkout must remain on F:")
    if not args.run or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in args.run
    ):
        raise ValueError("--run must be a lowercase alphanumeric token")

    log_root = work_root / "reports" / f"validation-{args.run}"
    log_root.mkdir(parents=True, exist_ok=False)
    temp_root = work_root / "tmp" / f"validation-{args.run}"
    temp_root.mkdir(parents=True, exist_ok=False)

    environment = os.environ.copy()
    environment["TEMP"] = str(temp_root)
    environment["TMP"] = str(temp_root)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    source_state_id = _source_state_id()
    python = str(Path(sys.executable).resolve())
    common_timeout = 600
    commands: list[tuple[str, list[str], dict[str, str], int]] = [
        (
            "root-tests",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "-m",
                "not docker",
                "--basetemp",
                str(temp_root / "root"),
            ],
            environment,
            common_timeout,
        ),
        (
            "eval-tests",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "-c",
                "eval/pyproject.toml",
                "eval/tests",
                "--basetemp",
                str(temp_root / "eval"),
            ],
            {**environment, "PYTHONPATH": str(PROJECT_ROOT / "eval" / "src")},
            common_timeout,
        ),
        (
            "docker-network-denied",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "-m",
                "docker",
                "--basetemp",
                str(temp_root / "docker"),
            ],
            {**environment, "LUMI_TRACE_TEST_IMAGE": DOCKER_IMAGE},
            common_timeout,
        ),
        ("ruff-check", [python, "-m", "ruff", "check", "."], environment, 120),
        (
            "ruff-format-check",
            [python, "-m", "ruff", "format", "--check", "."],
            environment,
            120,
        ),
        ("licence-check", [python, "scripts/check_licenses.py"], environment, 120),
        ("secret-check", [python, "scripts/check_secrets.py"], environment, 120),
        (
            "dependency-check",
            [python, "scripts/check_dependencies.py"],
            environment,
            120,
        ),
        (
            "public-boundary-check",
            [python, "scripts/check_public_boundary.py"],
            environment,
            120,
        ),
        (
            "dependency-audit",
            [python, "-m", "pip_audit", "--skip-editable", "--progress-spinner", "off"],
            environment,
            300,
        ),
        ("git-diff-check", ["git", "diff", "--check"], environment, 120),
        (
            "historical-v0-4-evidence",
            [python, "scripts/verify_v0_4_evidence.py", "evidence/v0.4"],
            environment,
            120,
        ),
    ]
    results = [
        _run(
            name=name,
            command=command,
            environment=command_environment,
            log_root=log_root,
            timeout_seconds=timeout_seconds,
        )
        for name, command, command_environment, timeout_seconds in commands
    ]
    record = {
        "schema_version": "lumi-trace-v0.4.1-final-validation-v1",
        "run": args.run,
        "source_checkout_drive": "F:",
        "private_record_drive": "G:",
        "temporary_artifact_drive": "F:",
        "source_state_id": source_state_id,
        "docker_image": DOCKER_IMAGE,
        "commands": results,
        "command_count": len(results),
        "passed_command_count": sum(item["passed"] for item in results),
        "all_passed": all(item["passed"] for item in results),
    }
    record["record_id"] = stable_id("v0.4.1-final-validation", record)
    if _source_state_id() != source_state_id:
        raise RuntimeError("source state changed during final validation")
    output = private_root / "manifests" / f"final-validation-{args.run}.json"
    _write_once(output, record)
    if not record["all_passed"]:
        raise RuntimeError(f"V0.4.1 validation failed; inspect {output}")
    return record


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run", required=True)
    result.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    return result


def main() -> int:
    record = validate(parser().parse_args())
    print(record["record_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
