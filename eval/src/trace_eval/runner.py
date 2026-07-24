# SPDX-License-Identifier: Apache-2.0
"""Bounded, label-blind subprocess runner for the exact Lumi Trace V0.1 CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, dump_json, load_json, sha256_bytes, sha256_file, stable_id
from .contracts import make_record, validate_record
from .errors import ContractError, RunnerError
from .package import seal_package, verify_package
from .policy import FAILURE_CODES, assert_runner_blind, sanitize_environment
from .registry import load_registry, records_by_schema, validate_registry
from .resources import process_tree_observation


def _resolve_under(root: Path, relative: str, *, directory: bool) -> Path:
    root = root.resolve(strict=True)
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RunnerError("runner input resolves outside the public source root") from exc
    if (
        candidate.is_symlink()
        or (directory and not candidate.is_dir())
        or (not directory and not candidate.is_file())
    ):
        raise RunnerError("runner input is missing or unsafe")
    return candidate


def _readonly_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o444)


def _writable_tree(root: Path) -> None:
    """Restore copied inputs so TemporaryDirectory can clean them on Windows."""

    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o644)


def _artifacts(root: Path) -> list[dict[str, Any]]:
    paths = sorted(
        (path for path in root.rglob("*") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in paths
    ]


def _tree_id(root: Path) -> str:
    manifest = {"algorithm": "lumi-tree-sha256-v1", "files": _artifacts(root)}
    return sha256_bytes(canonical_bytes(manifest))


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    else:
        import signal

        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _run_observed(
    command: list[str],
    *,
    stdout: Any,
    stderr: Any,
    environment: dict[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        stdout=stdout,
        stderr=stderr,
        env=environment,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    started = time.perf_counter_ns()
    peak_resident_bytes = 0
    peak_process_count = 0
    cpu_time_by_pid: dict[int, int] = {}
    timed_out = False
    while process.poll() is None:
        resident_bytes, process_count, cpu_times = process_tree_observation(process.pid)
        peak_resident_bytes = max(peak_resident_bytes, resident_bytes)
        peak_process_count = max(peak_process_count, process_count)
        for pid, cpu_time_ms in cpu_times.items():
            cpu_time_by_pid[pid] = max(cpu_time_by_pid.get(pid, 0), cpu_time_ms)
        elapsed_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
        if elapsed_seconds >= timeout_seconds:
            timed_out = True
            _terminate_process_tree(process)
            break
        time.sleep(0.05)
    resident_bytes, process_count, cpu_times = process_tree_observation(process.pid)
    peak_resident_bytes = max(peak_resident_bytes, resident_bytes)
    peak_process_count = max(peak_process_count, process_count)
    for pid, cpu_time_ms in cpu_times.items():
        cpu_time_by_pid[pid] = max(cpu_time_by_pid.get(pid, 0), cpu_time_ms)
    return {
        "return_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "wall_time_ms": (time.perf_counter_ns() - started) // 1_000_000,
        "peak_resident_bytes": peak_resident_bytes or None,
        "peak_process_count": peak_process_count,
        "cpu_time_ms": sum(cpu_time_by_pid.values()),
    }


def _identity_artifacts(root: Path) -> list[dict[str, Any]]:
    """Describe identity-bearing content without folding telemetry into a seal."""

    artifacts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"manifest.json", "raw-output-seal.json", "run-record.json"}:
            continue
        if path.name in {"stdout.bin", "stderr.bin"}:
            artifacts.append({"path": relative, "identity_excluded": "observational_log"})
            continue
        if path.suffix == ".json":
            try:
                value = load_json(path)
            except ContractError:
                value = None
            if isinstance(value, dict) and isinstance(value.get("record_id"), str):
                validate_record(value)
                artifacts.append({"path": relative, "record_id": value["record_id"]})
                continue
        artifacts.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return artifacts


def verify_runtime(
    configuration: dict[str, Any], executable: Path, artifact: Path
) -> dict[str, str]:
    validate_record(configuration)
    if configuration["schema_version"] != "evaluator-configuration-v1":
        raise ContractError("runner configuration has the wrong contract")
    runtime = configuration["payload"]["runtime"]
    if not isinstance(runtime, dict):
        raise ContractError("configuration runtime must be an object")
    expected = runtime.get("artifact_sha256")
    if sha256_file(artifact) != expected:
        raise RunnerError("exact Lumi Trace runtime artifact hash mismatch")
    if executable.is_symlink() or not executable.is_file():
        raise RunnerError("Lumi Trace executable is missing or unsafe")
    result = subprocess.run(
        [str(executable), "version"], check=False, capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        raise RunnerError("pinned Lumi Trace executable failed its version probe")
    try:
        version = __import__("json").loads(result.stdout)
    except ValueError as exc:
        raise RunnerError("pinned Lumi Trace version output is not JSON") from exc
    if (
        version.get("version") != runtime.get("version")
        or version.get("checkpoint") is not None
        or version.get("current_weights") != 0
    ):
        raise RunnerError("pinned runtime identity or zero-weight contract mismatch")
    return {"artifact_sha256": expected, "version": version["version"]}


def _attempt(
    *,
    group: dict[str, Any],
    configuration: dict[str, Any],
    run_id: str,
    executable: Path,
    source_root: Path,
    workspace_root: Path,
    raw_root: Path,
) -> dict[str, Any]:
    payload = group["payload"]
    runner_inputs = payload["runner_inputs"]
    assert_runner_blind(runner_inputs)
    suffix = group["record_id"].rsplit(":", 1)[-1]
    destination = raw_root / suffix
    destination.mkdir(parents=True)
    limits = configuration["payload"]["limits"]
    timeout_seconds = int(limits["case_timeout_seconds"])
    output_bytes = int(limits["subprocess_output_bytes"])
    disk_bytes = int(limits["case_disk_bytes"])
    started = time.perf_counter_ns()
    failure_codes: list[str] = []
    status = "COMPLETED"
    return_code: int | None = None
    retained_log_bytes = 0
    termination_reason = "COMPLETED"
    peak_resident_bytes: int | None = None
    peak_process_count = 0
    cpu_time_ms = 0
    stage_wall_time_ms: dict[str, int] = {}
    repository_file_count = 0
    repository_bytes = 0
    indexed_observations: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="trace-eval-case-", dir=workspace_root) as temporary:
        case_root = Path(temporary)
        repository_source = _resolve_under(source_root, runner_inputs["repository"], directory=True)
        finding_source = _resolve_under(source_root, runner_inputs["finding"], directory=False)
        source_files = [
            path
            for path in repository_source.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        repository_file_count = len(source_files)
        repository_bytes = sum(path.stat().st_size for path in source_files)
        input_hashes = payload["input_hashes"]
        identity_started = time.perf_counter_ns()
        if sha256_file(finding_source) not in input_hashes:
            raise RunnerError("finding input does not match the governed group hashes")
        if _tree_id(repository_source) != payload["repository_tree_id"]:
            raise RunnerError("repository input does not match the governed tree identity")
        stage_wall_time_ms["input_identity"] = (
            time.perf_counter_ns() - identity_started
        ) // 1_000_000
        repository = case_root / "repository"
        finding = case_root / "finding.json"
        materialisation_started = time.perf_counter_ns()
        shutil.copytree(repository_source, repository)
        shutil.copy2(finding_source, finding)
        _readonly_tree(repository)
        stage_wall_time_ms["evaluator_materialisation"] = (
            time.perf_counter_ns() - materialisation_started
        ) // 1_000_000
        output = case_root / "output"
        command = [
            str(executable),
            "trace",
            "--finding",
            str(finding),
            "--finding-format",
            str(runner_inputs.get("finding_format", "manual")),
            "--repository",
            str(repository),
            "--output",
            str(output),
            "--top-k",
            str(configuration["payload"]["k_max"]),
            "--source-revision",
            str(configuration["payload"]["runtime"]["source_revision"]),
        ]
        if runner_inputs.get("plan") is not None:
            plan = _resolve_under(source_root, runner_inputs["plan"], directory=False)
            command.extend(["--plan", str(plan), "--image", str(runner_inputs["image"])])
        environment = sanitize_environment(os.environ, temp_root=case_root)
        stdout_log = case_root / "stdout.bin"
        stderr_log = case_root / "stderr.bin"
        with stdout_log.open("wb") as stdout, stderr_log.open("wb") as stderr:
            observed = _run_observed(
                command,
                stdout=stdout,
                stderr=stderr,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
        stage_wall_time_ms["runtime"] = int(observed["wall_time_ms"])
        return_code = observed["return_code"]
        peak_resident_bytes = observed["peak_resident_bytes"]
        peak_process_count = int(observed["peak_process_count"])
        cpu_time_ms = int(observed["cpu_time_ms"])
        retained_log_bytes = stdout_log.stat().st_size + stderr_log.stat().st_size
        if observed["timed_out"]:
            status = "FAILED"
            termination_reason = "WALL_TIME_LIMIT"
            failure_codes.append("RESOURCE_LIMIT_REACHED")
        elif retained_log_bytes > output_bytes:
            status = "FAILED"
            termination_reason = "RETAINED_OUTPUT_LIMIT"
            failure_codes.append("RESOURCE_LIMIT_REACHED")
        elif return_code != 0 or not output.is_dir():
            status = "FAILED"
            termination_reason = "RUNTIME_OR_SCHEMA_FAILURE"
            failure_codes.append("RUNNER_OR_SCHEMA_FAILURE")
        else:
            retain_started = time.perf_counter_ns()
            shutil.copytree(output, destination / "evidence-package")
            stage_wall_time_ms["evidence_retention"] = (
                time.perf_counter_ns() - retain_started
            ) // 1_000_000
            total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
            if total > disk_bytes:
                status = "FAILED"
                termination_reason = "RETAINED_DISK_LIMIT"
                failure_codes.append("RESOURCE_LIMIT_REACHED")
            else:
                index = load_json(output / "repository-index.json")
                if isinstance(index, dict):
                    indexed_observations = {
                        "index_file_count": index.get("file_count"),
                        "indexed_text_file_count": index.get("indexed_text_file_count"),
                        "index_symbol_count": index.get("symbol_count"),
                        "index_exclusions": index.get("exclusions"),
                        "index_global_limit_reached": index.get("global_limit_reached"),
                        "index_limits": index.get("limits"),
                    }
        try:
            for source, name in ((stdout_log, "stdout.bin"), (stderr_log, "stderr.bin")):
                if source.exists():
                    with source.open("rb") as stream, (destination / name).open("wb") as target:
                        target.write(stream.read(output_bytes))
            if output.is_dir() and not (destination / "evidence-package").exists():
                shutil.copytree(output, destination / "evidence-package")
        finally:
            _writable_tree(repository)
    elapsed_ms = (time.perf_counter_ns() - started) // 1_000_000
    if any(code not in FAILURE_CODES for code in failure_codes):
        raise RunnerError("attempt produced an unknown failure code")
    attempt_id = stable_id("trace-eval-attempt", {"run_id": run_id, "group_id": group["record_id"]})
    record = make_record(
        "attempt-record-v1",
        {
            "attempt_id": attempt_id,
            "run_id": run_id,
            "group_id": group["record_id"],
            "status": status,
            "failure_codes": failure_codes,
            "output_artifacts": _identity_artifacts(destination),
            "stage": "COMPLETE" if status == "COMPLETED" else "RUNTIME",
            "attempt_number": 1,
            "retry_of": None,
        },
        observations={
            "wall_time_ms": elapsed_ms,
            "cpu_time_ms": cpu_time_ms,
            "return_code": return_code,
            "retained_log_bytes": min(retained_log_bytes, output_bytes),
            "retained_artifact_bytes": sum(
                path.stat().st_size for path in destination.rglob("*") if path.is_file()
            ),
            "retained_file_count": sum(1 for path in destination.rglob("*") if path.is_file()),
            "peak_resident_bytes": peak_resident_bytes,
            "peak_resident_collection": "POLLED_PROCESS_TREE",
            "peak_process_count": peak_process_count,
            "cache_state": "COLD_DISPOSABLE_WORKSPACE",
            "termination_reason": termination_reason,
            "repository_file_count": repository_file_count,
            "repository_bytes": repository_bytes,
            "stage_wall_time_ms": stage_wall_time_ms,
            "index": indexed_observations,
            "configured_limits": limits,
            "enforced_limits": [
                "wall_time",
                "retained_output_bytes",
                "retained_disk_bytes",
                "process_tree_termination",
            ],
        },
    )
    return record


def run_registry(
    *,
    registry_path: Path,
    configuration_path: Path,
    executable: Path,
    runtime_artifact: Path,
    source_root: Path,
    workspace_root: Path,
    output: Path,
) -> dict[str, Any]:
    if output.exists():
        raise RunnerError("run output already exists")
    registry = load_registry(registry_path)
    configuration = load_json(configuration_path)
    if not isinstance(configuration, dict):
        raise ContractError("configuration must be a record object")
    validate_record(configuration)
    mode = configuration["payload"]["mode"]
    validate_registry(registry, mode=mode)
    runtime = verify_runtime(configuration, executable, runtime_artifact)
    workspace_root.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True)
    raw_root = output / "raw"
    attempts_root = output / "attempts"
    raw_root.mkdir()
    attempts_root.mkdir()
    run_id = stable_id(
        "trace-eval-run",
        {
            "mode": mode,
            "runtime": runtime,
            "registry_id": registry["registry_id"],
            "configuration_id": configuration["record_id"],
        },
    )
    expected_partition = {
        "public-fixture": "public_regression",
        "development": "development",
        "qualification": "qualification",
    }[mode]
    groups = [
        group
        for group in records_by_schema(registry, "candidate-ranking-group-v1")
        if group["payload"]["split"] == expected_partition
    ]
    attempts: list[dict[str, Any]] = []
    for group in sorted(groups, key=lambda item: item["record_id"]):
        attempt = _attempt(
            group=group,
            configuration=configuration,
            run_id=run_id,
            executable=executable,
            source_root=source_root,
            workspace_root=workspace_root,
            raw_root=raw_root,
        )
        attempts.append(attempt)
        dump_json(attempts_root / f"{attempt['record_id'].rsplit(':', 1)[-1]}.json", attempt)
    runner_view = {
        "registry_id": registry["registry_id"],
        "configuration_id": configuration["record_id"],
        "groups": [group["record_id"] for group in groups],
    }
    raw_seal = make_record(
        "raw-output-seal-v1",
        {
            "run_id": run_id,
            "artifacts": _identity_artifacts(output),
            "sealed_before_labels": True,
            "runner_view_hash": stable_id("runner-view", runner_view),
        },
    )
    dump_json(output / "raw-output-seal.json", raw_seal)
    run_record = make_record(
        "run-record-v1",
        {
            "run_id": run_id,
            "mode": mode,
            "runtime_id": stable_id("lumi-trace-runtime", runtime),
            "registry_id": registry["registry_id"],
            "configuration_id": configuration["record_id"],
            "attempt_ids": [attempt["record_id"] for attempt in attempts],
            "raw_output_seal_id": raw_seal["record_id"],
        },
    )
    dump_json(output / "run-record.json", run_record)
    manifest = seal_package(output)
    return {"run_record": run_record, "manifest": manifest, "attempts": attempts}


def load_run_package(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    manifest = verify_package(path)
    run_record = load_json(path / "run-record.json")
    raw_seal = load_json(path / "raw-output-seal.json")
    if not isinstance(run_record, dict) or not isinstance(raw_seal, dict):
        raise ContractError("run package records must be objects")
    validate_record(run_record)
    validate_record(raw_seal)
    attempts = []
    for attempt_path in sorted((path / "attempts").glob("*.json")):
        attempt = load_json(attempt_path)
        if not isinstance(attempt, dict):
            raise ContractError("attempt record must be an object")
        attempts.append(validate_record(attempt))
        suffix = attempt["payload"]["group_id"].rsplit(":", 1)[-1]
        if attempt["payload"]["output_artifacts"] != _identity_artifacts(path / "raw" / suffix):
            raise ContractError("attempt output identities do not match retained raw artifacts")
    if sorted(item["record_id"] for item in attempts) != sorted(
        run_record["payload"]["attempt_ids"]
    ):
        raise ContractError("run attempt identities do not match the run record")
    if raw_seal["payload"]["artifacts"] != _identity_artifacts(path):
        raise ContractError("raw-output seal does not match retained identity-bearing artifacts")
    return run_record, attempts, manifest
