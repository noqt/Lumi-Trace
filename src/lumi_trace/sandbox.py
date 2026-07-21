# SPDX-License-Identifier: Apache-2.0
"""Fail-closed Docker sandbox for bounded local reproduction.

The implementation resolves a locally present immutable image, creates each
container with a network-none/read-only/non-root policy, inspects that policy
before start, and never offers a host-process fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .canonical import canonical_sha256, load_json, sha256_bytes
from .errors import InputError
from .repository import compute_repository_identity

_DIGEST_REFERENCE = re.compile(r"(?:^sha256:|@sha256:)[0-9a-f]{64}$")
_SHA256_ID = re.compile(r"sha256:[0-9a-f]{64}")
_PROXY_ENVIRONMENT = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)
_CREDENTIAL_ENVIRONMENT = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "DOCKER_AUTH_CONFIG",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "KUBECONFIG",
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "PYPI_TOKEN",
    "SSH_AUTH_SOCK",
    "TWINE_PASSWORD",
)
_SENSITIVE_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|AUTH|CREDENTIALS?|PASSWD|PASSWORD|PRIVATE_KEY|SECRET|SESSION|TOKEN)(?:_|$)",
    re.IGNORECASE,
)
_QUALIFICATION_MARKER = b"LUMI_TRACE_SANDBOX_QUALIFIED"

_QUALIFICATION_SCRIPT = r"""
set -eu
uid="$(id -u)"
[ "$uid" -ne 0 ]
[ "$(ulimit -c)" = "0" ]
[ ! -S /var/run/docker.sock ]
[ ! -S /run/docker.sock ]
[ ! -S /run/containerd/containerd.sock ]
[ "${HOME:-}" = "/tmp" ]
[ -z "${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}${NO_PROXY:-}" ]
[ -z "${http_proxy:-}${https_proxy:-}${all_proxy:-}${no_proxy:-}" ]
while read -r iface destination rest; do
    [ "$destination" != "00000000" ] || exit 41
done < /proc/net/route
if [ -r /proc/net/ipv6_route ]; then
    while read -r destination prefix source source_prefix next_hop metric ref use flags iface; do
        if [ "$destination" = "00000000000000000000000000000000" ] && \
           [ "$prefix" = "00" ] && [ "$iface" != "lo" ]; then
            exit 42
        fi
    done < /proc/net/ipv6_route
fi
if touch /repo/.lumi-trace-write-probe 2>/dev/null; then
    rm -f /repo/.lumi-trace-write-probe
    exit 43
fi
printf 'LUMI_TRACE_SANDBOX_QUALIFIED uid=%s\n' "$uid"
""".strip()


def _require_integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InputError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _require_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InputError(f"{name} must be numeric")
    result = float(value)
    if not minimum < result <= maximum:
        raise InputError(f"{name} must be greater than {minimum} and at most {maximum}")
    return result


def _relative_directory(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise InputError(f"{name} must be a non-empty POSIX relative directory")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", value):
        raise InputError(f"{name} must remain below the repository root")
    return path.as_posix()


def validate_reproduction_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Strictly validate and normalize reproduction-plan-v1."""

    if not isinstance(plan, dict):
        raise InputError("reproduction plan must be a JSON object")
    allowed = {"schema_version", "include_output_preview", "limits", "steps"}
    unknown = sorted(set(plan) - allowed)
    if unknown:
        raise InputError(f"unknown reproduction plan fields: {', '.join(unknown)}")
    if plan.get("schema_version") != "reproduction-plan-v1":
        raise InputError("reproduction plan must use reproduction-plan-v1")
    preview = plan.get("include_output_preview", False)
    if not isinstance(preview, bool):
        raise InputError("include_output_preview must be boolean")
    limits = plan.get("limits")
    if not isinstance(limits, dict):
        raise InputError("reproduction plan limits must be an object")
    required_limits = {"timeout_seconds", "output_bytes", "pids", "memory_mb", "cpus"}
    if set(limits) != required_limits:
        raise InputError(
            "reproduction plan limits must contain exactly: " + ", ".join(sorted(required_limits))
        )
    normalized_limits = {
        "timeout_seconds": _require_integer(
            limits["timeout_seconds"], "limits.timeout_seconds", 1, 3600
        ),
        "output_bytes": _require_integer(
            limits["output_bytes"], "limits.output_bytes", 1, 16 * 1024 * 1024
        ),
        "pids": _require_integer(limits["pids"], "limits.pids", 1, 4096),
        "memory_mb": _require_integer(limits["memory_mb"], "limits.memory_mb", 16, 65_536),
        "cpus": _require_number(limits["cpus"], "limits.cpus", 0, 256),
    }
    steps = plan.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise InputError("reproduction plan must contain 1 to 64 steps")
    normalized_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) != {"argv", "cwd", "expect"}:
            raise InputError(f"steps[{index}] must contain exactly argv, cwd, and expect")
        argv = step["argv"]
        if not isinstance(argv, list) or not 1 <= len(argv) <= 256:
            raise InputError(f"steps[{index}].argv must contain 1 to 256 strings")
        normalized_argv: list[str] = []
        for argument in argv:
            if (
                not isinstance(argument, str)
                or not argument
                or len(argument) > 8192
                or "\x00" in argument
            ):
                raise InputError(f"steps[{index}].argv contains an invalid argument")
            normalized_argv.append(argument)
        executable = normalized_argv[0]
        if (
            executable == "/repo"
            or executable.startswith("/repo/")
            or (not executable.startswith("/") and "/" in executable)
        ):
            raise InputError(
                f"steps[{index}].argv[0] must be an image executable; "
                "invoke repository scripts through an explicit interpreter"
            )
        expect = step["expect"]
        allowed_expect = {"exit_code", "stdout_contains", "stderr_contains"}
        if not isinstance(expect, dict) or not expect or set(expect) - allowed_expect:
            raise InputError(f"steps[{index}].expect has no predicate or an unknown predicate")
        normalized_expect: dict[str, Any] = {}
        if "exit_code" in expect:
            normalized_expect["exit_code"] = _require_integer(
                expect["exit_code"], f"steps[{index}].expect.exit_code", 0, 255
            )
        for key in ("stdout_contains", "stderr_contains"):
            if key not in expect:
                continue
            value = expect[key]
            if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
                raise InputError(f"steps[{index}].expect.{key} is invalid")
            normalized_expect[key] = value
        normalized_steps.append(
            {
                "argv": normalized_argv,
                "cwd": _relative_directory(step["cwd"], f"steps[{index}].cwd"),
                "expect": normalized_expect,
            }
        )
    return {
        "schema_version": "reproduction-plan-v1",
        "include_output_preview": preview,
        "limits": normalized_limits,
        "steps": normalized_steps,
    }


def load_reproduction_plan(path: Path) -> dict[str, Any]:
    value = load_json(path, max_bytes=2 * 1024 * 1024, max_items=100_000)
    if not isinstance(value, dict):
        raise InputError("reproduction plan must be a JSON object")
    return validate_reproduction_plan(value)


def plan_identity(plan: dict[str, Any]) -> str:
    return canonical_sha256(validate_reproduction_plan(plan))


def verify_reproduction_receipt(receipt: dict[str, Any]) -> None:
    """Verify required receipt structure and all canonical identities."""

    required = {
        "schema_version",
        "status",
        "reason_code",
        "reason_codes",
        "attempted",
        "repository_identity",
        "repository",
        "plan_id",
        "policy_id",
        "sandbox",
        "qualification",
        "qualification_id",
        "steps",
        "receipt_id",
        "runtime",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise InputError("reproduction receipt fields do not match reproduction-receipt-v1")
    if receipt.get("schema_version") != "reproduction-receipt-v1":
        raise InputError("reproduction receipt must use reproduction-receipt-v1")
    if receipt.get("status") not in {"COMPLETED", "TIMED_OUT", "OUTPUT_LIMIT", "UNSUPPORTED"}:
        raise InputError("reproduction receipt status is invalid")
    if not isinstance(receipt.get("attempted"), bool):
        raise InputError("reproduction receipt attempted flag is invalid")
    if not isinstance(receipt.get("reason_code"), str) or not isinstance(
        receipt.get("reason_codes"), list
    ):
        raise InputError("reproduction receipt reason codes are invalid")
    reason_codes = receipt["reason_codes"]
    if (
        not reason_codes
        or not all(
            isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", code)
            for code in reason_codes
        )
        or len(reason_codes) != len(set(reason_codes))
        or receipt["reason_code"] not in reason_codes
    ):
        raise InputError("reproduction receipt reason-code set is invalid")
    if not isinstance(receipt.get("repository"), dict) or not isinstance(
        receipt.get("sandbox"), dict
    ):
        raise InputError("reproduction receipt repository or sandbox is invalid")
    if not isinstance(receipt.get("steps"), list) or not isinstance(receipt.get("runtime"), dict):
        raise InputError("reproduction receipt steps or runtime is invalid")
    repository = receipt["repository"]
    if set(repository) != {"before", "after", "unchanged"} or not isinstance(
        repository["unchanged"], bool
    ):
        raise InputError("reproduction receipt repository attestation is invalid")
    repository_ids = [
        receipt.get("repository_identity"),
        repository.get("before"),
        repository.get("after"),
    ]
    if any(
        not isinstance(value, str) or re.fullmatch(r"repository:[0-9a-f]{64}", value) is None
        for value in repository_ids
    ) or any(
        not isinstance(receipt.get(key), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt[key]) is None
        for key in ("plan_id", "policy_id", "qualification_id", "receipt_id")
    ):
        raise InputError("reproduction receipt identity field is invalid")
    sandbox = receipt["sandbox"]
    sandbox_fields = {
        "backend",
        "qualified",
        "network_mode",
        "image_reference_sha256",
        "image_id",
        "source_mount",
    }
    if (
        set(sandbox) != sandbox_fields
        or sandbox.get("backend") != "docker"
        or not isinstance(sandbox.get("qualified"), bool)
        or sandbox.get("network_mode") != "none"
        or sandbox.get("source_mount") != "read_only"
        or not isinstance(sandbox.get("image_reference_sha256"), str)
        or _SHA256_ID.fullmatch(sandbox["image_reference_sha256"]) is None
    ):
        raise InputError("reproduction receipt sandbox attestation is invalid")
    sandbox_image_id = sandbox.get("image_id")
    if sandbox_image_id is not None and (
        not isinstance(sandbox_image_id, str) or _SHA256_ID.fullmatch(sandbox_image_id) is None
    ):
        raise InputError("reproduction receipt sandbox image identity is invalid")
    if sandbox["qualified"] and sandbox_image_id is None:
        raise InputError("qualified reproduction receipt requires a resolved image identity")
    runtime = receipt["runtime"]
    runtime_fields = {
        "engine_server_version",
        "engine_architecture",
        "engine_endpoint_class",
        "duration_ms",
        "duration_measurement",
        "qualification_cleanup_verified",
        "step_cleanup",
        "setup_reason_code",
        "output_preview_included",
    }
    if (
        set(runtime) != runtime_fields
        or runtime.get("duration_ms") is not None
        or runtime.get("duration_measurement") != "not_recorded_for_determinism"
        or not isinstance(runtime.get("output_preview_included"), bool)
        or not isinstance(runtime.get("step_cleanup"), list)
        or runtime.get("engine_server_version") is not None
        and not isinstance(runtime.get("engine_server_version"), str)
        or runtime.get("engine_architecture") is not None
        and not isinstance(runtime.get("engine_architecture"), str)
        or runtime.get("engine_endpoint_class") is not None
        and not isinstance(runtime.get("engine_endpoint_class"), str)
        or runtime.get("qualification_cleanup_verified") is not None
        and not isinstance(runtime.get("qualification_cleanup_verified"), bool)
        or runtime.get("setup_reason_code") is not None
        and (
            not isinstance(runtime.get("setup_reason_code"), str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]*", runtime["setup_reason_code"]) is None
        )
    ):
        raise InputError("reproduction receipt runtime telemetry is invalid")
    for index, step in enumerate(receipt["steps"]):
        step_fields = {
            "index",
            "argv_id",
            "cwd",
            "expect_id",
            "exit_code",
            "termination_reason",
            "timed_out",
            "output_limit_exceeded",
            "oom_killed",
            "stdout",
            "stderr",
            "witness",
        }
        if not isinstance(step, dict) or set(step) != step_fields or step.get("index") != index:
            raise InputError("reproduction receipt step structure is invalid")
        if step.get("termination_reason") not in {
            "completed",
            "timeout",
            "output_limit",
            "setup_failure",
        } or any(
            not isinstance(step.get(key), bool)
            for key in ("timed_out", "output_limit_exceeded", "oom_killed")
        ):
            raise InputError("reproduction receipt step status is invalid")
        if (
            step.get("timed_out") is not (step.get("termination_reason") == "timeout")
            or step.get("output_limit_exceeded")
            is not (step.get("termination_reason") == "output_limit")
            or step.get("exit_code") is not None
            and (not _nonnegative_receipt_integer(step.get("exit_code")) or step["exit_code"] > 255)
            or not isinstance(step.get("cwd"), str)
            or _relative_directory(step["cwd"], f"steps[{index}].cwd") != step["cwd"]
        ):
            raise InputError("reproduction receipt step execution state is invalid")
        for stream_name in ("stdout", "stderr"):
            stream = step.get(stream_name)
            if (
                not isinstance(stream, dict)
                or set(stream) - {"bytes", "sha256", "preview"}
                or not {"bytes", "sha256"}.issubset(stream)
                or not _nonnegative_receipt_integer(stream.get("bytes"))
                or not isinstance(stream.get("sha256"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", stream["sha256"]) is None
                or "preview" in stream
                and (not isinstance(stream["preview"], str) or len(stream["preview"]) > 4096)
            ):
                raise InputError("reproduction receipt output structure is invalid")
            if ("preview" in stream) is not runtime["output_preview_included"]:
                raise InputError("reproduction receipt output-preview state is inconsistent")
        witness = step.get("witness")
        if not isinstance(witness, dict) or set(witness) != {
            "matched",
            "exit_code",
            "stdout_contains",
            "stderr_contains",
        }:
            raise InputError("reproduction receipt witness structure is invalid")
        if not isinstance(witness.get("matched"), bool) or any(
            witness.get(key) is not None and not isinstance(witness.get(key), bool)
            for key in ("exit_code", "stdout_contains", "stderr_contains")
        ):
            raise InputError("reproduction receipt witness values are invalid")
        predicate_values = [
            witness[key]
            for key in ("exit_code", "stdout_contains", "stderr_contains")
            if witness[key] is not None
        ]
        if not predicate_values or witness["matched"] != all(predicate_values):
            raise InputError("reproduction receipt witness aggregate is inconsistent")
        if any(
            not isinstance(step.get(key), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", step[key]) is None
            for key in ("argv_id", "expect_id")
        ):
            raise InputError("reproduction receipt step identity is invalid")
    cleanup = runtime["step_cleanup"]
    if len(cleanup) != len(receipt["steps"]):
        raise InputError("reproduction receipt cleanup count is inconsistent")
    for index, item in enumerate(cleanup):
        if (
            not isinstance(item, dict)
            or set(item) != {"index", "kill_attempted", "remove_succeeded"}
            or item.get("index") != index
            or not isinstance(item.get("kill_attempted"), bool)
            or not isinstance(item.get("remove_succeeded"), bool)
        ):
            raise InputError("reproduction receipt cleanup structure is invalid")
    expected = canonical_sha256(receipt, omit_keys=("receipt_id",))
    if receipt.get("receipt_id") != expected:
        raise InputError("reproduction receipt identity mismatch")
    qualification = receipt.get("qualification")
    if isinstance(qualification, dict):
        qualification_fields = {
            "qualified",
            "image_id",
            "container_policy_verified",
            "non_root",
            "uid",
            "no_default_ipv4_route",
            "no_default_ipv6_route",
            "engine_sockets_absent",
            "host_credential_mounts_absent",
            "credential_environment_absent",
            "core_dumps_disabled",
            "source_read_only",
            "probe_stdout_sha256",
            "qualification_id",
        }
        boolean_fields = qualification_fields - {
            "image_id",
            "uid",
            "probe_stdout_sha256",
            "qualification_id",
        }
        if set(qualification) != qualification_fields or any(
            not isinstance(qualification.get(key), bool) for key in boolean_fields
        ):
            raise InputError("sandbox qualification structure is invalid")
        if (
            qualification.get("qualified") is not True
            or sandbox.get("qualified") is not True
            or qualification.get("image_id") != sandbox_image_id
            or not isinstance(qualification.get("image_id"), str)
            or _SHA256_ID.fullmatch(qualification["image_id"]) is None
            or not _nonnegative_receipt_integer(qualification.get("uid"))
            or qualification.get("uid") != 65_532
            or not isinstance(qualification.get("probe_stdout_sha256"), str)
            or _SHA256_ID.fullmatch(qualification["probe_stdout_sha256"]) is None
        ):
            raise InputError("sandbox qualification evidence is invalid")
        qualification_expected = canonical_sha256(qualification, omit_keys=("qualification_id",))
        if (
            qualification.get("qualification_id") != qualification_expected
            or receipt.get("qualification_id") != qualification_expected
        ):
            raise InputError("sandbox qualification identity mismatch")
    elif qualification is None:
        if sandbox.get("qualified") is not False:
            raise InputError("missing qualification cannot attest a qualified sandbox")
        qualification_expected = canonical_sha256({"reason_code": receipt.get("reason_code")})
        if receipt.get("qualification_id") != qualification_expected:
            raise InputError("unsupported receipt qualification identity mismatch")
    else:
        raise InputError("reproduction receipt qualification is invalid")


def _nonnegative_receipt_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass
class _SharedBudget:
    limit: int
    total: int = 0
    exceeded: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def reserve(self, amount: int) -> int:
        with self.lock:
            available = max(0, self.limit - self.total)
            retained = min(available, amount)
            self.total += amount
            if self.total > self.limit:
                self.exceeded = True
            return retained


@dataclass
class _Stream:
    digest: Any = field(default_factory=hashlib.sha256)
    count: int = 0
    retained: bytearray = field(default_factory=bytearray)

    def drain(self, stream: BinaryIO, budget: _SharedBudget) -> None:
        while chunk := stream.read(65_536):
            self.digest.update(chunk)
            self.count += len(chunk)
            keep = budget.reserve(len(chunk))
            if keep:
                self.retained.extend(chunk[:keep])

    def receipt(self, include_preview: bool) -> dict[str, Any]:
        result: dict[str, Any] = {
            "bytes": self.count,
            "sha256": f"sha256:{self.digest.hexdigest()}",
        }
        if include_preview:
            result["preview"] = bytes(self.retained[:4096]).decode("utf-8", errors="replace")
        return result


@dataclass
class _Execution:
    termination_reason: str
    exit_code: int | None
    timed_out: bool
    output_limit_exceeded: bool
    oom_killed: bool
    stdout: _Stream
    stderr: _Stream
    policy_verified: bool
    kill_attempted: bool
    remove_succeeded: bool
    setup_reason_code: str | None = None


class DockerSandbox:
    """Execute validated plans with a qualified local Linux Docker image."""

    def __init__(
        self,
        image: str,
        policy: dict[str, Any] | None = None,
        executable: str = "docker",
    ) -> None:
        self.image = image
        self.executable = executable
        policy = policy or {}
        unknown = sorted(set(policy) - {"tmpfs_mb", "nofile"})
        if unknown:
            raise InputError(f"unknown sandbox policy fields: {', '.join(unknown)}")
        self.tmpfs_mb = _require_integer(policy.get("tmpfs_mb", 64), "tmpfs_mb", 16, 1024)
        self.nofile = _require_integer(policy.get("nofile", 256), "nofile", 64, 4096)

    def _command(
        self, arguments: list[str], *, timeout: int = 20
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.executable, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def status(self) -> dict[str, Any]:
        """Inspect engine and image state without pulling or starting a container."""

        endpoint = self._local_endpoint()
        if not endpoint["local"]:
            return {
                "available": False,
                "reason_code": endpoint["reason_code"],
                "endpoint_class": endpoint["endpoint_class"],
            }
        try:
            version = self._command(["version", "--format", "{{json .Server}}"])
        except FileNotFoundError:
            return {"available": False, "reason_code": "ENGINE_NOT_FOUND"}
        except subprocess.TimeoutExpired:
            return {"available": False, "reason_code": "ENGINE_STATUS_TIMEOUT"}
        if version.returncode:
            return {"available": False, "reason_code": "ENGINE_UNAVAILABLE"}
        try:
            server = json.loads(version.stdout)
        except json.JSONDecodeError:
            return {"available": False, "reason_code": "ENGINE_STATUS_INVALID"}
        result: dict[str, Any] = {
            "available": True,
            "endpoint_class": endpoint["endpoint_class"],
            "server_version": server.get("Version"),
            "operating_system": server.get("Os"),
            "architecture": server.get("Arch"),
            "image_present": False,
        }
        if server.get("Os") != "linux":
            result.update(available=False, reason_code="LINUX_CONTAINERS_REQUIRED")
            return result
        if not _DIGEST_REFERENCE.search(self.image):
            result.update(reason_code="IMAGE_REFERENCE_NOT_IMMUTABLE")
            return result
        try:
            inspected = self._command(["image", "inspect", self.image])
        except subprocess.TimeoutExpired:
            result.update(reason_code="IMAGE_INSPECT_TIMEOUT")
            return result
        if inspected.returncode:
            result.update(reason_code="LOCAL_IMAGE_NOT_FOUND")
            return result
        try:
            image = json.loads(inspected.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            result.update(reason_code="IMAGE_INSPECT_INVALID")
            return result
        image_id = image.get("Id")
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            result.update(reason_code="IMAGE_ID_INVALID")
            return result
        image_config = image.get("Config") if isinstance(image.get("Config"), dict) else {}
        if image_config.get("Volumes"):
            result.update(
                image_present=True,
                image_id=image_id,
                reason_code="IMAGE_DECLARED_VOLUMES_UNSUPPORTED",
            )
            return result
        result.update(image_present=True, image_id=image_id, reason_code=None)
        return result

    @staticmethod
    def _classify_endpoint(endpoint: str) -> str | None:
        lowered = endpoint.casefold()
        if lowered.startswith("unix:///"):
            return "local-unix-socket"
        if lowered.startswith("npipe:////./pipe/"):
            return "local-windows-named-pipe"
        return None

    def _local_endpoint(self) -> dict[str, Any]:
        configured_context = os.environ.get("DOCKER_CONTEXT")
        configured_host = os.environ.get("DOCKER_HOST")
        if configured_host and not configured_context:
            endpoint_class = self._classify_endpoint(configured_host)
            return {
                "local": endpoint_class is not None,
                "endpoint_class": endpoint_class or "remote-or-unsupported",
                "reason_code": None if endpoint_class else "LOCAL_ENGINE_ENDPOINT_REQUIRED",
            }
        arguments = ["context", "inspect"]
        if configured_context:
            arguments.append(configured_context)
        arguments.extend(["--format", "{{json .Endpoints.docker.Host}}"])
        try:
            inspected = self._command(arguments)
        except FileNotFoundError:
            return {
                "local": False,
                "endpoint_class": "unavailable",
                "reason_code": "ENGINE_NOT_FOUND",
            }
        except subprocess.TimeoutExpired:
            return {
                "local": False,
                "endpoint_class": "unavailable",
                "reason_code": "ENGINE_STATUS_TIMEOUT",
            }
        if inspected.returncode:
            return {
                "local": False,
                "endpoint_class": "unresolved",
                "reason_code": "ENGINE_ENDPOINT_UNRESOLVED",
            }
        try:
            endpoint = json.loads(inspected.stdout.strip())
        except json.JSONDecodeError:
            endpoint = None
        endpoint_class = self._classify_endpoint(endpoint) if isinstance(endpoint, str) else None
        return {
            "local": endpoint_class is not None,
            "endpoint_class": endpoint_class or "remote-or-unsupported",
            "reason_code": None if endpoint_class else "LOCAL_ENGINE_ENDPOINT_REQUIRED",
        }

    def _policy(self, plan: dict[str, Any]) -> dict[str, Any]:
        return {
            "version": "docker-network-denied-policy-v1",
            "network_mode": "none",
            "engine_endpoint": "local-unix-or-local-npipe-only",
            "read_only_root": True,
            "user": "65532:65532",
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "source_mount": "read_only",
            "image_pull": "never",
            "image_entrypoint": "overridden-with-declared-argv0",
            "image_healthcheck": "disabled",
            "image_declared_volumes": "rejected",
            "container_log_driver": "none",
            "cleanup_volumes": True,
            "sensitive_environment": "cleared-and-inspected-v1",
            "tmpfs_mb": self.tmpfs_mb,
            "nofile": self.nofile,
            "limits": plan["limits"],
        }

    def _create_arguments(
        self,
        repository_root: Path,
        cwd: str,
        argv: list[str],
        image_id: str,
        limits: dict[str, Any],
        name: str,
    ) -> list[str]:
        workdir = "/repo" if cwd == "." else f"/repo/{cwd}"
        mount = f"type=bind,source={repository_root.resolve()},target=/repo,readonly"
        arguments = [
            "create",
            "--name",
            name,
            "--label",
            f"com.skylark.lumi-trace.run={name}",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--no-healthcheck",
            "--log-driver",
            "none",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(limits["pids"]),
            "--cpus",
            str(limits["cpus"]),
            "--memory",
            f"{limits['memory_mb']}m",
            "--memory-swap",
            f"{limits['memory_mb']}m",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            f"nofile={self.nofile}:{self.nofile}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_mb}m,mode=1777",
            "--mount",
            mount,
            "--workdir",
            workdir,
            "--entrypoint",
            argv[0],
            "--env",
            "HOME=/tmp",
            "--env",
            "TMPDIR=/tmp",
        ]
        for key in _PROXY_ENVIRONMENT:
            arguments.extend(["--env", f"{key}="])
        for key in _CREDENTIAL_ENVIRONMENT:
            arguments.extend(["--env", f"{key}="])
        arguments.extend([image_id, *argv[1:]])
        return arguments

    def _policy_attested(
        self,
        container: dict[str, Any],
        *,
        repository_root: Path,
        cwd: str,
        argv: list[str],
        image_id: str,
        limits: dict[str, Any],
    ) -> bool:
        host = container.get("HostConfig") or {}
        config = container.get("Config") or {}
        mounts = host.get("Mounts") or []
        source_mount = next(
            (item for item in mounts if isinstance(item, dict) and item.get("Target") == "/repo"),
            None,
        )
        try:
            source_mount_matches = Path(str(source_mount.get("Source"))).resolve(
                strict=True
            ) == repository_root.resolve(strict=True)
        except (AttributeError, OSError):
            source_mount_matches = False
        security = set(host.get("SecurityOpt") or [])
        cap_drop = {str(item).upper() for item in (host.get("CapDrop") or [])}
        ulimits = {
            item.get("Name"): (item.get("Soft"), item.get("Hard"))
            for item in (host.get("Ulimits") or [])
            if isinstance(item, dict)
        }
        tmpfs_options = str((host.get("Tmpfs") or {}).get("/tmp", ""))
        container_mounts = container.get("Mounts") or []
        environment = {}
        for item in config.get("Env") or []:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                environment[key] = value
        sensitive_environment_absent = not any(
            value and (key in _CREDENTIAL_ENVIRONMENT or _SENSITIVE_ENVIRONMENT_NAME.search(key))
            for key, value in environment.items()
        )
        return bool(
            host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and config.get("User") == "65532:65532"
            and (config.get("Labels") or {}).get("com.skylark.lumi-trace.run")
            == str(container.get("Name", "")).removeprefix("/")
            and container.get("Image") == image_id
            and config.get("WorkingDir") == ("/repo" if cwd == "." else f"/repo/{cwd}")
            and config.get("Entrypoint") == [argv[0]]
            and (config.get("Cmd") or []) == argv[1:]
            and (config.get("Healthcheck") or {}).get("Test") == ["NONE"]
            and not config.get("Volumes")
            and len(mounts) == 1
            and source_mount
            and source_mount.get("Type") == "bind"
            and source_mount.get("ReadOnly") is True
            and source_mount_matches
            and len(container_mounts) == 1
            and container_mounts[0].get("Destination") == "/repo"
            and container_mounts[0].get("RW") is False
            and "ALL" in cap_drop
            and not host.get("CapAdd")
            and "no-new-privileges:true" in security
            and host.get("PidsLimit") == int(limits["pids"])
            and host.get("Memory") == int(limits["memory_mb"]) * 1024 * 1024
            and host.get("MemorySwap") == int(limits["memory_mb"]) * 1024 * 1024
            and host.get("NanoCpus") == int(float(limits["cpus"]) * 1_000_000_000)
            and ulimits.get("core") == (0, 0)
            and ulimits.get("nofile") == (self.nofile, self.nofile)
            and all(option in tmpfs_options.split(",") for option in ("noexec", "nosuid", "nodev"))
            and f"size={self.tmpfs_mb}m" in tmpfs_options
            and (host.get("LogConfig") or {}).get("Type") == "none"
            and not host.get("Binds")
            and not host.get("VolumesFrom")
            and not host.get("Devices")
            and not host.get("DeviceRequests")
            and environment.get("HOME") == "/tmp"
            and environment.get("TMPDIR") == "/tmp"
            and all(not environment.get(key) for key in _PROXY_ENVIRONMENT)
            and sensitive_environment_absent
        )

    def _execute_container(
        self,
        repository_root: Path,
        cwd: str,
        argv: list[str],
        image_id: str,
        limits: dict[str, Any],
        output_limit: int,
    ) -> _Execution:
        name = f"lumi-trace-{uuid.uuid4().hex[:20]}"
        container_id: str | None = None
        kill_attempted = False
        remove_succeeded = False
        stdout = _Stream()
        stderr = _Stream()
        try:
            create = self._command(
                self._create_arguments(repository_root, cwd, argv, image_id, limits, name)
            )
            if create.returncode:
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    False,
                    False,
                    False,
                    "CONTAINER_CREATE_FAILED",
                )
                return execution
            container_id = create.stdout.strip()
            inspect = self._command(["inspect", container_id])
            if inspect.returncode:
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    False,
                    False,
                    False,
                    "CONTAINER_INSPECT_FAILED",
                )
                return execution
            try:
                container = json.loads(inspect.stdout)[0]
            except (json.JSONDecodeError, IndexError, TypeError):
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    False,
                    False,
                    False,
                    "CONTAINER_INSPECT_INVALID",
                )
                return execution
            policy_verified = self._policy_attested(
                container,
                repository_root=repository_root,
                cwd=cwd,
                argv=argv,
                image_id=image_id,
                limits=limits,
            )
            if not policy_verified:
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    False,
                    False,
                    False,
                    "CONTAINER_POLICY_MISMATCH",
                )
                return execution

            process = subprocess.Popen(
                [self.executable, "start", "--attach", container_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise RuntimeError("Docker attach did not expose output pipes")
            budget = _SharedBudget(output_limit)
            stdout_thread = threading.Thread(
                target=stdout.drain, args=(process.stdout, budget), daemon=True
            )
            stderr_thread = threading.Thread(
                target=stderr.drain, args=(process.stderr, budget), daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            deadline = time.monotonic() + int(limits["timeout_seconds"])
            timed_out = False
            while process.poll() is None:
                if budget.exceeded:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.02)
            if process.poll() is None:
                kill_attempted = True
                self._command(["kill", container_id], timeout=10)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                execution = _Execution(
                    "setup_failure",
                    None,
                    timed_out,
                    budget.exceeded,
                    False,
                    stdout,
                    stderr,
                    policy_verified,
                    kill_attempted,
                    False,
                    "OUTPUT_CAPTURE_INCOMPLETE",
                )
                return execution

            state_result = self._command(["inspect", container_id])
            if state_result.returncode:
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    policy_verified,
                    kill_attempted,
                    False,
                    "CONTAINER_FINAL_STATE_UNATTESTED",
                )
                return execution
            try:
                state = json.loads(state_result.stdout)[0].get("State")
            except (json.JSONDecodeError, IndexError, TypeError, AttributeError):
                state = None
            zero_time = "0001-01-01T00:00:00Z"
            state_attested = bool(
                isinstance(state, dict)
                and isinstance(state.get("OOMKilled"), bool)
                and state.get("Status") == "exited"
                and state.get("Running") is False
                and state.get("Dead") is False
                and state.get("Pid") == 0
                and state.get("Error") == ""
                and isinstance(state.get("ExitCode"), int)
                and state.get("StartedAt") not in {None, "", zero_time}
                and state.get("FinishedAt") not in {None, "", zero_time}
            )
            if not state_attested:
                execution = _Execution(
                    "setup_failure",
                    None,
                    False,
                    False,
                    False,
                    stdout,
                    stderr,
                    policy_verified,
                    kill_attempted,
                    False,
                    "CONTAINER_FINAL_STATE_UNATTESTED",
                )
                return execution
            exit_code = state.get("ExitCode")
            if not isinstance(exit_code, int):
                exit_code = process.returncode if isinstance(process.returncode, int) else None
            if timed_out:
                termination = "timeout"
            elif budget.exceeded:
                termination = "output_limit"
            else:
                termination = "completed"
            execution = _Execution(
                termination,
                exit_code,
                timed_out,
                budget.exceeded,
                bool(state.get("OOMKilled")),
                stdout,
                stderr,
                policy_verified,
                kill_attempted,
                False,
            )
            return execution
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            execution = _Execution(
                "setup_failure",
                None,
                False,
                False,
                False,
                stdout,
                stderr,
                False,
                kill_attempted,
                False,
                "CONTAINER_RUNTIME_FAILURE",
            )
            return execution
        finally:
            cleanup_target = container_id
            if cleanup_target is None:
                try:
                    uncertain = self._command(["inspect", name], timeout=10)
                    if uncertain.returncode == 0:
                        inspected_uncertain = json.loads(uncertain.stdout)[0]
                        labels = (inspected_uncertain.get("Config") or {}).get("Labels") or {}
                        if labels.get("com.skylark.lumi-trace.run") == name:
                            cleanup_target = name
                except (
                    FileNotFoundError,
                    subprocess.SubprocessError,
                    json.JSONDecodeError,
                    IndexError,
                    TypeError,
                ):
                    cleanup_target = None
            if cleanup_target:
                try:
                    removed = self._command(
                        ["rm", "--force", "--volumes", cleanup_target], timeout=10
                    )
                    remove_succeeded = removed.returncode == 0
                except (FileNotFoundError, subprocess.SubprocessError):
                    remove_succeeded = False
                # Dataclass instances already returned from try are mutable.
                current = locals().get("execution")
                if isinstance(current, _Execution):
                    current.remove_succeeded = remove_succeeded

    def _run_and_cleanup(
        self,
        repository_root: Path,
        cwd: str,
        argv: list[str],
        image_id: str,
        limits: dict[str, Any],
        output_limit: int,
    ) -> _Execution:
        """Wrap execution so cleanup status is observed after finally."""

        result = self._execute_container(repository_root, cwd, argv, image_id, limits, output_limit)
        return result

    @staticmethod
    def _witness(expect: dict[str, Any], execution: _Execution) -> dict[str, bool | None]:
        exit_match = execution.exit_code == expect["exit_code"] if "exit_code" in expect else None
        stdout_match = (
            expect["stdout_contains"].encode("utf-8") in execution.stdout.retained
            if "stdout_contains" in expect
            else None
        )
        stderr_match = (
            expect["stderr_contains"].encode("utf-8") in execution.stderr.retained
            if "stderr_contains" in expect
            else None
        )
        checks = [item for item in (exit_match, stdout_match, stderr_match) if item is not None]
        return {
            "matched": bool(checks) and all(checks),
            "exit_code": exit_match,
            "stdout_contains": stdout_match,
            "stderr_contains": stderr_match,
        }

    def _finalize_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        receipt["receipt_id"] = canonical_sha256(receipt, omit_keys=("receipt_id",))
        return receipt

    def _unsupported(
        self,
        *,
        reason_code: str,
        repository_identity: str,
        plan_id: str,
        policy_id: str,
        status: dict[str, Any],
        qualification: dict[str, Any] | None = None,
        qualification_cleanup: bool | None = None,
    ) -> dict[str, Any]:
        qualification_id = canonical_sha256(
            qualification if qualification is not None else {"reason_code": reason_code}
        )
        receipt = {
            "schema_version": "reproduction-receipt-v1",
            "status": "UNSUPPORTED",
            "reason_code": reason_code,
            "reason_codes": [reason_code],
            "attempted": False,
            "repository_identity": repository_identity,
            "repository": {
                "before": repository_identity,
                "after": repository_identity,
                "unchanged": True,
            },
            "plan_id": plan_id,
            "policy_id": policy_id,
            "sandbox": {
                "backend": "docker",
                "qualified": False,
                "network_mode": "none",
                "image_reference_sha256": sha256_bytes(self.image.encode("utf-8")),
                "image_id": status.get("image_id"),
                "source_mount": "read_only",
            },
            "qualification": qualification,
            "qualification_id": qualification_id,
            "steps": [],
            "runtime": {
                "engine_server_version": status.get("server_version"),
                "engine_architecture": status.get("architecture"),
                "engine_endpoint_class": status.get("endpoint_class"),
                "duration_ms": None,
                "duration_measurement": "not_recorded_for_determinism",
                "qualification_cleanup_verified": qualification_cleanup,
                "step_cleanup": [],
                "setup_reason_code": reason_code,
                "output_preview_included": False,
            },
        }
        return self._finalize_receipt(receipt)

    def run(
        self,
        repository_root: Path,
        repository_identity: str,
        plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Qualify the sandbox, execute the plan, and return a bounded receipt."""

        normalized = validate_reproduction_plan(plan)
        plan_id = canonical_sha256(normalized)
        policy = self._policy(normalized)
        policy_id = canonical_sha256(policy)
        status = self.status()
        if not status.get("available"):
            return self._unsupported(
                reason_code=str(status.get("reason_code") or "ENGINE_UNAVAILABLE"),
                repository_identity=repository_identity,
                plan_id=plan_id,
                policy_id=policy_id,
                status=status,
            )
        if not status.get("image_present") or status.get("reason_code"):
            return self._unsupported(
                reason_code=str(status.get("reason_code") or "LOCAL_IMAGE_NOT_FOUND"),
                repository_identity=repository_identity,
                plan_id=plan_id,
                policy_id=policy_id,
                status=status,
            )
        image_id = str(status["image_id"])
        limits = normalized["limits"]
        qualification_limits = dict(limits)
        # Sandbox qualification measures the runtime boundary, not the user's
        # workload. Keep it bounded but independent of a deliberately short
        # reproduction-step timeout so engine startup latency cannot change
        # whether an otherwise supported plan reaches its first step.
        qualification_limits["timeout_seconds"] = 15
        qualification = self._run_and_cleanup(
            repository_root,
            ".",
            ["/bin/sh", "-c", _QUALIFICATION_SCRIPT],
            image_id,
            qualification_limits,
            65_536,
        )
        marker = _QUALIFICATION_MARKER in qualification.stdout.retained
        uid_match = re.search(rb"\buid=(\d+)\b", qualification.stdout.retained)
        qualified = bool(
            qualification.termination_reason == "completed"
            and qualification.exit_code == 0
            and qualification.policy_verified
            and marker
            and uid_match
            and int(uid_match.group(1)) == 65_532
            and qualification.remove_succeeded
        )
        if not qualified:
            return self._unsupported(
                reason_code=qualification.setup_reason_code or "SANDBOX_QUALIFICATION_FAILED",
                repository_identity=repository_identity,
                plan_id=plan_id,
                policy_id=policy_id,
                status=status,
                qualification_cleanup=qualification.remove_succeeded,
            )
        qualification_record: dict[str, Any] = {
            "qualified": True,
            "image_id": image_id,
            "container_policy_verified": True,
            "non_root": True,
            "uid": 65_532,
            "no_default_ipv4_route": True,
            "no_default_ipv6_route": True,
            "engine_sockets_absent": True,
            "host_credential_mounts_absent": True,
            "credential_environment_absent": True,
            "core_dumps_disabled": True,
            "source_read_only": True,
            "probe_stdout_sha256": f"sha256:{qualification.stdout.digest.hexdigest()}",
        }
        qualification_record["qualification_id"] = canonical_sha256(qualification_record)

        step_receipts: list[dict[str, Any]] = []
        cleanup: list[dict[str, Any]] = []
        reasons: list[str] = []
        attempted = False
        global_status = "COMPLETED"
        for index, step in enumerate(normalized["steps"]):
            local_cwd = repository_root / Path(step["cwd"])
            try:
                local_cwd.resolve(strict=True).relative_to(repository_root.resolve(strict=True))
            except (FileNotFoundError, ValueError):
                reasons.append("STEP_WORKDIR_INVALID")
                global_status = "UNSUPPORTED"
                break
            if not local_cwd.is_dir():
                reasons.append("STEP_WORKDIR_INVALID")
                global_status = "UNSUPPORTED"
                break
            attempted = True
            execution = self._run_and_cleanup(
                repository_root,
                step["cwd"],
                step["argv"],
                image_id,
                limits,
                int(limits["output_bytes"]),
            )
            witness = self._witness(step["expect"], execution)
            step_receipts.append(
                {
                    "index": index,
                    "argv_id": canonical_sha256(step["argv"]),
                    "cwd": step["cwd"],
                    "expect_id": canonical_sha256(step["expect"]),
                    "exit_code": execution.exit_code,
                    "termination_reason": execution.termination_reason,
                    "timed_out": execution.timed_out,
                    "output_limit_exceeded": execution.output_limit_exceeded,
                    "oom_killed": execution.oom_killed,
                    "stdout": execution.stdout.receipt(normalized["include_output_preview"]),
                    "stderr": execution.stderr.receipt(normalized["include_output_preview"]),
                    "witness": witness,
                }
            )
            cleanup.append(
                {
                    "index": index,
                    "kill_attempted": execution.kill_attempted,
                    "remove_succeeded": execution.remove_succeeded,
                }
            )
            if execution.termination_reason == "timeout":
                global_status = "TIMED_OUT"
                reasons.append("REPRODUCTION_TIMEOUT")
                break
            if execution.termination_reason == "output_limit":
                global_status = "OUTPUT_LIMIT"
                reasons.append("REPRODUCTION_OUTPUT_LIMIT")
                break
            if execution.termination_reason == "setup_failure":
                global_status = "UNSUPPORTED"
                reasons.append(execution.setup_reason_code or "REPRODUCTION_SETUP_FAILED")
                break
            if execution.oom_killed:
                reasons.append("REPRODUCTION_OOM_KILLED")
            if not execution.remove_succeeded:
                reasons.append("SANDBOX_CLEANUP_FAILED")
            if not witness["matched"]:
                reasons.append("EXPLICIT_WITNESS_NOT_OBSERVED")

        after_identity = compute_repository_identity(repository_root)["repository_id"]
        unchanged = after_identity == repository_identity
        if not unchanged:
            reasons.append("REPOSITORY_CHANGED")
        if not reasons:
            reasons.append("EXECUTION_COMPLETED")
        reasons = sorted(set(reasons))
        primary = {
            "TIMED_OUT": "REPRODUCTION_TIMEOUT",
            "OUTPUT_LIMIT": "REPRODUCTION_OUTPUT_LIMIT",
            "UNSUPPORTED": reasons[0],
        }.get(global_status, reasons[0])
        receipt: dict[str, Any] = {
            "schema_version": "reproduction-receipt-v1",
            "status": global_status,
            "reason_code": primary,
            "reason_codes": reasons,
            "attempted": attempted,
            "repository_identity": repository_identity,
            "repository": {
                "before": repository_identity,
                "after": after_identity,
                "unchanged": unchanged,
            },
            "plan_id": plan_id,
            "policy_id": policy_id,
            "sandbox": {
                "backend": "docker",
                "qualified": True,
                "network_mode": "none",
                "image_reference_sha256": sha256_bytes(self.image.encode("utf-8")),
                "image_id": image_id,
                "source_mount": "read_only",
            },
            "qualification": qualification_record,
            "qualification_id": qualification_record["qualification_id"],
            "steps": step_receipts,
            "runtime": {
                "engine_server_version": status.get("server_version"),
                "engine_architecture": status.get("architecture"),
                "engine_endpoint_class": status.get("endpoint_class"),
                "duration_ms": None,
                "duration_measurement": "not_recorded_for_determinism",
                "qualification_cleanup_verified": qualification.remove_succeeded,
                "step_cleanup": cleanup,
                "setup_reason_code": None if global_status == "COMPLETED" else primary,
                "output_preview_included": normalized["include_output_preview"],
            },
        }
        return self._finalize_receipt(receipt)
