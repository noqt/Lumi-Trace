# SPDX-License-Identifier: Apache-2.0
"""Dedicated Trace-Eval environment and storage qualification."""

from __future__ import annotations

import importlib.metadata
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .canonical import dump_json, sha256_file
from .contracts import make_record
from .errors import PolicyError


def _ensure_isolated_roots(roots: dict[str, str]) -> dict[str, str]:
    if len(roots) != len(set(roots.values())):
        raise PolicyError("Trace-Eval roots must be distinct")
    resolved: dict[str, str] = {}
    for role, value in roots.items():
        path = Path(value).resolve(strict=False)
        lowered = {part.casefold() for part in path.parts}
        if lowered & {"cybergym", "scout", "yumi", "yumi-train", "lumi-scout"}:
            raise PolicyError(f"Trace-Eval root crosses a prohibited product boundary: {role}")
        path.mkdir(parents=True, exist_ok=True)
        resolved[role] = str(path)
    paths = [Path(value) for value in resolved.values()]
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            try:
                second.relative_to(first)
            except ValueError:
                pass
            else:
                raise PolicyError("Trace-Eval storage roles must not be nested")
            try:
                first.relative_to(second)
            except ValueError:
                pass
            else:
                raise PolicyError("Trace-Eval storage roles must not be nested")
    return resolved


def _docker_facts() -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{json .Server}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "server": None}
    return {"available": result.returncode == 0, "server": result.stdout.strip() or None}


def qualify_environment(
    *,
    runtime_artifact: Path,
    expected_runtime_sha256: str,
    evaluator_artifact: Path,
    expected_evaluator_sha256: str,
    evaluator_source_revision: str,
    dependency_lock: Path,
    roots: dict[str, str],
    output: Path,
) -> dict[str, Any]:
    if sys.version_info[:2] != (3, 11):
        raise PolicyError("Trace-Eval reference qualification requires Python 3.11")
    if sys.prefix == sys.base_prefix:
        raise PolicyError("Trace-Eval must run inside its dedicated virtual environment")
    runtime_hash = sha256_file(runtime_artifact)
    if runtime_hash != expected_runtime_sha256:
        raise PolicyError("V0.1 system-under-test artifact does not match the approved hash")
    evaluator_hash = sha256_file(evaluator_artifact)
    if evaluator_hash != expected_evaluator_sha256:
        raise PolicyError("Trace-Eval artifact does not match the approved hash")
    resolved_roots = _ensure_isolated_roots(roots)
    packages = sorted(
        {
            distribution.metadata.get("Name", "unknown").casefold(): distribution.version
            for distribution in importlib.metadata.distributions()
        }.items()
    )
    facts = {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_prefix_isolated": sys.prefix != sys.base_prefix,
        "packages": [{"name": name, "version": version} for name, version in packages],
        "docker": _docker_facts(),
        "filesystems": {
            role: {
                "free_bytes": shutil.disk_usage(path).free,
                "total_bytes": shutil.disk_usage(path).total,
            }
            for role, path in resolved_roots.items()
        },
    }
    record = make_record(
        "environment-qualification-v1",
        {
            "environment": "Trace-Eval",
            "sut": {
                "release": "v0.1.0",
                "release_commit": "04bee651f6347ec3b4b5d3a941029ef8f6bfc48d",
                "artifact_sha256": runtime_hash,
                "model_status": "PROPOSED_NOT_TRAINED",
                "checkpoint": None,
                "active_parameters": 0,
            },
            "evaluator": {
                "release": "v0.2.0",
                "artifact_sha256": evaluator_hash,
                "source_revision": evaluator_source_revision,
                "package": "skylark-lumi-trace-eval",
            },
            "roots": resolved_roots,
            "facts": facts,
            "isolation": {
                "system_python": False,
                "shared_editable_install": False,
                "scout_dependency": False,
                "yumi_dependency": False,
                "shared_model_cache": False,
                "dependency_lock_sha256": sha256_file(dependency_lock),
                "offline_after_staging": True,
            },
        },
    )
    dump_json(output, record)
    return record
