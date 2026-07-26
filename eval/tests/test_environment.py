# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from trace_eval import environment
from trace_eval.canonical import sha256_file
from trace_eval.errors import PolicyError

RPDS_PYTHON_312_WINDOWS_SHA256 = "2c958bf94822e9290a40aaf2a822d4bc5c88099093e3948ad6c571eca9272e5f"


def test_environment_qualification_binds_both_artifacts_and_separated_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime.whl"
    evaluator = tmp_path / "evaluator.whl"
    lock = tmp_path / "requirements.lock"
    runtime.write_bytes(b"approved runtime")
    evaluator.write_bytes(b"approved evaluator")
    lock.write_text("dependency==1 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8")
    monkeypatch.setattr(environment.sys, "version_info", (3, 11, 9))
    monkeypatch.setattr(environment.sys, "prefix", "isolated")
    monkeypatch.setattr(environment.sys, "base_prefix", "base")
    monkeypatch.setattr(environment, "_docker_facts", lambda: {"available": False, "server": None})
    output = tmp_path / "qualification.json"
    record = environment.qualify_environment(
        runtime_artifact=runtime,
        expected_runtime_sha256=sha256_file(runtime),
        evaluator_artifact=evaluator,
        expected_evaluator_sha256=sha256_file(evaluator),
        evaluator_source_revision="a" * 40,
        dependency_lock=lock,
        roots={
            "workspace": str(tmp_path / "workspace"),
            "runs": str(tmp_path / "runs"),
        },
        output=output,
    )
    assert record["payload"]["sut"]["artifact_sha256"] == sha256_file(runtime)
    assert record["payload"]["evaluator"]["artifact_sha256"] == sha256_file(evaluator)
    assert record["payload"]["isolation"]["shared_editable_install"] is False
    assert output.is_file()


def test_environment_rejects_nested_and_prohibited_product_roots(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="must not be nested"):
        environment._ensure_isolated_roots(
            {"runs": str(tmp_path / "runs"), "cases": str(tmp_path / "runs" / "cases")}
        )
    with pytest.raises(PolicyError, match="prohibited product boundary"):
        environment._ensure_isolated_roots({"cache": str(tmp_path / "Yumi-Train" / "cache")})


def test_dependency_lock_covers_the_supported_python_312_windows_wheel() -> None:
    lock = Path(__file__).parents[1] / "requirements" / "trace-eval.lock"
    assert f"--hash=sha256:{RPDS_PYTHON_312_WINDOWS_SHA256}" in lock.read_text(encoding="utf-8")
