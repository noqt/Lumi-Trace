# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from trace_eval.canonical import dump_json, load_json, sha256_file
from trace_eval.contracts import make_record
from trace_eval.errors import RunnerError
from trace_eval.metrics import score_run, verify_scored_package
from trace_eval.package import verify_package
from trace_eval.readiness import evaluate_readiness
from trace_eval.replay import compare_run_packages, replay_run
from trace_eval.runner import load_run_package, run_registry, verify_runtime

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "eval" / "public-fixtures" / "v0.2"
WHEEL = (
    ROOT / "evidence" / "v0.1.0" / "release-artifacts" / "skylark_lumi_trace-0.1.0-py3-none-any.whl"
)


def _runtime_executable() -> Path:
    name = "lumi-trace.exe" if os.name == "nt" else "lumi-trace"
    executable = Path(sys.executable).parent / name
    if not executable.is_file():
        pytest.skip("the V0.1 development CLI is not installed in this test environment")
    return executable


def _run(tmp_path: Path) -> Path:
    output = tmp_path / "run"
    run_registry(
        registry_path=PUBLIC / "runner-registry.json",
        configuration_path=PUBLIC / "configuration.json",
        executable=_runtime_executable(),
        runtime_artifact=WHEEL,
        source_root=ROOT,
        workspace_root=tmp_path / "workspace",
        output=output,
    )
    return output


def test_public_fixture_run_score_replay_and_readiness_closure(tmp_path: Path) -> None:
    run = _run(tmp_path)
    run_record, attempts, _ = load_run_package(run)
    assert len(attempts) == 3
    assert all(attempt["payload"]["status"] == "COMPLETED" for attempt in attempts)
    raw_seal = load_json(run / "raw-output-seal.json")
    assert raw_seal["payload"]["sealed_before_labels"] is True
    assert not any(
        "label-set-v1" in path.read_text(encoding="utf-8", errors="ignore")
        for path in run.rglob("*.json")
    )

    scored = tmp_path / "scored"
    score_run(
        run_root=run,
        registry_path=PUBLIC / "runner-registry.json",
        labels_path=PUBLIC / "labels.json",
        metric_spec_path=PUBLIC / "metric-specification.json",
        output=scored,
    )
    verify_scored_package(scored)

    replay = tmp_path / "replay"
    result = replay_run(
        original=run,
        registry=PUBLIC / "runner-registry.json",
        configuration=PUBLIC / "configuration.json",
        executable=_runtime_executable(),
        runtime_artifact=WHEEL,
        source_root=ROOT,
        workspace_root=tmp_path / "replay-workspace",
        output=replay,
    )
    assert result["record"]["payload"]["identity_agreement"] is True
    assert (
        compare_run_packages(run, replay / "replayed-run", identity_required=False)["payload"][
            "semantic_agreement"
        ]
        is True
    )
    verify_package(replay)

    environment = make_record(
        "environment-qualification-v1",
        {
            "environment": "Trace-Eval unit fixture",
            "sut": {
                "release": "v0.1.0",
                "artifact_sha256": sha256_file(WHEEL),
                "active_parameters": 0,
            },
            "evaluator": {
                "release": "v0.2.0",
                "artifact_sha256": "sha256:" + "0" * 64,
                "source_revision": "unit-fixture",
            },
            "roots": {"workspace": str(tmp_path / "workspace")},
            "facts": {"python": sys.version.split()[0]},
            "isolation": {"unit_fixture": True},
        },
    )
    environment_path = tmp_path / "environment.json"
    dump_json(environment_path, environment)
    closure = evaluate_readiness(
        environment_record_path=environment_path,
        registry_path=PUBLIC / "runner-registry.json",
        run_package=run,
        scored_package=scored,
        replay_package=replay,
        output=tmp_path / "readiness",
    )
    assert closure["readiness"]["payload"]["closure_state"] == (
        "ENVIRONMENT_QUALIFIED / DATA_GATES_PENDING"
    )
    assert closure["readiness"]["payload"]["recommendation"] == "DO_NOT_BEGIN_TRACE_001"
    assert closure["readiness"]["payload"]["training_started"] is False
    assert run_record["payload"]["mode"] == "public-fixture"


def test_runtime_artifact_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    configuration = load_json(PUBLIC / "configuration.json")
    wrong = tmp_path / "wrong.whl"
    wrong.write_bytes(b"not the approved runtime")
    with pytest.raises(RunnerError, match="artifact hash mismatch"):
        verify_runtime(configuration, _runtime_executable(), wrong)


def test_timeout_is_preserved_as_a_result_without_labels(tmp_path: Path) -> None:
    configuration = load_json(PUBLIC / "configuration.json")
    payload = deepcopy(configuration["payload"])
    payload["limits"]["case_timeout_seconds"] = 0
    bounded = make_record("evaluator-configuration-v1", payload)
    configuration_path = tmp_path / "bounded-configuration.json"
    dump_json(configuration_path, bounded)
    output = tmp_path / "timeout-run"
    run_registry(
        registry_path=PUBLIC / "runner-registry.json",
        configuration_path=configuration_path,
        executable=_runtime_executable(),
        runtime_artifact=WHEEL,
        source_root=ROOT,
        workspace_root=tmp_path / "workspace",
        output=output,
    )
    _, attempts, _ = load_run_package(output)
    assert len(attempts) == 3
    assert all(attempt["payload"]["status"] == "FAILED" for attempt in attempts)
    assert all(
        "RESOURCE_LIMIT_REACHED" in attempt["payload"]["failure_codes"] for attempt in attempts
    )
    assert (output / "raw-output-seal.json").is_file()
