# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lumi_trace.errors import InputError
from lumi_trace.reporting import classify_evidence
from lumi_trace.repository import RepositoryWorkspace
from lumi_trace.sandbox import (
    DockerSandbox,
    load_reproduction_plan,
    plan_identity,
    validate_reproduction_plan,
)


def test_plan_is_strict_and_stable(project_root: Path) -> None:
    plan = load_reproduction_plan(project_root / "tests" / "data" / "reproduction-plan.json")
    assert plan["schema_version"] == "reproduction-plan-v1"
    assert plan["include_output_preview"] is False
    assert plan["limits"]["cpus"] == 0.5
    assert plan_identity(plan) == plan_identity(dict(reversed(list(plan.items()))))


def test_plan_requires_image_executable_for_repository_script(project_root: Path) -> None:
    plan = load_reproduction_plan(project_root / "tests" / "data" / "reproduction-plan.json")
    plan["steps"][0]["argv"] = ["./tests/reproduce.sh"]
    with pytest.raises(InputError, match="explicit interpreter"):
        validate_reproduction_plan(plan)


def test_container_arguments_enforce_the_isolation_policy(tmp_path: Path) -> None:
    sandbox = DockerSandbox("sha256:" + "a" * 64)
    arguments = sandbox._create_arguments(  # noqa: SLF001 - policy construction is a contract
        tmp_path,
        ".",
        ["/bin/sh", "-c", "true"],
        "sha256:" + "b" * 64,
        {"timeout_seconds": 5, "output_bytes": 1000, "pids": 12, "memory_mb": 32, "cpus": 0.5},
        "lumi-trace-fixture",
    )
    rendered = "\n".join(arguments)
    assert "none" in arguments
    assert "--read-only" in arguments
    assert "--no-healthcheck" in arguments
    assert "--log-driver" in arguments and "none" in arguments
    assert "--entrypoint" in arguments
    assert "65532:65532" in arguments
    assert "ALL" in arguments
    assert "no-new-privileges:true" in arguments
    assert "core=0:0" in arguments
    assert "target=/repo,readonly" in rendered
    assert "HTTP_PROXY=" in arguments
    assert "--pull" in arguments and "never" in arguments


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp://127.0.0.1:2375",
        "ssh://builder.example.invalid",
        "npipe:////remote-host/pipe/docker_engine",
    ],
)
def test_remote_or_nonlocal_engine_endpoint_is_rejected(
    monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    status = DockerSandbox("sha256:" + "a" * 64).status()
    assert status == {
        "available": False,
        "reason_code": "LOCAL_ENGINE_ENDPOINT_REQUIRED",
        "endpoint_class": "remote-or-unsupported",
    }


def test_image_with_declared_volume_is_unsupported(
    project_root: Path, fixture_repository: Path
) -> None:
    class VolumeImageSandbox(DockerSandbox):
        def status(self) -> dict[str, object]:
            return {
                "available": True,
                "image_present": True,
                "image_id": "sha256:" + "b" * 64,
                "reason_code": "IMAGE_DECLARED_VOLUMES_UNSUPPORTED",
                "endpoint_class": "local-unix-socket",
            }

    plan = load_reproduction_plan(project_root / "tests" / "data" / "reproduction-plan.json")
    with RepositoryWorkspace(fixture_repository) as workspace:
        receipt = VolumeImageSandbox("sha256:" + "a" * 64).run(
            workspace.root, str(workspace.identity["repository_id"]), plan
        )
    assert receipt["status"] == "UNSUPPORTED"
    assert receipt["reason_code"] == "IMAGE_DECLARED_VOLUMES_UNSUPPORTED"


@pytest.mark.docker
def test_owned_fixture_confirms_in_network_denied_sandbox(
    project_root: Path, fixture_repository: Path
) -> None:
    image = os.environ.get("LUMI_TRACE_TEST_IMAGE")
    if not image:
        pytest.skip("LUMI_TRACE_TEST_IMAGE is not set to a preloaded immutable image")
    plan = load_reproduction_plan(project_root / "tests" / "data" / "reproduction-plan.json")
    before = set(
        subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=lumi-trace-", "--format", "{{.ID}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    )
    with RepositoryWorkspace(fixture_repository) as workspace:
        first = DockerSandbox(image).run(
            workspace.root, str(workspace.identity["repository_id"]), plan
        )
        second = DockerSandbox(image).run(
            workspace.root, str(workspace.identity["repository_id"]), plan
        )
    after = set(
        subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=lumi-trace-", "--format", "{{.ID}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    )
    assert before == after
    assert first == second
    assert first["status"] == "COMPLETED"
    assert first["sandbox"] == {
        "backend": "docker",
        "qualified": True,
        "network_mode": "none",
        "image_reference_sha256": first["sandbox"]["image_reference_sha256"],
        "image_id": first["sandbox"]["image_id"],
        "source_mount": "read_only",
    }
    assert all(
        first["qualification"][key] is True
        for key in (
            "qualified",
            "container_policy_verified",
            "non_root",
            "no_default_ipv4_route",
            "no_default_ipv6_route",
            "engine_sockets_absent",
            "host_credential_mounts_absent",
            "credential_environment_absent",
            "core_dumps_disabled",
            "source_read_only",
        )
    )
    assert first["repository"]["unchanged"] is True
    assert first["steps"][0]["witness"]["matched"] is True
    assert classify_evidence(reproduction_requested=True, receipt=first)["outcome"] == "CONFIRMED"
    schema = json.loads(
        (project_root / "schemas" / "reproduction-receipt-v1.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(first)


@pytest.mark.docker
def test_missing_container_entrypoint_cannot_confirm(
    project_root: Path, fixture_repository: Path
) -> None:
    image = os.environ.get("LUMI_TRACE_TEST_IMAGE")
    if not image:
        pytest.skip("LUMI_TRACE_TEST_IMAGE is not set to a preloaded immutable image")
    plan = load_reproduction_plan(project_root / "tests" / "data" / "reproduction-plan.json")
    plan["steps"][0]["argv"] = ["/definitely-not-a-lumi-command"]
    plan["steps"][0]["expect"] = {
        "exit_code": 127,
        "stderr_contains": "definitely-not-a-lumi-command",
    }
    with RepositoryWorkspace(fixture_repository) as workspace:
        receipt = DockerSandbox(image).run(
            workspace.root, str(workspace.identity["repository_id"]), plan
        )
    assert receipt["status"] == "UNSUPPORTED"
    assert receipt["reason_code"] == "CONTAINER_FINAL_STATE_UNATTESTED"
    assert classify_evidence(reproduction_requested=True, receipt=receipt)["outcome"] == (
        "UNSUPPORTED"
    )
