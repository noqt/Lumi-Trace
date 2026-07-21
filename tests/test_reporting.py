# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lumi_trace.canonical import canonical_sha256, stable_id
from lumi_trace.errors import InputError, IntegrityError
from lumi_trace.findings import import_manual
from lumi_trace.indexing import build_repository_index
from lumi_trace.ranking import rank_candidates
from lumi_trace.reporting import (
    build_evidence_bundle,
    classify_evidence,
    export_sarif,
    verify_evidence_bundle,
)
from lumi_trace.repository import RepositoryWorkspace
from lumi_trace.sandbox import verify_reproduction_receipt


def _confirmed_receipt(repository_id: str) -> dict[str, object]:
    image_id = "sha256:" + "a" * 64
    qualification: dict[str, object] = {
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
        "probe_stdout_sha256": "sha256:" + "b" * 64,
    }
    qualification["qualification_id"] = canonical_sha256(qualification)
    receipt: dict[str, object] = {
        "schema_version": "reproduction-receipt-v1",
        "status": "COMPLETED",
        "reason_code": "EXECUTION_COMPLETED",
        "reason_codes": ["EXECUTION_COMPLETED"],
        "attempted": True,
        "repository_identity": repository_id,
        "plan_id": "sha256:" + "c" * 64,
        "policy_id": "sha256:" + "d" * 64,
        "sandbox": {
            "backend": "docker",
            "qualified": True,
            "network_mode": "none",
            "image_reference_sha256": "sha256:" + "e" * 64,
            "image_id": image_id,
            "source_mount": "read_only",
        },
        "qualification": qualification,
        "qualification_id": qualification["qualification_id"],
        "repository": {
            "before": repository_id,
            "after": repository_id,
            "unchanged": True,
        },
        "steps": [
            {
                "index": 0,
                "argv_id": "sha256:" + "f" * 64,
                "cwd": ".",
                "expect_id": "sha256:" + "1" * 64,
                "exit_code": 23,
                "termination_reason": "completed",
                "timed_out": False,
                "output_limit_exceeded": False,
                "oom_killed": False,
                "stdout": {"bytes": 0, "sha256": "sha256:" + "0" * 64},
                "stderr": {"bytes": 0, "sha256": "sha256:" + "0" * 64},
                "witness": {
                    "matched": True,
                    "exit_code": True,
                    "stdout_contains": None,
                    "stderr_contains": None,
                },
            }
        ],
        "runtime": {
            "engine_server_version": "fixture",
            "engine_architecture": "fixture",
            "engine_endpoint_class": "local-unix-socket",
            "duration_ms": None,
            "duration_measurement": "not_recorded_for_determinism",
            "qualification_cleanup_verified": True,
            "step_cleanup": [{"index": 0, "kill_attempted": False, "remove_succeeded": True}],
            "setup_reason_code": None,
            "output_preview_included": False,
        },
    }
    receipt["receipt_id"] = canonical_sha256(receipt)
    return receipt


def test_classification_requires_a_qualified_explicit_witness() -> None:
    assert classify_evidence(reproduction_requested=False, receipt=None)["outcome"] == (
        "INSUFFICIENT_EVIDENCE"
    )
    receipt = _confirmed_receipt("repository:fixture")
    assert classify_evidence(reproduction_requested=True, receipt=receipt)["outcome"] == "CONFIRMED"
    receipt["steps"] = [{"witness": {"matched": False}}]
    assert classify_evidence(reproduction_requested=True, receipt=receipt)["outcome"] == (
        "INSUFFICIENT_EVIDENCE"
    )


def test_classification_rejects_oom_even_when_witness_matches() -> None:
    receipt = _confirmed_receipt("repository:fixture")
    receipt["reason_code"] = "REPRODUCTION_OOM_KILLED"
    receipt["reason_codes"] = ["REPRODUCTION_OOM_KILLED"]
    receipt["steps"][0]["oom_killed"] = True
    result = classify_evidence(reproduction_requested=True, receipt=receipt)
    assert result["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert "REPRODUCTION_OOM_KILLED" in result["reason_codes"]


def test_classification_rejects_a_receipt_level_confirmed_status() -> None:
    receipt = _confirmed_receipt("repository:fixture")
    receipt["status"] = "CONFIRMED"
    result = classify_evidence(reproduction_requested=True, receipt=receipt)
    assert result["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert "REPRODUCTION_INFRASTRUCTURE_FAILURE" in result["reason_codes"]


def test_receipt_verification_requires_resolved_sandbox_identity() -> None:
    receipt = _confirmed_receipt("repository:" + "9" * 64)
    receipt["sandbox"]["image_reference_sha256"] = None
    receipt["sandbox"]["image_id"] = None
    receipt["qualification"]["image_id"] = None
    receipt["qualification"]["probe_stdout_sha256"] = None
    receipt["qualification"]["qualification_id"] = canonical_sha256(
        receipt["qualification"], omit_keys=("qualification_id",)
    )
    receipt["qualification_id"] = receipt["qualification"]["qualification_id"]
    receipt["receipt_id"] = canonical_sha256(receipt, omit_keys=("receipt_id",))
    with pytest.raises(InputError, match="sandbox attestation"):
        verify_reproduction_receipt(receipt)


def test_bundle_and_sarif_are_verifiable_and_contain_no_snippets(
    fixture_repository: Path, manual_finding_path: Path
) -> None:
    finding = import_manual(manual_finding_path, fixture_repository)
    with RepositoryWorkspace(fixture_repository) as workspace:
        index = build_repository_index(workspace.root, workspace.identity)
        candidates = rank_candidates(finding, index)
        bundle = build_evidence_bundle(
            finding=finding,
            repository=workspace.identity,
            index=index,
            candidate_set=candidates,
            reproduction_requested=True,
            receipt=_confirmed_receipt(str(workspace.identity["repository_id"])),
            source_revision="fixture-revision",
        )
    verify_evidence_bundle(bundle)
    assert bundle["classification"]["outcome"] == "CONFIRMED"
    sarif = export_sarif(bundle)
    encoded = json.dumps(sarif)
    assert '"snippet"' not in encoded
    assert str(fixture_repository) not in encoded
    assert sarif["runs"][0]["results"][0]["properties"]["currentWeights"] == 0

    false_confirmation = build_evidence_bundle(
        finding=finding,
        repository=workspace.identity,
        index=index,
        candidate_set=candidates,
        reproduction_requested=False,
        receipt=None,
        source_revision="fixture-revision",
    )
    false_confirmation["classification"] = bundle["classification"]
    false_confirmation["bundle_id"] = stable_id(
        "evidence-bundle", false_confirmation, omit_keys=("bundle_id",)
    )
    with pytest.raises(IntegrityError, match="classification is inconsistent"):
        verify_evidence_bundle(false_confirmation)

    malformed_candidates = build_evidence_bundle(
        finding=finding,
        repository=workspace.identity,
        index=index,
        candidate_set=candidates,
        reproduction_requested=False,
        receipt=None,
        source_revision="fixture-revision",
    )
    malformed_candidates["candidates"] = [{"rank": 1}]
    malformed_candidates["bundle_id"] = stable_id(
        "evidence-bundle", malformed_candidates, omit_keys=("bundle_id",)
    )
    with pytest.raises(IntegrityError, match="candidate structure"):
        verify_evidence_bundle(malformed_candidates)
