# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from trace_eval.contracts import make_record
from trace_eval.programme import (
    assess_natural_corpus,
    close_v03,
    programme_boundary,
    v03_readiness,
)


def _split(assignments: dict[str, str]) -> dict[str, object]:
    partitions = {
        "public_regression": [],
        "construction": [],
        "future_training_candidate": [],
        "development": [],
        "qualification": [],
        "frozen_holdback": [],
    }
    for repository_id, partition in assignments.items():
        partitions[partition].append(repository_id)
    return make_record(
        "split-manifest-v1",
        {
            "partitions": partitions,
            "repositories": assignments,
            "locked": True,
            "independence_method": "tree, lineage, family, history, and content fingerprints",
        },
    )


def _rights(number: int) -> dict[str, object]:
    digest = f"{number + 1:064x}"
    return make_record(
        "repository-rights-manifest-v1",
        {
            "repository_id": f"repository:{number}",
            "tree_id": f"sha256:{digest}",
            "source": "rights-cleared test record",
            "acquisition_method": "immutable local archive",
            "licence": "Apache-2.0",
            "rights_basis": "authorship",
            "redistribution_status": "PRIVATE_EVALUATION_ONLY",
            "review_status": "SKYLARK_AUTHORED",
            "lineage_id": f"lineage:{number}",
            "family_id": f"family:{number}",
            "shared_history_root": f"history:{number}",
            "exposure_state": "DEVELOPMENT_VISIBLE",
            "governed_location": f"repositories/{number}",
            "input_hashes": [f"sha256:{digest}"],
            "content_fingerprints": [f"sha256:{digest}"],
        },
    )


def _label(number: int, repository: int) -> dict[str, object]:
    return make_record(
        "trace-code-location-label-v1",
        {
            "group_id": f"group:{number}",
            "label_state": "ACCEPTED",
            "repository_id": f"repository:{repository}",
            "repository_family": f"family:{repository}",
            "expected_disposition": "SUPPORTED",
            "targets": [
                {
                    "path": f"src/case_{number}.py",
                    "role": "VULNERABLE_IMPLEMENTATION",
                }
            ],
            "primary_role": "VULNERABLE_IMPLEMENTATION",
            "hard_negatives": [],
            "safe_control": False,
            "review_receipt_ids": [f"review:{number}"],
            "corrections": [],
            "constructed_without_runner_output": True,
        },
    )


def _ir_decision() -> dict[str, object]:
    return make_record(
        "trace-ir-feasibility-decision-v1",
        {
            "lane_state": "IR_FEASIBILITY_SUPPORTED",
            "evidence_ids": ["trace-ir-metrics:test"],
            "live_integrations": False,
            "response_actions": False,
            "performance_claim": "OWNED_LAB_FIXTURE_FEASIBILITY_ONLY",
        },
    )


def test_programme_boundary_preserves_all_stop_gates() -> None:
    boundary = programme_boundary()
    payload = boundary["payload"]
    assert payload["training_authorised"] is False
    assert payload["weights_acquired"] is False
    assert payload["holdback_state"] == "FROZEN_UNOPENED"
    assert "CYBERGYM" in payload["prohibited_sources"]
    assert "HISTORICAL_LUMI_EVIDENCE" in payload["prohibited_sources"]


def test_empty_natural_store_closes_data_gates_pending() -> None:
    registry, lineage = assess_natural_corpus(
        repositories=[],
        labels=[],
        split_manifest=_split({}),
        private_evidence_location="GOVERNED_G_DRIVE_PRIVATE_STORE",
    )
    assert registry["payload"]["accepted_group_count"] == 0
    assert registry["payload"]["accepted_repository_count"] == 0
    assert registry["payload"]["sufficiency"] == "DATA_GATES_PENDING"
    assert lineage["payload"]["holdback_opened"] is False
    readiness = v03_readiness(
        natural_registry=registry,
        lineage_audit=lineage,
        ir_decision=_ir_decision(),
        environment_evidence_ids=["lumi-trace-v0.2-public-evidence:test"],
    )
    assert readiness["payload"]["recommendation"] == "DO_NOT_BEGIN_TRACE_001"
    assert readiness["payload"]["training_started"] is False
    assert all("gate" in gate and "status" in gate for gate in readiness["payload"]["gates"])
    closure = close_v03(
        natural_registry=registry,
        ir_decision=_ir_decision(),
        evidence_ids=[readiness["record_id"]],
    )
    assert closure["payload"]["programme_state"] == "DATA_GATES_PENDING"
    assert closure["payload"]["ir_lane_state"] == "IR_FEASIBILITY_SUPPORTED"
    assert closure["payload"]["qualification_run"] is False
    assert closure["payload"]["publication_decision"] == "NO_GO_PENDING_USER_REVIEW"


def test_pilot_contract_requires_50_groups_and_8_repositories() -> None:
    repositories = [_rights(number) for number in range(8)]
    assignments = {
        repository["payload"]["repository_id"]: "development" for repository in repositories
    }
    labels = [_label(number, number % 8) for number in range(50)]
    registry, lineage = assess_natural_corpus(
        repositories=repositories,
        labels=labels,
        split_manifest=_split(assignments),
        private_evidence_location="GOVERNED_G_DRIVE_PRIVATE_STORE",
    )
    assert registry["payload"]["sufficiency"] == "PILOT_TARGET_MET"
    assert lineage["payload"]["cross_partition_overlap_count"] == 0


def test_revision_snapshots_count_once_per_unrelated_repository_family() -> None:
    repositories = [_rights(number) for number in range(2)]
    second_payload = dict(repositories[1]["payload"])
    second_payload["family_id"] = repositories[0]["payload"]["family_id"]
    second_payload["lineage_id"] = repositories[0]["payload"]["lineage_id"]
    second_payload["shared_history_root"] = repositories[0]["payload"]["shared_history_root"]
    repositories[1] = make_record("repository-rights-manifest-v1", second_payload)
    assignments = {
        repository["payload"]["repository_id"]: "development" for repository in repositories
    }
    labels = [_label(0, 0), _label(1, 1)]
    registry, _ = assess_natural_corpus(
        repositories=repositories,
        labels=labels,
        split_manifest=_split(assignments),
        private_evidence_location="GOVERNED_G_DRIVE_PRIVATE_STORE",
    )
    assert registry["payload"]["accepted_group_count"] == 2
    assert registry["payload"]["accepted_repository_count"] == 1
    assert registry["payload"]["sufficiency"] == "MORE_NATURAL_DATA_REQUIRED"
