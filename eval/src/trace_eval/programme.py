# SPDX-License-Identifier: Apache-2.0
"""V0.3 programme boundary, corpus sufficiency, and closure decisions."""

from __future__ import annotations

from typing import Any

from .code_metrics import PRIMARY_LABEL_STATES, validate_location_label
from .contracts import make_record, validate_record
from .errors import ContractError
from .policy import audit_repository_independence, verify_rights

NATURAL_TARGET_GROUPS = (50, 100)
NATURAL_TARGET_REPOSITORIES = (8, 12)


def programme_boundary() -> dict[str, Any]:
    """Return the hash-bound authority record for the approved V0.3 build."""
    return make_record(
        "programme-boundary-v1",
        {
            "version": "0.3",
            "authority": "USER_APPROVED_BUILD_BRIEF_2026-07-23",
            "permitted_activities": [
                "TRACE_CODE_NATURAL_EVALUATION",
                "TRACE_IR_INERT_FIXTURE_FEASIBILITY",
                "PUBLIC_SAFE_EVIDENCE_SEALING",
            ],
            "prohibited_sources": [
                "CUSTOMER_DATA",
                "CYBERGYM",
                "HISTORICAL_LUMI_EVIDENCE",
                "LUMI_SCOUT",
                "PROTECTED_HOLDBACK",
                "PUBLIC_TARGETS",
                "LIVE_TELEMETRY",
            ],
            "training_authorised": False,
            "weights_acquired": False,
            "holdback_state": "FROZEN_UNOPENED",
        },
    )


def assess_natural_corpus(
    *,
    repositories: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    split_manifest: dict[str, Any],
    private_evidence_location: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate admitted records and make an evidence-honest pilot sufficiency decision."""
    for repository in repositories:
        verify_rights(repository, mode="development")
    audit = audit_repository_independence(repositories, split_manifest)
    accepted_labels: list[dict[str, Any]] = []
    repository_ids = {repository["payload"]["repository_id"] for repository in repositories}
    family_by_repository = {
        repository["payload"]["repository_id"]: repository["payload"]["family_id"]
        for repository in repositories
    }
    for label in labels:
        validate_location_label(label)
        if label["payload"]["label_state"] in PRIMARY_LABEL_STATES:
            if label["payload"]["repository_id"] not in repository_ids:
                raise ContractError("accepted natural label has no admitted repository")
            accepted_labels.append(label)
    accepted_repository_families = {
        family_by_repository[label["payload"]["repository_id"]] for label in accepted_labels
    }
    group_count = len(accepted_labels)
    repository_count = len(accepted_repository_families)
    sufficient = (
        NATURAL_TARGET_GROUPS[0] <= group_count <= NATURAL_TARGET_GROUPS[1]
        and NATURAL_TARGET_REPOSITORIES[0] <= repository_count <= NATURAL_TARGET_REPOSITORIES[1]
    )
    sufficiency = (
        "PILOT_TARGET_MET"
        if sufficient
        else "MORE_NATURAL_DATA_REQUIRED"
        if group_count or repository_count
        else "DATA_GATES_PENDING"
    )
    registry = make_record(
        "natural-corpus-registry-v1",
        {
            "repositories": [repository["record_id"] for repository in repositories],
            "groups": [label["record_id"] for label in labels],
            "accepted_group_count": group_count,
            "accepted_repository_count": repository_count,
            "sufficiency": sufficiency,
            "private_evidence_location": private_evidence_location,
        },
    )
    split_payload = split_manifest["payload"]
    lineage = make_record(
        "repository-lineage-audit-v1",
        {
            "repository_count": audit["repository_count"],
            "partitions": {
                key: len(value) for key, value in sorted(split_payload["partitions"].items())
            },
            "cross_partition_overlap_count": len(audit["violations"]),
            "methods": [
                "TREE_ID",
                "LINEAGE_ID",
                "FAMILY_ID",
                "SHARED_HISTORY_ROOT",
                "CONTENT_FINGERPRINT_JACCARD",
            ],
            "holdback_opened": False,
        },
    )
    return registry, lineage


def v03_readiness(
    *,
    natural_registry: dict[str, Any],
    lineage_audit: dict[str, Any],
    ir_decision: dict[str, Any],
    environment_evidence_ids: list[str],
) -> dict[str, Any]:
    """Evaluate every V0.3 training gate without authorising training."""
    for record in (natural_registry, lineage_audit, ir_decision):
        validate_record(record)
    natural = natural_registry["payload"]
    pilot_met = natural["sufficiency"] == "PILOT_TARGET_MET"
    groups = natural["accepted_group_count"]
    repositories = natural["accepted_repository_count"]

    def gate(name: str, met: bool, evidence: list[str], detail: str) -> dict[str, Any]:
        return {
            "gate": name,
            "status": "MET" if met else "UNMET / EVIDENCE_REQUIRED",
            "evidence": evidence,
            "detail": detail,
        }

    gates = [
        gate(
            "v0_2_environment_and_v0_1_runtime_verified",
            bool(environment_evidence_ids),
            environment_evidence_ids,
            "The sealed V0.2 evaluator evidence and exact V0.1 wheel were verified.",
        ),
        gate(
            "v0_3_natural_pilot_scale",
            pilot_met,
            [natural_registry["record_id"]],
            f"Accepted natural pilot: {groups} groups across {repositories} repositories.",
        ),
        gate(
            "repository_disjoint_governed_partitions",
            lineage_audit["payload"]["cross_partition_overlap_count"] == 0 and repositories > 0,
            [lineage_audit["record_id"]],
            (
                "No cross-partition overlap was detected."
                if repositories
                else "No natural repositories were admitted, so disjoint partitions "
                "cannot establish data readiness."
            ),
        ),
        gate(
            "500_useful_labelled_groups",
            groups >= 500,
            [natural_registry["record_id"]],
            f"Required at least 500 useful groups; observed {groups}.",
        ),
        gate(
            "25_unrelated_training_repositories",
            repositories >= 25,
            [natural_registry["record_id"]],
            f"Required at least 25 unrelated repositories; observed {repositories}.",
        ),
        gate(
            "meaningful_hard_negatives_and_safe_controls",
            False,
            [natural_registry["record_id"]],
            "Natural controlled-reviewed labels are required at scale.",
        ),
        gate(
            "audited_location_and_reproduction_labels",
            False,
            [natural_registry["record_id"]],
            "No governed natural label set reached the training-readiness scale.",
        ),
        gate(
            "approved_performance_threshold",
            False,
            [],
            "Performance thresholds were declined because development evidence is absent.",
        ),
        gate(
            "foundation_model_and_weight_licence",
            False,
            [],
            "No model or weights were selected or acquired under V0.3 authority.",
        ),
        gate(
            "separate_trace_001_authority",
            False,
            [],
            "No separate TRACE-001 authority record exists.",
        ),
    ]
    return make_record(
        "training-readiness-decision-v1",
        {
            "recommendation": "DO_NOT_BEGIN_TRACE_001",
            "closure_state": (
                "NATURAL_PILOT_QUALIFIED / SCALE_CORPUS" if pilot_met else "DATA_GATES_PENDING"
            ),
            "gates": gates,
            "training_started": False,
            "weights_downloaded": False,
        },
    )


def close_v03(
    *,
    natural_registry: dict[str, Any],
    ir_decision: dict[str, Any],
    evidence_ids: list[str],
) -> dict[str, Any]:
    """Issue the V0.3 stop-gated programme and lane states."""
    validate_record(natural_registry)
    validate_record(ir_decision)
    natural = natural_registry["payload"]
    programme_state = (
        "NATURAL_PILOT_QUALIFIED / SCALE_CORPUS"
        if natural["sufficiency"] == "PILOT_TARGET_MET"
        else "DATA_GATES_PENDING"
    )
    return make_record(
        "v0.3-closure-v1",
        {
            "programme_state": programme_state,
            "ir_lane_state": ir_decision["payload"]["lane_state"],
            "natural_corpus": {
                "accepted_groups": natural["accepted_group_count"],
                "accepted_repositories": natural["accepted_repository_count"],
                "sufficiency": natural["sufficiency"],
            },
            "threshold_decision": "DECLINED / INSUFFICIENT_DEVELOPMENT_EVIDENCE",
            "qualification_run": False,
            "holdback_opened": False,
            "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
            "training_started": False,
            "weights_acquired": False,
            "publication_decision": "NO_GO_PENDING_USER_REVIEW",
            "evidence_ids": evidence_ids,
        },
    )
