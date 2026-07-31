# SPDX-License-Identifier: Apache-2.0
"""Evidence-honest V0.2 closure and training-readiness decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import dump_json, load_json
from .contracts import make_record, validate_record
from .errors import ContractError
from .metrics import verify_scored_package
from .package import seal_package, verify_package
from .registry import load_registry, records_by_schema
from .runner import load_run_package

CLOSURE_STATE = "ENVIRONMENT_QUALIFIED / DATA_GATES_PENDING"


def _gate(name: str, status: str, evidence: list[str], detail: str) -> dict[str, Any]:
    if status not in {"MET", "FAILED", "UNMET / EVIDENCE_REQUIRED"}:
        raise ContractError("training-readiness gate status is invalid")
    return {"gate": name, "status": status, "evidence": evidence, "detail": detail}


def evaluate_readiness(
    *,
    environment_record_path: Path,
    registry_path: Path,
    run_package: Path,
    scored_package: Path,
    replay_package: Path,
    output: Path,
) -> dict[str, Any]:
    if output.exists():
        raise ContractError("readiness output already exists")
    environment = load_json(environment_record_path)
    if not isinstance(environment, dict):
        raise ContractError("environment qualification must be an object")
    validate_record(environment)
    registry = load_registry(registry_path)
    run_record, _, run_manifest = load_run_package(run_package)
    scored_manifest = verify_scored_package(scored_package)
    replay_manifest = verify_package(replay_package)
    replay = load_json(replay_package / "replay-verification.json")
    aggregate = load_json(scored_package / "aggregate-metrics.json")
    if not isinstance(replay, dict) or not isinstance(aggregate, dict):
        raise ContractError("replay and aggregate records must be objects")
    validate_record(replay)
    validate_record(aggregate)
    repositories = records_by_schema(registry, "repository-rights-manifest-v1")
    groups = records_by_schema(registry, "candidate-ranking-group-v1")
    public_groups = [item for item in groups if item["payload"]["split"] == "public_regression"]
    false_confirmations = aggregate["payload"]["micro"]["false_confirmations"]["count"]
    gates = [
        _gate(
            "trace_eval_environment_isolated",
            "MET",
            [environment["record_id"]],
            "Dedicated Python 3.11 Trace-Eval roots and dependency lock qualified.",
        ),
        _gate(
            "exact_v0_1_runtime_verified",
            "MET",
            [environment["record_id"], run_record["record_id"]],
            "Released V0.1 wheel is verified by hash and CLI identity.",
        ),
        _gate(
            "retained_evidence_verifies",
            "MET",
            [
                run_manifest["package_id"],
                scored_manifest["package_id"],
                replay_manifest["package_id"],
            ],
            "All retained public-fixture packages verify by exact manifest.",
        ),
        _gate(
            "same_host_determinism",
            "MET" if replay["payload"]["identity_agreement"] else "FAILED",
            [replay["record_id"]],
            "Public-fixture replay identity comparison.",
        ),
        _gate(
            "zero_false_confirmations_in_audited_controls",
            "MET" if false_confirmations == 0 else "FAILED",
            [aggregate["record_id"]],
            f"Observed false confirmations: {false_confirmations}.",
        ),
        _gate(
            "500_useful_labelled_groups",
            "UNMET / EVIDENCE_REQUIRED",
            [registry["registry_id"]],
            (
                f"Only {len(public_groups)} public synthetic groups are present; "
                "they do not count as governed natural training candidates."
            ),
        ),
        _gate(
            "25_unrelated_training_repositories",
            "UNMET / EVIDENCE_REQUIRED",
            [registry["registry_id"]],
            f"Only {len(repositories)} public synthetic repositories are present.",
        ),
        _gate(
            "repository_disjoint_governed_partitions",
            "UNMET / EVIDENCE_REQUIRED",
            [registry["registry_id"]],
            "Development, qualification, and frozen-holdback corpora were not supplied or opened.",
        ),
        _gate(
            "meaningful_natural_hard_negatives",
            "UNMET / EVIDENCE_REQUIRED",
            [registry["registry_id"]],
            "Synthetic controls cannot establish natural hard-negative sufficiency.",
        ),
        _gate(
            "audited_location_and_reproduction_labels",
            "UNMET / EVIDENCE_REQUIRED",
            [registry["registry_id"]],
            "Public synthetic controlled-review receipts do not establish governed corpus scale.",
        ),
        _gate(
            "approved_ranking_threshold",
            "UNMET / EVIDENCE_REQUIRED",
            [aggregate["record_id"]],
            "No ranking threshold may be approved from one public fixture repository.",
        ),
        _gate(
            "foundation_model_and_weight_licence",
            "UNMET / EVIDENCE_REQUIRED",
            [],
            (
                "No foundation model or weight licence was selected; selection is "
                "outside V0.2 authority."
            ),
        ),
        _gate(
            "separate_trace_001_authority",
            "UNMET / EVIDENCE_REQUIRED",
            [],
            "No separate training authority record exists.",
        ),
    ]
    qualification = make_record(
        "qualification-decision-v1",
        {
            "closure_state": CLOSURE_STATE,
            "runtime_id": run_record["payload"]["runtime_id"],
            "evaluator_id": environment["record_id"],
            "evidence_ids": [
                run_manifest["package_id"],
                scored_manifest["package_id"],
                replay_manifest["package_id"],
            ],
            "threshold_decision": "DECLINED / INSUFFICIENT_DEVELOPMENT_EVIDENCE",
            "holdback_opened": False,
        },
    )
    readiness = make_record(
        "training-readiness-decision-v1",
        {
            "recommendation": "DO_NOT_BEGIN_TRACE_001",
            "closure_state": CLOSURE_STATE,
            "gates": gates,
            "training_started": False,
            "weights_downloaded": False,
        },
    )
    output.mkdir(parents=True)
    dump_json(output / "qualification-decision.json", qualification)
    dump_json(output / "training-readiness-decision.json", readiness)
    manifest = seal_package(output)
    return {"qualification": qualification, "readiness": readiness, "manifest": manifest}
