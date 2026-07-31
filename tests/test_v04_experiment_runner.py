# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from trace_eval.canonical import stable_id
from trace_eval.errors import PolicyError
from trace_eval.features import CANDIDATE_GENERATION_ALGORITHM
from trace_eval.trace001 import TrainingConfig

from scripts.run_v0_4_experiments import (
    _effective_quarantine,
    _gate_results,
    _python_network_denied,
    build_candidate_lock,
    build_final_entry_gates,
    build_training_execution_lock,
)


def test_v04_experiment_gate_results_apply_every_locked_threshold() -> None:
    aggregate = {
        "valid_attempt_completion": 1.0,
        "target_indexability": 0.95,
        "file_recall_at_5": 0.65,
        "file_recall_at_10": 0.75,
        "file_recall_at_20": 0.85,
        "location_role_correct_recall_at_20": 0.70,
        "mean_reciprocal_rank": 0.35,
        "no_relevant_candidate": 0.15,
        "hard_negative_outrank": 0.20,
        "wrong_location_role_top_one": 0.15,
        "repository_family_macro_recall_at_20": 0.80,
        "minimum_family_recall_at_20": 0.60,
        "zero_recall_family_count": 0,
        "false_supported_disposition": 0,
        "false_vulnerability_safe_control": 0,
        "unsafe_non_abstention": 0,
    }
    assert all(_gate_results(aggregate).values())
    aggregate["file_recall_at_20"] = 0.849
    assert _gate_results(aggregate)["file_recall_at_20"] is False


def test_v04_qualification_context_denies_python_network() -> None:
    import socket

    with _python_network_denied(), pytest.raises(PolicyError, match="QUALIFICATION_NETWORK_DENIED"):
        socket.socket()


def _algorithm(
    *,
    role: float,
    recall: float,
    family: float,
    mrr: float,
    passed: int,
) -> dict[str, object]:
    gate_names = [f"gate-{index}" for index in range(16)]
    return {
        "aggregate": {
            "location_role_correct_recall_at_20": role,
            "file_recall_at_5": recall,
            "file_recall_at_10": recall,
            "file_recall_at_20": recall,
            "repository_family_macro_recall_at_20": family,
            "minimum_family_recall_at_20": family,
            "zero_recall_family_count": 0,
            "mean_reciprocal_rank": mrr,
            "hard_negative_outrank": 0.1,
        },
        "gate_results": {name: index < passed for index, name in enumerate(gate_names)},
    }


def test_v04_candidate_lock_uses_development_only_and_predeclared_order() -> None:
    summary = {
        "schema_version": "lumi-trace-v0.4-private-baseline-summary-v1",
        "summary_id": "v0.4-baseline-summary:" + "a" * 64,
        "partition": "ENGINEERING_DEVELOPMENT",
        "group_count": 100,
        "family_count": 8,
        "maximum_candidates": 2_000,
        "candidate_generation_algorithm": CANDIDATE_GENERATION_ALGORITHM,
        "qualification_consumed": False,
        "holdback_opened": False,
        "algorithms": {
            "lexical": _algorithm(role=0.7, recall=0.9, family=0.8, mrr=0.4, passed=15),
            "sparse": _algorithm(role=0.8, recall=0.9, family=0.8, mrr=0.4, passed=15),
            "v0.1.2": _algorithm(role=0.9, recall=0.9, family=0.8, mrr=0.4, passed=14),
        },
    }
    candidate_lock = build_candidate_lock(
        summary,
        maximum_candidates=2_000,
        supersedes_candidate_lock_id="v0.4-candidate-lock:" + "0" * 64,
    )
    assert candidate_lock["selected_deterministic_comparator"] == "sparse"
    assert candidate_lock["qualification_state"] == "SEALED_UNOPENED"
    assert candidate_lock["protected_holdback_state"] == "SEALED_UNOPENED"
    assert candidate_lock["candidate_generation"]["labels_available_during_generation"] is False
    assert candidate_lock["candidate_generation"]["file_coverage_reserved_before_symbols"] is True
    assert (
        candidate_lock["candidate_generation"]["selection_policy"]
        == "QUERY_AWARE_IDF_FILE_SYMBOL_HYBRID"
    )
    assert (
        candidate_lock["candidate_generation"]["audited_target_quarantine_override"]
        == "TARGET_PATH_IDENTITY_ONLY"
    )
    assert candidate_lock["supersedes_candidate_lock_id"].endswith("0" * 64)

    summary["partition"] = "MODEL_SELECTION"
    with pytest.raises(PolicyError, match="DEVELOPMENT_SUMMARY_NOT_LOCKABLE"):
        build_candidate_lock(summary, maximum_candidates=2_000)


def test_v04_quarantine_override_is_limited_to_audited_target_paths() -> None:
    target = {"path": "pkg/parser.py", "symbol": "validate_input"}
    target_identity = stable_id("repository-path", target["path"])
    other_identity = stable_id("repository-path", "pkg/untrusted.py")
    effective, override_count = _effective_quarantine(
        {target_identity, other_identity},
        [target],
    )
    assert effective == {other_identity}
    assert override_count == 1


def test_v04_training_execution_lock_has_no_external_model_supply_chain() -> None:
    supply, execution = build_training_execution_lock(
        candidate_lock_id="v0.4-candidate-lock:" + "b" * 64,
        training_code_sha256="sha256:" + "c" * 64,
        feature_code_sha256="sha256:" + "d" * 64,
        dependency_lock_sha256="sha256:" + "e" * 64,
        config=TrainingConfig(
            maximum_candidates_per_group=2_000,
            maximum_pairs_per_group=256,
        ),
    )
    assert supply["model_origin"] == "FROM_SCRATCH_LINEAR"
    assert supply["foundation_model"] is None
    assert supply["tokenizer"] is None
    assert supply["external_weights"] == []
    assert supply["downloads_required"] is False
    assert execution["checkpoint_policy"]["public_weight_release_authorised"] is False
    assert execution["training_authority"] == "CONDITIONAL_ON_FINAL_SECTION_17_READINESS"


def test_v04_final_entry_gates_require_candidate_presence_and_ordering_gap() -> None:
    development = {
        "schema_version": "lumi-trace-v0.4-private-baseline-summary-v1",
        "summary_id": "v0.4-baseline-summary:" + "1" * 64,
        "partition": "ENGINEERING_DEVELOPMENT",
        "group_count": 100,
        "family_count": 8,
        "maximum_candidates": 2_000,
        "candidate_generation_algorithm": CANDIDATE_GENERATION_ALGORITHM,
        "qualification_consumed": False,
        "holdback_opened": False,
        "algorithms": {
            "lexical": _algorithm(role=0.5, recall=0.9, family=0.9, mrr=0.5, passed=15),
            "sparse": _algorithm(role=0.5, recall=0.9, family=0.9, mrr=0.5, passed=15),
            "v0.1.2": _algorithm(role=0.4, recall=0.8, family=0.8, mrr=0.4, passed=14),
            "random": _algorithm(role=0.0, recall=0.0, family=0.0, mrr=0.0, passed=3),
            "always_abstain": _algorithm(role=0.0, recall=0.0, family=0.0, mrr=0.0, passed=3),
        },
    }
    candidate_lock = build_candidate_lock(development, maximum_candidates=2_000)
    supply, execution = build_training_execution_lock(
        candidate_lock_id=candidate_lock["candidate_lock_id"],
        training_code_sha256="sha256:" + "2" * 64,
        feature_code_sha256="sha256:" + "3" * 64,
        dependency_lock_sha256="sha256:" + "4" * 64,
        config=TrainingConfig(maximum_candidates_per_group=2_000),
    )
    seal_id = "partition-seal:" + "5" * 64
    training_manifest = {
        "schema_version": "training-eligibility-manifest-v1",
        "record_id": "training-eligibility-manifest:" + "6" * 64,
        "payload": {
            "group_count": 500,
            "family_count": 25,
            "partition_seal_id": seal_id,
        },
    }
    partition_seal = {
        "schema_version": "partition-seal-v1",
        "record_id": seal_id,
        "payload": {
            "sealed_before_training": True,
            "holdback_state": "SEALED_UNOPENED",
            "assignments": [
                {
                    "audit_card_id": "card:1",
                    "group_id": "group:1",
                    "family_id": "family:1",
                    "partition": "TRAINING",
                },
                {
                    "audit_card_id": "card:2",
                    "group_id": "group:2",
                    "family_id": "family:2",
                    "partition": "QUALIFICATION",
                },
            ],
        },
    }
    training_summary = {
        "schema_version": "lumi-trace-v0.4-private-baseline-summary-v1",
        "summary_id": "v0.4-baseline-summary:" + "7" * 64,
        "partition": "TRAINING",
        "algorithms": {
            "sparse": {
                "aggregate": {
                    "target_indexability": 0.97,
                }
            }
        },
    }
    final = build_final_entry_gates(
        training_manifest=training_manifest,
        partition_seal=partition_seal,
        candidate_lock=candidate_lock,
        development_summary=development,
        training_summary=training_summary,
        supply_chain=supply,
        execution_lock=execution,
        item_audits_passed=True,
        training_rights_passed=True,
        controlled_labels_passed=True,
        poisoning_and_provenance_passed=True,
    )
    assert all(final["gates"].values())
    training_summary["algorithms"]["sparse"]["aggregate"]["target_indexability"] = 0.94
    blocked = build_final_entry_gates(
        training_manifest=training_manifest,
        partition_seal=partition_seal,
        candidate_lock=candidate_lock,
        development_summary=development,
        training_summary=training_summary,
        supply_chain=supply,
        execution_lock=execution,
        item_audits_passed=True,
        training_rights_passed=True,
        controlled_labels_passed=True,
        poisoning_and_provenance_passed=True,
    )
    assert blocked["gates"]["candidate_presence"] is False
    assert blocked["gates"]["ordering_gap"] is False
