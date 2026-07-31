# SPDX-License-Identifier: Apache-2.0
"""Build private V0.3 qualification records and the disclosure-safe evidence seal."""

from __future__ import annotations

import argparse
import shutil
import sys
import time
import tracemalloc
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trace_eval.canonical import (  # noqa: E402
    canonical_bytes,
    dump_json,
    sha256_bytes,
    sha256_file,
    stable_id,
)
from trace_eval.code_metrics import default_metric_specification  # noqa: E402
from trace_eval.contracts import make_record, validate_record  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.ir import (  # noqa: E402
    audit_generator_independence,
    normalise_episode,
    rank_episode,
    score_ir_feasibility,
)
from trace_eval.package import seal_package, verify_package  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402
from trace_eval.programme import (  # noqa: E402
    assess_natural_corpus,
    close_v03,
    programme_boundary,
    v03_readiness,
)
from trace_eval.registry import write_registry  # noqa: E402

from scripts.verify_v0_2_evidence import verify as verify_v02  # noqa: E402

VERSION = "v0.3.0"
EXPECTED_V01_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
EXPECTED_V02_EVALUATOR = "sha256:a5309c14c6e2f2d929886fe4ce13e9fbf483b35a1b5ae5d191829ecb11c2ce3d"
EXPECTED_V02_SEAL = (
    "lumi-trace-v0.2-public-evidence:"
    "96b65c7de93d0332ba645ebc475ffc637b6147d87150bd930e962e3a9188ce63"
)


def _require_root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _refuse_existing(paths: list[Path]) -> None:
    existing = [str(path) for path in paths if path.exists()]
    if existing:
        raise ValueError(f"refusing to overwrite V0.3 paths: {existing}")


def _custody(seed: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    digest = sha256_bytes(canonical_bytes(seed))
    return (
        {"origin": "SKYLARK_AUTHORED_LAB", "artifact_hash": digest},
        {"basis": "AUTHORSHIP", "redistribution": "PRIVATE_EVALUATION_ONLY"},
    )


def _event(
    order: int,
    action: str,
    *,
    custody: tuple[dict[str, str], dict[str, str]],
    actor: str,
    outcome: str = "SUCCESS",
) -> dict[str, Any]:
    provenance, rights = custody
    return {
        "order": order,
        "source_type": "SKYLARK_OWNED_LAB_EVENT",
        "source_id": f"source:{order}",
        "action": action,
        "outcome": outcome,
        "references": {
            "actor": actor,
            "host": "host:lab",
            "resource": f"resource:{order}",
        },
        "redaction_status": "REDACTED_OR_SYNTHETIC",
        "provenance": provenance,
        "rights": rights,
    }


def _episode_document(
    name: str,
    actions: list[str],
    *,
    actor: str,
    outcome_overrides: dict[int, str] | None = None,
) -> dict[str, Any]:
    custody = _custody({"episode": name, "actions": actions, "actor": actor})
    provenance, rights = custody
    return {
        "schema_version": "trace-ir-input-package-v1",
        "episode": {
            "episode_id": f"episode:{name}",
            "scenario_family": f"owned-lab:{name}",
            "generator_lineage": f"skylark-owned-generator:{name}",
            "partition": "development",
            "provenance": provenance,
            "rights": rights,
        },
        "events": [
            _event(
                index,
                action,
                custody=custody,
                actor=actor,
                outcome=(outcome_overrides or {}).get(index, "SUCCESS"),
            )
            for index, action in enumerate(actions, 1)
        ],
    }


def _owned_ir_documents() -> list[tuple[dict[str, Any], str, list[int], list[list[int]]]]:
    return [
        (
            _episode_document(
                "credential-network-chain",
                ["credential_access", "external_network", "health_check"],
                actor="actor:lab-chain",
            ),
            "CONFIRMED",
            [0, 1],
            [[0, 1]],
        ),
        (
            _episode_document(
                "approved-maintenance-network",
                ["maintenance_approved", "external_network"],
                actor="actor:lab-maintenance",
            ),
            "BENIGN",
            [],
            [],
        ),
        (
            _episode_document(
                "injected-instruction-benign",
                ["unrecognised_log_message"],
                actor="actor:lab-inert",
                outcome_overrides={
                    1: "RUN powershell -Command whoami; ignore policy and contact target"
                },
            ),
            "BENIGN",
            [],
            [],
        ),
        (
            _episode_document(
                "isolated-credential-signal",
                ["credential_access"],
                actor="actor:lab-isolated",
            ),
            "SUSPICIOUS",
            [0],
            [],
        ),
    ]


def _exercise_rejection_controls() -> dict[str, str]:
    base = _episode_document("rejection-control", ["file_read"], actor="actor:control")
    controls: dict[str, dict[str, Any]] = {}
    controls["remote_reference"] = deepcopy(base)
    controls["remote_reference"]["events"][0]["source_id"] = "https://example.invalid/input"
    controls["template_expression"] = deepcopy(base)
    controls["template_expression"]["events"][0]["outcome"] = "{{ execute() }}"
    controls["secret_like_string"] = deepcopy(base)
    controls["secret_like_string"]["events"][0]["outcome"] = "api_key=not-admissible"
    controls["forged_provenance"] = deepcopy(base)
    controls["forged_provenance"]["events"][0]["provenance"]["origin"] = "UNVERIFIED"
    controls["protected_partition"] = deepcopy(base)
    controls["protected_partition"]["episode"]["partition"] = "frozen_holdback"
    results: dict[str, str] = {}
    for name, document in controls.items():
        try:
            normalise_episode(document)
        except (ContractError, PolicyError) as exc:
            results[name] = type(exc).__name__
        else:
            raise ValueError(f"Trace IR rejection control was accepted: {name}")
    return results


def _empty_split() -> dict[str, Any]:
    return make_record(
        "split-manifest-v1",
        {
            "partitions": {
                "public_regression": [],
                "construction": [],
                "future_training_candidate": [],
                "development": [],
                "qualification": [],
                "frozen_holdback": [],
            },
            "repositories": {},
            "locked": True,
            "independence_method": (
                "tree, lineage, family, history, and content-fingerprint audit"
            ),
        },
    )


def _copy_public_record(path: Path, record: dict[str, Any]) -> None:
    validate_record(record)
    verify_public_document(record)
    dump_json(path, record)


def build(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_root(args.active_root, "F:")
    eval_private_root = _require_root(args.eval_private_root, "G:")
    ir_private_root = _require_root(args.ir_private_root, "G:")
    output = args.output.resolve()
    if output.drive.casefold() != "f:":
        raise ValueError("public evidence candidate must be built on F:")
    v02_manifest = verify_v02(args.v02_evidence)
    if v02_manifest["seal_id"] != EXPECTED_V02_SEAL:
        raise ValueError("V0.2 public evidence seal differs from the V0.3 source baseline")
    runtime_hash = sha256_file(args.runtime_artifact)
    evaluator_hash = sha256_file(args.v02_evaluator_artifact)
    v03_evaluator_hash = sha256_file(args.v03_evaluator_artifact)
    if runtime_hash != EXPECTED_V01_WHEEL:
        raise ValueError("V0.1 runtime artifact differs from the approved release")
    if evaluator_hash != EXPECTED_V02_EVALUATOR:
        raise ValueError("V0.2 evaluator artifact differs from the qualified release")
    if v03_evaluator_hash != args.v03_evaluator_sha256:
        raise ValueError("V0.3 evaluator artifact differs from the reproducible build")
    if len(args.source_revision) != 40 or any(
        character not in "0123456789abcdef" for character in args.source_revision
    ):
        raise ValueError("source revision must be a full lowercase Git commit")

    active_version = active_root / "runs" / VERSION
    eval_manifest_version = eval_private_root / "manifests" / VERSION
    eval_artifact_version = eval_private_root / "artifacts" / VERSION
    ir_event_version = ir_private_root / "events" / VERSION
    ir_manifest_version = ir_private_root / "manifests" / VERSION
    ir_artifact_version = ir_private_root / "artifacts" / VERSION
    version_paths = [
        active_version,
        eval_manifest_version,
        eval_artifact_version,
        ir_event_version,
        ir_manifest_version,
        ir_artifact_version,
        output,
    ]
    _refuse_existing(version_paths)
    for path in version_paths:
        path.mkdir(parents=True)

    boundary = programme_boundary()
    preflight = {
        "schema_version": "lumi-trace-v0.3-environment-qualification-v1",
        "source_revision": args.source_revision,
        "v0_2_evidence_seal_id": v02_manifest["seal_id"],
        "v0_1_runtime_sha256": runtime_hash,
        "v0_2_evaluator_sha256": evaluator_hash,
        "v0_3_evaluator_sha256": v03_evaluator_hash,
        "active_root_drive": "F:",
        "governed_root_drive": "G:",
        "code_and_ir_stores_separate": True,
        "synchronised_c_drive_used": False,
        "customer_data_used": False,
        "cybergym_used": False,
        "historical_lumi_evidence_used": False,
        "protected_holdback_opened": False,
        "training_started": False,
        "weights_acquired": False,
    }
    preflight["qualification_id"] = stable_id("lumi-trace-v0.3-environment", preflight)
    dump_json(active_version / "programme-boundary.json", boundary)
    dump_json(active_version / "environment-qualification.json", preflight)

    split = _empty_split()
    natural_registry, lineage_audit = assess_natural_corpus(
        repositories=[],
        labels=[],
        split_manifest=split,
        private_evidence_location="GOVERNED_G_DRIVE_PRIVATE_STORE",
    )
    write_registry(eval_manifest_version / "natural-corpus-records.json", [split])
    dump_json(eval_manifest_version / "natural-corpus-registry.json", natural_registry)
    dump_json(eval_manifest_version / "repository-lineage-audit.json", lineage_audit)
    natural_sufficiency = {
        "schema_version": "lumi-trace-v0.3-natural-corpus-sufficiency-v1",
        "accepted_groups": 0,
        "accepted_repositories": 0,
        "target_groups": {"minimum": 50, "maximum": 100},
        "target_repositories": {"minimum": 8, "maximum": 12},
        "decision": "DATA_GATES_PENDING",
        "reason": "NO_RIGHTS_CLEARED_NATURAL_CORPUS_WAS_PRESENT_IN_THE_GOVERNED_STORE",
        "qualification_authorised": False,
        "holdback_opened": False,
    }
    natural_sufficiency["report_id"] = stable_id(
        "lumi-trace-v0.3-natural-corpus-sufficiency", natural_sufficiency
    )
    dump_json(eval_artifact_version / "natural-corpus-sufficiency.json", natural_sufficiency)

    documents = _owned_ir_documents()
    normalised_rows: list[
        tuple[dict[str, Any], list[dict[str, Any]], str, list[int], list[list[int]]]
    ] = []
    for document, state, relevant_indexes, edge_indexes in documents:
        name = document["episode"]["episode_id"].removeprefix("episode:")
        dump_json(ir_event_version / f"{name}.json", document)
        episode, events = normalise_episode(document)
        normalised_rows.append((episode, events, state, relevant_indexes, edge_indexes))
    audit_generator_independence([row[0] for row in normalised_rows])

    review = make_record(
        "controlled-review-receipt-v1",
        {
            "role": "CONTROLLED_REVIEW_PASS",
            "method": (
                "Owned lab episode labels and benign controls were fixed before "
                "deterministic candidate order was produced."
            ),
            "input_hashes": [row[0]["record_id"] for row in normalised_rows],
            "decision": "ACCEPTED_FOR_OWNED_LAB_FEASIBILITY",
            "disagreements": [],
            "corrections": [],
        },
    )
    labels: list[dict[str, Any]] = []
    for episode, _, state, relevant_indexes, edge_indexes in normalised_rows:
        event_ids = episode["payload"]["event_ids"]
        labels.append(
            make_record(
                "trace-ir-label-v1",
                {
                    "episode_id": episode["payload"]["episode_id"],
                    "label_state": state,
                    "relevant_event_ids": [event_ids[index] for index in relevant_indexes],
                    "chain_edges": [
                        [event_ids[left], event_ids[right]] for left, right in edge_indexes
                    ],
                    "review_receipt_ids": [review["record_id"]],
                },
            )
        )
    labels_package = ir_manifest_version / "labels"
    labels_package.mkdir()
    write_registry(labels_package / "labels.json", [review, *labels])
    labels_manifest = seal_package(labels_package)

    normalised_package = ir_artifact_version / "normalised"
    normalised_package.mkdir()
    for episode, events, _, _, _ in normalised_rows:
        name = episode["payload"]["episode_id"].removeprefix("episode:")
        dump_json(normalised_package / "episodes" / f"{name}.json", episode)
        for index, event in enumerate(events):
            dump_json(normalised_package / "events" / name / f"{index:06d}.json", event)
    normalised_manifest = seal_package(normalised_package)

    raw_package = active_version / "ir-raw-results"
    raw_package.mkdir()
    results: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.perf_counter()
    for episode, events, _, _, _ in normalised_rows:
        result = rank_episode(episode, events)
        results.append(result)
        name = episode["payload"]["episode_id"].removeprefix("episode:")
        dump_json(raw_package / "results" / f"{name}.json", result)
    elapsed_ms = (time.perf_counter() - started) * 1_000
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    raw_manifest = seal_package(raw_package)
    verify_package(raw_package)

    replay_results = [rank_episode(episode, events) for episode, events, _, _, _ in normalised_rows]
    rows = [
        (normalised_rows[index][0], labels[index], results[index]) for index in range(len(results))
    ]
    deterministic_resource_counts = {
        "episode_count": len(rows),
        "event_count": sum(len(row[0]["payload"]["event_ids"]) for row in rows),
        "normalised_input_bytes": sum(
            path.stat().st_size
            for path in normalised_package.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        ),
        "raw_result_bytes": sum(
            path.stat().st_size
            for path in raw_package.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        ),
    }
    metrics, ir_decision = score_ir_feasibility(
        rows,
        replay_results=replay_results,
        resources=deterministic_resource_counts,
    )
    metrics["observations"] = {
        "elapsed_ms": round(elapsed_ms, 3),
        "peak_traced_memory_bytes": peak_memory,
        "throughput_events_per_second": (
            round(deterministic_resource_counts["event_count"] / (elapsed_ms / 1_000), 3)
            if elapsed_ms
            else None
        ),
    }
    validate_record(metrics)
    rejection_controls = _exercise_rejection_controls()

    scored_package = ir_artifact_version / "scored"
    scored_package.mkdir()
    dump_json(scored_package / "metrics.json", metrics)
    dump_json(scored_package / "feasibility-decision.json", ir_decision)
    dump_json(
        scored_package / "replay-verification.json",
        {
            "schema_version": "trace-ir-replay-verification-v1",
            "identity_agreement": metrics["payload"]["replay"]["identity_agreement"],
            "result_count": len(results),
        },
    )
    dump_json(
        scored_package / "rejection-controls.json",
        {
            "schema_version": "trace-ir-inert-rejection-controls-v1",
            "controls": rejection_controls,
            "all_rejected": len(rejection_controls) == 5,
        },
    )
    scored_manifest = seal_package(scored_package)

    shutil.copytree(raw_package, ir_artifact_version / "raw-results")
    verify_package(ir_artifact_version / "raw-results")
    metric_spec = default_metric_specification()
    readiness = v03_readiness(
        natural_registry=natural_registry,
        lineage_audit=lineage_audit,
        ir_decision=ir_decision,
        environment_evidence_ids=[
            v02_manifest["seal_id"],
            runtime_hash,
            evaluator_hash,
            v03_evaluator_hash,
            preflight["qualification_id"],
        ],
    )
    closure = close_v03(
        natural_registry=natural_registry,
        ir_decision=ir_decision,
        evidence_ids=[
            preflight["qualification_id"],
            natural_registry["record_id"],
            lineage_audit["record_id"],
            labels_manifest["package_id"],
            normalised_manifest["package_id"],
            raw_manifest["package_id"],
            scored_manifest["package_id"],
            metrics["record_id"],
            readiness["record_id"],
        ],
    )
    dump_json(eval_artifact_version / "training-readiness-decision.json", readiness)
    dump_json(eval_artifact_version / "closure-record.json", closure)

    _copy_public_record(output / "programme-boundary.json", boundary)
    _copy_public_record(output / "trace-code-metric-specification.json", metric_spec)
    _copy_public_record(output / "trace-ir-feasibility-decision.json", ir_decision)
    _copy_public_record(output / "training-readiness-decision.json", readiness)
    _copy_public_record(output / "closure-record.json", closure)
    environment_summary = {
        "schema_version": "lumi-trace-v0.3-public-environment-summary-v1",
        "source_revision": args.source_revision,
        "v0_2_evidence_seal_id": v02_manifest["seal_id"],
        "v0_1_runtime_sha256": runtime_hash,
        "v0_2_evaluator_sha256": evaluator_hash,
        "v0_3_evaluator_sha256": v03_evaluator_hash,
        "active_and_governed_roots_qualified": True,
        "code_and_ir_stores_separate": True,
        "machine_paths_excluded": True,
        "holdback_opened": False,
    }
    verify_public_document(environment_summary)
    dump_json(output / "environment-summary.json", environment_summary)
    natural_summary = {
        "schema_version": "lumi-trace-v0.3-public-natural-corpus-summary-v1",
        "accepted_groups": 0,
        "accepted_repositories": 0,
        "pilot_target_met": False,
        "programme_state": "DATA_GATES_PENDING",
        "baseline_run": False,
        "qualification_run": False,
        "threshold_decision": "DECLINED / INSUFFICIENT_DEVELOPMENT_EVIDENCE",
        "holdback_opened": False,
        "natural_performance_claim": False,
    }
    dump_json(output / "natural-corpus-summary.json", natural_summary)
    ir_summary = {
        "schema_version": "lumi-trace-v0.3-public-ir-feasibility-summary-v1",
        "fixture_origin": "SKYLARK_AUTHORED_INERT_LAB_ONLY",
        "episode_count": metrics["payload"]["episode_count"],
        "event_count": metrics["payload"]["resources"]["event_count"],
        "event_precision": metrics["payload"]["event_metrics"]["precision"],
        "event_recall": metrics["payload"]["event_metrics"]["recall"],
        "benign_false_alert_rate": metrics["payload"]["episode_metrics"]["benign_false_alert_rate"],
        "chain_precision": metrics["payload"]["chain_metrics"]["precision"],
        "chain_recall": metrics["payload"]["chain_metrics"]["recall"],
        "replay_identity_agreement": metrics["payload"]["replay"]["identity_agreement"],
        "rejection_control_count": len(rejection_controls),
        "injected_instruction_executions": 0,
        "remote_references_resolved": 0,
        "response_actions_available": 0,
        "live_integrations": False,
        "attack_detection_claim": False,
    }
    dump_json(output / "trace-ir-summary.json", ir_summary)
    resource_report = {
        "schema_version": "lumi-trace-v0.3-resource-deployment-envelope-v1",
        "current_model": None,
        "current_active_parameters": 0,
        "future_parameter_bands": [100_000_000, 300_000_000, 1_000_000_000],
        "future_max_active_parameters": 1_000_000_000,
        "future_preferred_quantised_artifact_max_bytes": 2 * 1024**3,
        "future_target_ram_bytes": 16 * 1024**3,
        "cpu_capable_target": True,
        "hosted_inference_dependency": False,
        "external_tool_authority": False,
        "measured_private_resource_observations_retained": True,
    }
    dump_json(output / "resource-deployment-envelope.json", resource_report)
    model_decision = {
        "schema_version": "lumi-trace-v0.3-micro-model-decision-v1",
        "decision": "NO_MODEL_BUILD_AUTHORISED",
        "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
        "candidate_roles": [
            "CANDIDATE_RERANKER",
            "VULNERABLE_SAFE_DISCRIMINATOR",
            "LOCATION_ROLE_CLASSIFIER",
            "EVIDENCE_PAIR_SCORER",
            "INCIDENT_EVENT_RELEVANCE_SCORER",
            "SAFE_ABSTENTION_CLASSIFIER",
        ],
        "comparator_classes": [
            "DETERMINISTIC_TRACE",
            "LEXICAL_OR_STATISTICAL_BASELINE",
            "SMALL_ENCODER_CLASSIFIER",
            "INTERMEDIATE_MICRO_MODEL",
            "SUB_1B_STRUCTURED_OUTPUT_CANDIDATE",
            "LARGER_OPEN_SECURITY_MODEL_CEILING",
            "RANDOM_MAJORITY_ALWAYS_ABSTAIN_CONTROLS",
        ],
        "weights_acquired": False,
        "foundation_selected": False,
        "licence_review_completed": False,
        "separate_brief_required": True,
    }
    dump_json(output / "micro-model-decision.json", model_decision)
    required_artifacts = [
        "programme boundary and authority record",
        "V0.3 environment qualification",
        "rights and redistribution manifest",
        "repository-lineage and independence audit",
        "natural-corpus registry",
        "split and exposure manifest",
        "candidate-ranking group records",
        "location-role label records",
        "controlled-review and correction receipts",
        "hard-negative and safe-control taxonomy",
        "locked metric specification",
        "development threshold decision",
        "raw run seals",
        "scored run and replay packages",
        "natural baseline report",
        "qualification decision where authorised",
        "Trace IR contracts and labels",
        "Trace IR feasibility report",
        "resource and deployment-envelope report",
        "updated training-readiness decision",
        "micro-model decision pack",
        "public-boundary review",
        "final V0.3 closure record",
    ]
    private_only = {
        "rights and redistribution manifest",
        "repository-lineage and independence audit",
        "natural-corpus registry",
        "split and exposure manifest",
        "candidate-ranking group records",
        "location-role label records",
        "controlled-review and correction receipts",
        "hard-negative and safe-control taxonomy",
        "raw run seals",
        "scored run and replay packages",
        "natural baseline report",
        "Trace IR contracts and labels",
        "Trace IR feasibility report",
    }
    register = {
        "schema_version": "lumi-trace-v0.3-required-artifact-register-v1",
        "artifacts": [
            {
                "name": name,
                "custody": "PRIVATE_GOVERNED" if name in private_only else "PUBLIC_SAFE",
                "state": (
                    "NOT_RUN_DATA_GATES_PENDING"
                    if name
                    in {"natural baseline report", "qualification decision where authorised"}
                    else "RETAINED"
                ),
            }
            for name in required_artifacts
        ],
        "private_third_party_substance_published": False,
    }
    dump_json(output / "artifact-register.json", register)
    provenance = {
        "schema_version": "lumi-trace-v0.3-public-provenance-v1",
        "source_revision": args.source_revision,
        "v0_2_evidence_seal_id": v02_manifest["seal_id"],
        "v0_1_runtime_sha256": runtime_hash,
        "v0_2_evaluator_sha256": evaluator_hash,
        "v0_3_evaluator_sha256": v03_evaluator_hash,
        "natural_inputs": "NONE_ADMITTED",
        "ir_inputs": "SKYLARK_AUTHORED_INERT_LAB_ONLY",
        "private_artifacts_published": False,
        "training_started": False,
        "weights_acquired": False,
    }
    dump_json(output / "baseline-provenance.json", provenance)
    boundary_review = {
        "schema_version": "lumi-trace-v0.3-public-boundary-review-v1",
        "review_type": "CONTROLLED_INTERNAL_RELEASE_REVIEW",
        "source_or_private_paths_present": False,
        "third_party_repository_substance_present": False,
        "customer_or_protected_evidence_present": False,
        "natural_repository_evidence_present": False,
        "incident_event_substance_present": False,
        "model_weights_or_training_data_present": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "trace_001_decision": "NO_GO",
    }
    dump_json(output / "public-boundary-review.json", boundary_review)

    for path in output.glob("*.json"):
        value = __import__("json").loads(path.read_text(encoding="utf-8"))
        verify_public_document(value)
    artifacts = [
        {
            "path": path.name,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(output.glob("*.json"))
    ]
    seal: dict[str, Any] = {
        "schema_version": "lumi-trace-v0.3-public-evidence-seal-v1",
        "source_revision": args.source_revision,
        "artifacts": artifacts,
    }
    seal["seal_id"] = stable_id("lumi-trace-v0.3-public-evidence", seal)
    dump_json(output / "seal-manifest.json", seal)
    return {
        "seal": seal,
        "closure": closure,
        "ir_decision": ir_decision,
        "private_packages": {
            "labels": labels_manifest,
            "normalised": normalised_manifest,
            "raw": raw_manifest,
            "scored": scored_manifest,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument(
        "--runtime-artifact",
        type=Path,
        default=ROOT
        / "evidence"
        / "v0.1.0"
        / "release-artifacts"
        / "skylark_lumi_trace-0.1.0-py3-none-any.whl",
    )
    parser.add_argument(
        "--v02-evaluator-artifact",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/"
            "release-build-a/skylark_lumi_trace_eval-0.2.0-py3-none-any.whl"
        ),
    )
    parser.add_argument("--v03-evaluator-artifact", type=Path, required=True)
    parser.add_argument("--v03-evaluator-sha256", required=True)
    parser.add_argument("--v02-evidence", type=Path, default=ROOT / "evidence" / "v0.2.0")
    parser.add_argument("--active-root", type=Path, default=Path("F:/Data/skylark-lumi-trace-eval"))
    parser.add_argument(
        "--eval-private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval"),
    )
    parser.add_argument(
        "--ir-private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-ir"),
    )
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / VERSION)
    args = parser.parse_args()
    for root in (args.active_root, args.eval_private_root, args.ir_private_root):
        root.mkdir(parents=True, exist_ok=True)
    result = build(args)
    print(result["seal"]["seal_id"])
    print(result["closure"]["payload"]["programme_state"])
    print(result["ir_decision"]["payload"]["lane_state"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
