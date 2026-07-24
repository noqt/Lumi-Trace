# SPDX-License-Identifier: Apache-2.0
"""Build the governed V0.3.2 deterministic capability and qualification evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_v0_3_2_recovery import _metric_rate, _score_code_run, _wilson
from trace_eval.canonical import dump_json, load_json, sha256_file
from trace_eval.code_metrics import default_metric_specification
from trace_eval.contracts import make_record
from trace_eval.package import seal_package, verify_package
from trace_eval.replay import replay_run
from trace_eval.runner import run_registry

VERSION = "v0.3.2"
SOURCE_REVISION = "1b7d4e713e367d1a1c98b54a03b47cd3978db36f"
RUNTIME_HASH = "sha256:6c674f15eb2d0178e3d0054d05dd733127981e640e8891fe37c135d394d42173"
EVALUATOR_HASH = "sha256:1c597ae51e84a4f0b5f497f297ee3326c0e1adf7d8d624285a25a690927b5de8"


def _root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _configuration(*, mode: str, metric_spec_id: str, purpose: str) -> dict[str, Any]:
    return make_record(
        "evaluator-configuration-v1",
        {
            "runtime": {
                "name": "skylark-lumi-trace",
                "version": "0.1.2",
                "artifact_sha256": RUNTIME_HASH,
                "source_revision": SOURCE_REVISION,
                "index_algorithm": "deterministic-lexical-index-v2",
                "algorithm": "deterministic-candidate-ranking-v2",
                "purpose": purpose,
            },
            "mode": mode,
            "limits": {
                "case_disk_bytes": 134_217_728,
                "case_timeout_seconds": 600,
                "memory_bytes": 2_147_483_648,
                "pids": 64,
                "subprocess_output_bytes": 1_048_576,
            },
            "offline": True,
            "k_max": 20,
            "metric_spec_id": metric_spec_id,
        },
    )


def _checks(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    micro = aggregate["payload"]["micro"]
    family = aggregate["payload"]["repository_family_macro"]["file_recall"]["20"]
    declared = [
        ("target_indexability", _metric_rate(micro["target_indexability"]), ">=", 0.90),
        ("file_recall_at_20", _metric_rate(micro["file_recall"]["20"]), ">=", 0.70),
        (
            "hard_negative_outrank",
            _metric_rate(micro["hard_negative_outrank"]),
            "<=",
            0.25,
        ),
        (
            "wrong_location_role_top_one",
            _metric_rate(micro["wrong_location_role_top_one"]),
            "<=",
            0.25,
        ),
        (
            "false_supported_disposition",
            _metric_rate(micro["false_supported_disposition"]["rate"]),
            "==",
            0.0,
        ),
        (
            "false_vulnerability_rate",
            _metric_rate(micro["false_vulnerability_rate"]),
            "==",
            0.0,
        ),
        (
            "unsafe_non_abstention",
            _metric_rate(micro["unsafe_non_abstention"]),
            "==",
            0.0,
        ),
        ("repository_family_macro_recall_at_20", family["mean"], ">=", 0.70),
        ("minimum_family_recall_at_20", family["minimum"], ">=", 0.50),
        ("zero_recall_family_count", family["zero_unit_count"], "==", 0),
    ]
    return [
        {
            "metric": metric,
            "observed": observed,
            "operator": operator,
            "threshold": threshold,
            "passed": observed is not None
            and (
                observed >= threshold
                if operator == ">="
                else observed <= threshold
                if operator == "<="
                else observed == threshold
            ),
        }
        for metric, observed, operator, threshold in declared
    ]


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    private = _root(args.private_root, "G:")
    verify_package(private / "manifests" / VERSION / "baseline-v0.1.1")
    if sha256_file(args.runtime_wheel) != RUNTIME_HASH:
        raise ValueError("V0.1.2 runtime wheel is not the reproducible artifact")
    if sha256_file(args.evaluator_wheel) != EVALUATOR_HASH:
        raise ValueError("Trace-Eval V0.3.3 wheel is not the reproducible artifact")
    previous = load_json(
        private / "manifests" / VERSION / "baseline-v0.1.1" / "baseline-decision.json"
    )
    if previous["qualification_authorised"] is not False:
        raise ValueError("V0.1.1 baseline did not preserve the qualification gate")
    budget = load_json(
        private / "manifests" / "v0.3.1" / "decisions" / "qualification-budget-final.json"
    )
    if (
        budget["payload"]["maximum_runs"] != 1
        or budget["payload"]["consumed_runs"] != 0
        or not str(budget["payload"]["state"]).startswith("UNUSED")
    ):
        raise ValueError("protected qualification budget is not unopened at 0 of 1")

    root = private / "manifests" / VERSION / "control-v0.1.2-sealed"
    if root.exists():
        raise ValueError("refusing to overwrite V0.1.2 control package")
    root.mkdir(parents=True)
    metric_spec = default_metric_specification()
    configuration = _configuration(
        mode="development",
        metric_spec_id=metric_spec["record_id"],
        purpose="V0.1.2_DETERMINISTIC_CAPABILITY_RECOVERY",
    )
    lock = {
        "schema_version": "lumi-trace-v0.3.2-artifact-lock-v1",
        "source_revision": SOURCE_REVISION,
        "runtime_version": "0.1.2",
        "runtime_wheel_sha256": RUNTIME_HASH,
        "evaluator_version": "0.3.3",
        "evaluator_wheel_sha256": EVALUATOR_HASH,
        "index_algorithm": "deterministic-lexical-index-v2",
        "ranking_algorithm": "deterministic-candidate-ranking-v2",
        "metric_specification": "trace-code-metric-specification-v2",
        "candidate_limit": 20,
        "maximum_candidates_per_path": 2,
        "qualification_budget": {"consumed": 0, "maximum": 1},
        "training_started": False,
        "weights_acquired": False,
    }
    dump_json(root / "artifact-lock.json", lock)
    dump_json(root / "metric-specification.json", metric_spec)
    dump_json(root / "development-configuration.json", configuration)
    manifest = seal_package(root)
    return {
        "control_package_id": manifest["package_id"],
        "configuration_id": configuration["record_id"],
        "metric_spec_id": metric_spec["record_id"],
    }


def development(args: argparse.Namespace) -> dict[str, Any]:
    active = _root(args.active_root, "F:")
    private = _root(args.private_root, "G:")
    corpus = private / "manifests" / "v0.3.1" / "corpus"
    control = private / "manifests" / VERSION / "control-v0.1.2-sealed"
    control_manifest = verify_package(control)
    verify_package(corpus)
    if sha256_file(args.runtime_wheel) != RUNTIME_HASH:
        raise ValueError("V0.1.2 runtime wheel changed after lock")
    if sha256_file(args.evaluator_wheel) != EVALUATOR_HASH:
        raise ValueError("Trace-Eval V0.3.3 wheel changed after lock")

    run_root = active / "runs" / VERSION / "development-v0.1.2-sealed"
    result = run_registry(
        registry_path=corpus / "runner-registry.json",
        configuration_path=control / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "v0.1.2-sealed-development",
        output=run_root,
    )
    metric_spec = load_json(control / "metric-specification.json")
    scored_root = active / "runs" / VERSION / "development-v0.1.2-sealed-scored"
    scored = _score_code_run(
        run_root=run_root,
        registry_path=corpus / "runner-registry.json",
        labels_path=corpus / "labels-evaluator-only.json",
        metric_spec=metric_spec,
        output=scored_root,
    )
    replay_root = active / "runs" / VERSION / "development-v0.1.2-sealed-replay"
    replay = replay_run(
        original=run_root,
        registry=corpus / "runner-registry.json",
        configuration=control / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "v0.1.2-sealed-development-replay",
        output=replay_root,
    )
    attempts = result["attempts"]
    all_completed = all(item["payload"]["status"] == "COMPLETED" for item in attempts)
    replay_valid = (
        replay["record"]["payload"]["identity_agreement"] is True
        and replay["record"]["payload"]["semantic_agreement"] is True
    )
    threshold_checks = _checks(scored["aggregate"])
    qualification_authorised = (
        all_completed and replay_valid and all(item["passed"] for item in threshold_checks)
    )
    qualification_configuration = _configuration(
        mode="qualification",
        metric_spec_id=metric_spec["record_id"],
        purpose="V0.1.2_LOCKED_SINGLE_USE_QUALIFICATION",
    )
    micro = scored["aggregate"]["payload"]["micro"]
    decision = {
        "schema_version": "lumi-trace-v0.3.2-capability-lock-v1",
        "source_revision": SOURCE_REVISION,
        "runtime_wheel_sha256": RUNTIME_HASH,
        "evaluator_wheel_sha256": EVALUATOR_HASH,
        "development_run_id": result["run_record"]["payload"]["run_id"],
        "all_attempts_completed": all_completed,
        "replay_identity_agreement": replay["record"]["payload"]["identity_agreement"],
        "replay_semantic_agreement": replay["record"]["payload"]["semantic_agreement"],
        "threshold_checks": threshold_checks,
        "performance_gates_passed": qualification_authorised,
        "qualification_authorised": qualification_authorised,
        "qualification_budget_consumed": 0,
        "training_authorised": False,
        "confidence_intervals_95": {
            "target_indexability": _wilson(micro["target_indexability"]),
            "file_recall_at_20": _wilson(micro["file_recall"]["20"]),
            "hard_negative_outrank": _wilson(micro["hard_negative_outrank"]),
        },
    }
    experiment = make_record(
        "deterministic-experiment-v1",
        {
            "experiment_id": "V0.1.2_SOURCE_PRIORITY_QUERY_HYGIENE_PATH_DIVERSITY",
            "runtime_version": "0.1.2",
            "algorithm": {
                "index": "deterministic-lexical-index-v2",
                "ranking": "deterministic-candidate-ranking-v2",
                "metric": "trace-code-metric-specification-v2",
            },
            "development_only": True,
            "hypothesis": (
                "bounded source-priority indexing, query hygiene, and two-per-path "
                "selection recover implementation visibility without case-specific rules"
            ),
            "configuration_id": load_json(control / "development-configuration.json")["record_id"],
            "result_id": scored["aggregate"]["record_id"],
            "decision": "LOCK_FOR_QUALIFICATION" if qualification_authorised else "REJECT",
        },
    )
    decision_root = private / "manifests" / VERSION / "capability-lock-v0.1.2-sealed"
    if decision_root.exists():
        raise ValueError("refusing to overwrite V0.1.2 capability lock")
    decision_root.mkdir(parents=True)
    dump_json(decision_root / "capability-lock.json", decision)
    dump_json(decision_root / "deterministic-experiment.json", experiment)
    dump_json(decision_root / "aggregate-metrics.json", scored["aggregate"])
    dump_json(decision_root / "qualification-configuration.json", qualification_configuration)
    dump_json(
        decision_root / "qualification-budget-before.json",
        load_json(
            private / "manifests" / "v0.3.1" / "decisions" / "qualification-budget-final.json"
        ),
    )
    decision_manifest = seal_package(decision_root)
    return {
        "run_package_id": result["manifest"]["package_id"],
        "scored_package_id": scored["manifest"]["package_id"],
        "replay_package_id": verify_package(replay_root)["package_id"],
        "control_package_id": control_manifest["package_id"],
        "decision_package_id": decision_manifest["package_id"],
        "attempts": len(attempts),
        "completed": sum(item["payload"]["status"] == "COMPLETED" for item in attempts),
        "micro": micro,
        "family_recall_at_20": scored["aggregate"]["payload"]["repository_family_macro"][
            "file_recall"
        ]["20"],
        "qualification_authorised": qualification_authorised,
    }


def qualify(args: argparse.Namespace) -> dict[str, Any]:
    active = _root(args.active_root, "F:")
    private = _root(args.private_root, "G:")
    corpus = private / "manifests" / "v0.3.1" / "corpus"
    lock_root = private / "manifests" / VERSION / "capability-lock-v0.1.2-sealed"
    verify_package(lock_root)
    lock = load_json(lock_root / "capability-lock.json")
    if lock["qualification_authorised"] is not True:
        raise ValueError("development gates did not authorise qualification")
    budget = load_json(lock_root / "qualification-budget-before.json")
    if budget["payload"]["consumed_runs"] != 0 or budget["payload"]["maximum_runs"] != 1:
        raise ValueError("qualification budget is not 0 of 1")
    if sha256_file(args.runtime_wheel) != RUNTIME_HASH:
        raise ValueError("V0.1.2 runtime wheel changed after capability lock")
    if sha256_file(args.evaluator_wheel) != EVALUATOR_HASH:
        raise ValueError("Trace-Eval V0.3.3 wheel changed after capability lock")

    run_root = active / "runs" / VERSION / "qualification-v0.1.2-sealed"
    result = run_registry(
        registry_path=corpus / "runner-registry.json",
        configuration_path=lock_root / "qualification-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "v0.1.2-sealed-qualification",
        output=run_root,
    )
    scored = _score_code_run(
        run_root=run_root,
        registry_path=corpus / "runner-registry.json",
        labels_path=corpus / "labels-evaluator-only.json",
        metric_spec=load_json(
            private / "manifests" / VERSION / "control-v0.1.2-sealed" / "metric-specification.json"
        ),
        output=active / "runs" / VERSION / "qualification-v0.1.2-sealed-scored",
    )
    attempts = result["attempts"]
    all_completed = all(item["payload"]["status"] == "COMPLETED" for item in attempts)
    threshold_checks = _checks(scored["aggregate"])
    passed = all_completed and all(item["passed"] for item in threshold_checks)
    budget_after = make_record(
        "qualification-budget-v1",
        {
            "split_manifest_id": budget["payload"]["split_manifest_id"],
            "maximum_runs": 1,
            "consumed_runs": 1,
            "state": "SPENT",
            "consumption_receipt_ids": [result["run_record"]["payload"]["run_id"]],
        },
    )
    decision = make_record(
        "qualification-decision-v1",
        {
            "closure_state": (
                "CAPABILITY_QUALIFIED" if passed else "QUALIFICATION_FAILED_PARTITION_SPENT"
            ),
            "runtime_id": {
                "version": "0.1.2",
                "artifact_sha256": RUNTIME_HASH,
                "source_revision": SOURCE_REVISION,
            },
            "evaluator_id": {
                "version": "0.3.3",
                "artifact_sha256": EVALUATOR_HASH,
            },
            "evidence_ids": [
                result["manifest"]["package_id"],
                scored["manifest"]["package_id"],
            ],
            "threshold_decision": {
                "checks": threshold_checks,
                "passed": passed,
                "used_for_remediation": False,
                "used_for_threshold_selection": False,
            },
            "holdback_opened": False,
        },
    )
    decision_root = private / "manifests" / VERSION / "qualification-v0.1.2-sealed"
    if decision_root.exists():
        raise ValueError("refusing to overwrite V0.1.2 qualification decision")
    decision_root.mkdir(parents=True)
    dump_json(decision_root / "qualification-decision.json", decision)
    dump_json(decision_root / "qualification-budget-after.json", budget_after)
    dump_json(decision_root / "aggregate-metrics.json", scored["aggregate"])
    manifest = seal_package(decision_root)
    return {
        "run_package_id": result["manifest"]["package_id"],
        "scored_package_id": scored["manifest"]["package_id"],
        "decision_package_id": manifest["package_id"],
        "attempts": len(attempts),
        "completed": sum(item["payload"]["status"] == "COMPLETED" for item in attempts),
        "micro": scored["aggregate"]["payload"]["micro"],
        "family_recall_at_20": scored["aggregate"]["payload"]["repository_family_macro"][
            "file_recall"
        ]["20"],
        "passed": passed,
        "qualification_budget_consumed": 1,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("phase", choices=["prepare", "development", "qualify"])
    value.add_argument("--active-root", type=Path, default=Path("F:/Data/skylark-lumi-trace-eval"))
    value.add_argument("--private-root", type=Path, default=Path("G:/Data/skylark-lumi-trace-eval"))
    value.add_argument(
        "--runtime-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.1.2-sealed-a/"
            "skylark_lumi_trace-0.1.2-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--evaluator-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.3.3-sealed-a/"
            "skylark_lumi_trace_eval-0.3.3-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--runtime-executable",
        type=Path,
        default=Path(
            "F:/Data/skylark-lumi-trace-eval/runtime/sut-v0.1.2-sealed/Scripts/lumi-trace.exe"
        ),
    )
    return value


def main() -> int:
    args = parser().parse_args()
    result = {
        "prepare": prepare,
        "development": development,
        "qualify": qualify,
    }[args.phase](args)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
