# SPDX-License-Identifier: Apache-2.0
"""Build governed V0.3.2 contract, resource, and development recovery evidence."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from trace_eval.canonical import dump_json, load_json, sha256_file
from trace_eval.code_metrics import aggregate_trace_code_metrics, score_trace_code_case
from trace_eval.contracts import make_record
from trace_eval.package import seal_package, verify_package
from trace_eval.registry import load_registry, records_by_schema
from trace_eval.replay import replay_run
from trace_eval.runner import load_run_package, run_registry

VERSION = "v0.3.2"
V031_SEAL = (
    "lumi-trace-v0.3.1-public-evidence:"
    "e06658ab3ab0b6f1d9085f1d3f5d0c672f7d4283d5e554f0305452e8492f567f"
)
V010_HASH = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
V031_EVAL_HASH = "sha256:7d1b81a9559d6cde474f155e97e1df108884232b7d0174f8568e53dcef5a38b8"
V011_HASH = "sha256:e3334957190d82369cf96b51aa69e844dc5133ee67ae4c007e60d12012a5f661"
V032_EVAL_HASH = "sha256:1fa88b5d71e4f7a10ba933e10edabb67217f1849b394f416544d5c282d858529"


def _root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _configuration(
    *,
    runtime_hash: str,
    timeout_seconds: int,
    metric_spec_id: str,
    purpose: str,
) -> dict[str, Any]:
    return make_record(
        "evaluator-configuration-v1",
        {
            "runtime": {
                "name": "skylark-lumi-trace",
                "version": "0.1.1",
                "artifact_sha256": runtime_hash,
                "source_revision": "release:0.1.1",
                "algorithm": "deterministic-candidate-ranking-v1",
                "purpose": purpose,
            },
            "mode": "development",
            "limits": {
                "case_disk_bytes": 134_217_728,
                "case_timeout_seconds": timeout_seconds,
                "memory_bytes": 2_147_483_648,
                "pids": 64,
                "subprocess_output_bytes": 1_048_576,
            },
            "offline": True,
            "k_max": 20,
            "metric_spec_id": metric_spec_id,
        },
    )


def _indexed_locations(index: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    files: list[str] = []
    symbols: list[dict[str, str]] = []
    for item in index.get("files", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        path = item["path"]
        files.append(path)
        for symbol in item.get("symbols", []):
            if not isinstance(symbol, dict):
                continue
            for key in ("name", "qualified_name"):
                value = symbol.get(key)
                if isinstance(value, str) and value:
                    symbols.append({"path": path, "symbol": value})
    return files, symbols


def _score_code_run(
    *,
    run_root: Path,
    registry_path: Path,
    labels_path: Path,
    metric_spec: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    if output.exists():
        raise ValueError("refusing to overwrite Trace Code scored package")
    run_record, attempts, _ = load_run_package(run_root)
    registry = load_registry(registry_path)
    labels = load_registry(labels_path)
    groups = {
        record["record_id"]: record
        for record in records_by_schema(registry, "candidate-ranking-group-v1")
    }
    location_labels = {
        record["payload"]["group_id"]: record
        for record in records_by_schema(labels, "trace-code-location-label-v1")
    }
    output.mkdir(parents=True)
    case_root = output / "case-results"
    case_root.mkdir()
    cases: list[dict[str, Any]] = []
    for attempt in attempts:
        group = groups[attempt["payload"]["group_id"]]
        label = location_labels[group["payload"]["group_id"]]
        candidates: list[dict[str, Any]] = []
        indexed_files: list[str] = []
        indexed_symbols: list[dict[str, str]] = []
        observed = "UNSUPPORTED_INPUT"
        if attempt["payload"]["status"] == "COMPLETED":
            suffix = group["record_id"].rsplit(":", 1)[-1]
            package = run_root / "raw" / suffix / "evidence-package"
            candidates_document = load_json(package / "candidates.json")
            index = load_json(package / "repository-index.json")
            bundle = load_json(package / "evidence-bundle.json")
            candidates = [
                item
                for item in candidates_document.get("candidates", [])
                if isinstance(item, dict) and int(item.get("rank", 21)) <= 20
            ]
            indexed_files, indexed_symbols = _indexed_locations(index)
            outcome = bundle.get("classification", {}).get("outcome")
            observed = {
                "CONFIRMED": "SUPPORTED",
                "UNSUPPORTED": "UNSUPPORTED_INPUT",
                "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE",
            }.get(outcome, "UNSUPPORTED_INPUT")
        taxonomy = dict(group["payload"]["taxonomy"])
        taxonomy["runtime_attempt_status"] = attempt["payload"]["status"]
        case = score_trace_code_case(
            label,
            candidates=candidates,
            indexed_files=indexed_files,
            indexed_symbols=indexed_symbols,
            observed_disposition=observed,
            taxonomy=taxonomy,
        )
        cases.append(case)
        dump_json(case_root / f"{case['record_id'].rsplit(':', 1)[-1]}.json", case)
    aggregate = aggregate_trace_code_metrics(cases, metric_spec)
    dump_json(output / "metric-specification.json", metric_spec)
    dump_json(output / "aggregate-metrics.json", aggregate)
    link = make_record(
        "run-record-v1",
        {
            "run_id": run_record["payload"]["run_id"],
            "mode": run_record["payload"]["mode"],
            "runtime_id": run_record["payload"]["runtime_id"],
            "registry_id": run_record["payload"]["registry_id"],
            "configuration_id": run_record["payload"]["configuration_id"],
            "attempt_ids": run_record["payload"]["attempt_ids"],
            "raw_output_seal_id": run_record["payload"]["raw_output_seal_id"],
            "scored_case_ids": [case["record_id"] for case in cases],
        },
    )
    dump_json(output / "run-link.json", link)
    manifest = seal_package(output)
    return {"aggregate": aggregate, "manifest": manifest, "cases": cases}


def _wilson(metric: dict[str, Any]) -> dict[str, float | int | None]:
    numerator = int(metric["numerator"])
    denominator = int(metric["denominator"])
    if denominator == 0:
        return {"numerator": numerator, "denominator": denominator, "low": None, "high": None}
    z = 1.959963984540054
    observed = numerator / denominator
    denominator_adjusted = 1 + z * z / denominator
    centre = (observed + z * z / (2 * denominator)) / denominator_adjusted
    margin = (
        z
        * math.sqrt(
            observed * (1 - observed) / denominator + z * z / (4 * denominator * denominator)
        )
        / denominator_adjusted
    )
    return {
        "numerator": numerator,
        "denominator": denominator,
        "low": max(0.0, centre - margin),
        "high": min(1.0, centre + margin),
    }


def _metric_rate(metric: dict[str, Any]) -> float | None:
    value = metric.get("rate")
    return float(value) if isinstance(value, int | float) else None


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    private = _root(args.private_root, "G:")
    corpus = private / "manifests" / "v0.3.1" / "corpus"
    verify_package(corpus)
    if sha256_file(args.v0_1_0_wheel) != V010_HASH:
        raise ValueError("immutable V0.1.0 wheel changed")
    if sha256_file(args.v0_3_1_evaluator_wheel) != V031_EVAL_HASH:
        raise ValueError("immutable V0.3.1 evaluator wheel changed")
    if sha256_file(args.runtime_wheel) != V011_HASH:
        raise ValueError("V0.1.1 runtime wheel is not the reproducible artifact")
    if sha256_file(args.evaluator_wheel) != V032_EVAL_HASH:
        raise ValueError("V0.3.2 evaluator wheel is not the reproducible artifact")
    root = private / "manifests" / VERSION / "control-original"
    if root.exists():
        raise ValueError("refusing to overwrite V0.3.2 original control package")
    root.mkdir(parents=True)
    starting = make_record(
        "starting-state-verification-v1",
        {
            "source_revision": args.source_revision,
            "v0_3_1_evidence_seal": V031_SEAL,
            "v0_1_0_runtime_hash": V010_HASH,
            "v0_3_1_evaluator_hash": V031_EVAL_HASH,
            "governed_roots": ["F:", "G:"],
            "verified": True,
        },
    )
    contract = make_record(
        "runtime-contract-decision-v1",
        {
            "runtime_version": "0.1.1",
            "candidate_schema": "candidate-set-v1",
            "ranking_algorithm": "deterministic-candidate-ranking-v1",
            "score_reason_match_limit": 20,
            "producer_verifier_schema_agreement": True,
            "ranking_behavior_preserved": True,
            "regression_manifest_id": args.contract_regression_id,
        },
    )
    metric_spec = load_json(
        private / "manifests" / "v0.3.1" / "pre-run" / "code-metric-specification.json"
    )
    configuration = _configuration(
        runtime_hash=V011_HASH,
        timeout_seconds=180,
        metric_spec_id=metric_spec["record_id"],
        purpose="V0.1.1_CONTRACT_RECOVERY_ORIGINAL_LIMITS",
    )
    dump_json(root / "starting-state-verification.json", starting)
    dump_json(root / "runtime-contract-decision.json", contract)
    dump_json(root / "metric-specification.json", metric_spec)
    dump_json(root / "development-configuration.json", configuration)
    manifest = seal_package(root)
    return {
        "control_package_id": manifest["package_id"],
        "configuration_id": configuration["record_id"],
    }


def diagnostic(args: argparse.Namespace) -> dict[str, Any]:
    active = _root(args.active_root, "F:")
    private = _root(args.private_root, "G:")
    corpus = private / "manifests" / "v0.3.1" / "corpus"
    control = private / "manifests" / VERSION / "control-original"
    verify_package(control)
    run_root = active / "runs" / VERSION / "development-v0.1.1-original-limits"
    result = run_registry(
        registry_path=corpus / "runner-registry.json",
        configuration_path=control / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "diagnostic",
        output=run_root,
    )
    metric_spec = load_json(control / "metric-specification.json")
    scored = _score_code_run(
        run_root=run_root,
        registry_path=corpus / "runner-registry.json",
        labels_path=corpus / "labels-evaluator-only.json",
        metric_spec=metric_spec,
        output=active / "runs" / VERSION / "development-v0.1.1-original-limits-scored",
    )
    attempts = result["attempts"]
    failure_counts = Counter(
        code for attempt in attempts for code in attempt["payload"]["failure_codes"]
    )
    classifications = [
        {
            "attempt_id": attempt["payload"]["attempt_id"],
            "termination_reason": attempt.get("observations", {}).get("termination_reason"),
            "wall_time_ms": attempt.get("observations", {}).get("wall_time_ms"),
            "runtime_wall_time_ms": attempt.get("observations", {})
            .get("stage_wall_time_ms", {})
            .get("runtime"),
            "peak_resident_bytes": attempt.get("observations", {}).get("peak_resident_bytes"),
            "repository_file_count": attempt.get("observations", {}).get("repository_file_count"),
            "repository_bytes": attempt.get("observations", {}).get("repository_bytes"),
        }
        for attempt in attempts
        if attempt["payload"]["status"] != "COMPLETED"
    ]
    unexpected = [
        item
        for item in classifications
        if item["termination_reason"] not in {"WALL_TIME_LIMIT", "RETAINED_DISK_LIMIT"}
    ]
    remediation = (
        "INCREASE_HARD_WALL_TO_600_SECONDS_WITH_PROCESS_TREE_TERMINATION"
        if classifications and not unexpected
        else "ENGINEERING_DIAGNOSIS_REQUIRED"
    )
    record = make_record(
        "resource-failure-classification-v1",
        {
            "runtime_version": "0.1.1",
            "configuration_id": load_json(control / "development-configuration.json")["record_id"],
            "attempt_count": len(attempts),
            "completed_attempts": sum(
                attempt["payload"]["status"] == "COMPLETED" for attempt in attempts
            ),
            "failure_counts": dict(sorted(failure_counts.items())),
            "classifications": classifications,
            "remediation": remediation,
        },
    )
    decision_root = private / "manifests" / VERSION / "resource-diagnostic"
    if decision_root.exists():
        raise ValueError("refusing to overwrite resource diagnostic package")
    decision_root.mkdir(parents=True)
    dump_json(decision_root / "resource-failure-classification.json", record)
    dump_json(decision_root / "diagnostic-aggregate.json", scored["aggregate"])
    manifest = seal_package(decision_root)
    return {
        "run_package_id": result["manifest"]["package_id"],
        "decision_package_id": manifest["package_id"],
        "attempts": len(attempts),
        "completed": record["payload"]["completed_attempts"],
        "failure_counts": record["payload"]["failure_counts"],
        "remediation": remediation,
    }


def recover(args: argparse.Namespace) -> dict[str, Any]:
    active = _root(args.active_root, "F:")
    private = _root(args.private_root, "G:")
    corpus = private / "manifests" / "v0.3.1" / "corpus"
    diagnostic_root = private / "manifests" / VERSION / "resource-diagnostic"
    verify_package(diagnostic_root)
    diagnosis = load_json(diagnostic_root / "resource-failure-classification.json")
    if (
        diagnosis["payload"]["remediation"]
        != "INCREASE_HARD_WALL_TO_600_SECONDS_WITH_PROCESS_TREE_TERMINATION"
    ):
        raise ValueError("resource diagnostic did not authorise the bounded recovery run")
    metric_spec = load_json(
        private / "manifests" / VERSION / "control-original" / "metric-specification.json"
    )
    control = private / "manifests" / VERSION / "control-recovered"
    if control.exists():
        raise ValueError("refusing to overwrite recovered control package")
    control.mkdir(parents=True)
    configuration = _configuration(
        runtime_hash=V011_HASH,
        timeout_seconds=600,
        metric_spec_id=metric_spec["record_id"],
        purpose="V0.1.1_BOUNDED_RESOURCE_RECOVERY",
    )
    dump_json(control / "development-configuration.json", configuration)
    dump_json(control / "metric-specification.json", metric_spec)
    control_manifest = seal_package(control)
    run_root = active / "runs" / VERSION / "development-v0.1.1-recovered"
    result = run_registry(
        registry_path=corpus / "runner-registry.json",
        configuration_path=control / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "recovered",
        output=run_root,
    )
    scored_root = active / "runs" / VERSION / "development-v0.1.1-recovered-scored"
    scored = _score_code_run(
        run_root=run_root,
        registry_path=corpus / "runner-registry.json",
        labels_path=corpus / "labels-evaluator-only.json",
        metric_spec=metric_spec,
        output=scored_root,
    )
    replay_root = active / "runs" / VERSION / "development-v0.1.1-recovered-replay"
    replay = replay_run(
        original=run_root,
        registry=corpus / "runner-registry.json",
        configuration=control / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=private / "artifacts" / "v0.3.1" / "runner-inputs",
        workspace_root=active / "workspace" / VERSION / "recovered-replay",
        output=replay_root,
    )
    attempts = result["attempts"]
    micro = scored["aggregate"]["payload"]["micro"]
    checks = [
        ("target_indexability", _metric_rate(micro["target_indexability"]), ">=", 0.90),
        ("file_recall_at_20", _metric_rate(micro["file_recall"]["20"]), ">=", 0.70),
        ("hard_negative_outrank", _metric_rate(micro["hard_negative_outrank"]), "<=", 0.25),
        (
            "wrong_location_role_top_one",
            _metric_rate(micro["wrong_location_role_top_one"]),
            "<=",
            0.25,
        ),
        (
            "false_supported_disposition",
            _metric_rate(micro["false_supported_disposition"]["rate"]),
            "<=",
            0.0,
        ),
        ("false_vulnerability_rate", _metric_rate(micro["false_vulnerability_rate"]), "<=", 0.0),
        ("unsafe_non_abstention", _metric_rate(micro["unsafe_non_abstention"]), "<=", 0.0),
    ]
    threshold_checks = [
        {
            "metric": metric,
            "observed": observed,
            "operator": operator,
            "threshold": threshold,
            "passed": observed is not None
            and (observed >= threshold if operator == ">=" else observed <= threshold),
        }
        for metric, observed, operator, threshold in checks
    ]
    all_completed = all(attempt["payload"]["status"] == "COMPLETED" for attempt in attempts)
    integrity = (
        all_completed
        and replay["record"]["payload"]["identity_agreement"] is True
        and replay["record"]["payload"]["semantic_agreement"] is True
    )
    decision = {
        "schema_version": "lumi-trace-v0.3.2-valid-baseline-decision-v1",
        "runtime_version": "0.1.1",
        "configuration_id": configuration["record_id"],
        "control_package_id": control_manifest["package_id"],
        "development_run_id": result["run_record"]["payload"]["run_id"],
        "all_attempts_completed": all_completed,
        "replay_identity_agreement": replay["record"]["payload"]["identity_agreement"],
        "replay_semantic_agreement": replay["record"]["payload"]["semantic_agreement"],
        "threshold_checks": threshold_checks,
        "performance_gates_passed": integrity and all(item["passed"] for item in threshold_checks),
        "qualification_authorised": integrity and all(item["passed"] for item in threshold_checks),
        "qualification_budget_consumed": 0,
        "training_authorised": False,
        "confidence_intervals_95": {
            "target_indexability": _wilson(micro["target_indexability"]),
            "file_recall_at_20": _wilson(micro["file_recall"]["20"]),
            "hard_negative_outrank": _wilson(micro["hard_negative_outrank"]),
        },
    }
    decision_root = private / "manifests" / VERSION / "baseline-v0.1.1"
    if decision_root.exists():
        raise ValueError("refusing to overwrite V0.1.1 baseline decision")
    decision_root.mkdir(parents=True)
    dump_json(decision_root / "baseline-decision.json", decision)
    dump_json(decision_root / "aggregate-metrics.json", scored["aggregate"])
    decision_manifest = seal_package(decision_root)
    return {
        "run_package_id": result["manifest"]["package_id"],
        "scored_package_id": scored["manifest"]["package_id"],
        "replay_package_id": verify_package(replay_root)["package_id"],
        "decision_package_id": decision_manifest["package_id"],
        "completed": sum(attempt["payload"]["status"] == "COMPLETED" for attempt in attempts),
        "attempts": len(attempts),
        "micro": micro,
        "performance_gates_passed": decision["performance_gates_passed"],
        "qualification_authorised": decision["qualification_authorised"],
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("phase", choices=["prepare", "diagnostic", "recover"])
    value.add_argument("--source-revision", default="UNCOMMITTED_V0.3.2_IMPLEMENTATION")
    value.add_argument(
        "--contract-regression-id",
        default="contract-regression:producer-verifier-schema-roundtrip-v0.1.1",
    )
    value.add_argument("--active-root", type=Path, default=Path("F:/Data/skylark-lumi-trace-eval"))
    value.add_argument("--private-root", type=Path, default=Path("G:/Data/skylark-lumi-trace-eval"))
    value.add_argument(
        "--v0-1-0-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/staging/"
            "skylark_lumi_trace-0.1.0-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--v0-3-1-evaluator-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.3.1-build-k/"
            "skylark_lumi_trace_eval-0.3.1-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--runtime-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.1.1-build-a/"
            "skylark_lumi_trace-0.1.1-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--evaluator-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.3.2-build-a/"
            "skylark_lumi_trace_eval-0.3.2-py3-none-any.whl"
        ),
    )
    value.add_argument(
        "--runtime-executable",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/runtime/sut-v0.1.1/Scripts/lumi-trace.exe"),
    )
    return value


def main() -> int:
    args = parser().parse_args()
    result = {
        "prepare": prepare,
        "diagnostic": diagnostic,
        "recover": recover,
    }[args.phase](args)
    print(json.dumps(result, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
