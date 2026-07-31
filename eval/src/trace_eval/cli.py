# SPDX-License-Identifier: Apache-2.0
"""Trace-Eval deterministic qualification command surface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .assurance import (
    audit_partition_independence,
    build_sample_plan,
    build_training_manifest,
    evaluate_training_readiness,
    scan_quarantine_entries,
    seal_partitions,
    v04_metric_specification,
    validate_group_audit_card,
    validate_rights_matrix,
    verify_transition_chain,
)
from .canonical import dump_json, load_json
from .code_metrics import default_metric_specification
from .contracts import validate_record
from .environment import qualify_environment
from .errors import TraceEvalError
from .ir import normalise_episode, rank_episode
from .metrics import score_run, verify_labels, verify_scored_package
from .package import seal_package, verify_package
from .policy import audit_repository_independence, verify_rights
from .readiness import evaluate_readiness
from .registry import load_registry, records_by_schema, validate_registry
from .replay import replay_run
from .runner import run_registry


def _path(value: str) -> Path:
    return Path(value)


def _summary(**values: Any) -> None:
    print(json.dumps(values, allow_nan=False, ensure_ascii=True, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trace-eval", description=__doc__)
    parser.add_argument("--version", action="version", version=f"Trace-Eval {__version__}")
    domains = parser.add_subparsers(dest="domain", required=True)

    environment = domains.add_parser("environment")
    environment_commands = environment.add_subparsers(dest="command", required=True)
    qualify = environment_commands.add_parser("qualify")
    qualify.add_argument("--runtime-artifact", type=_path, required=True)
    qualify.add_argument("--runtime-sha256", required=True)
    qualify.add_argument("--evaluator-artifact", type=_path, required=True)
    qualify.add_argument("--evaluator-sha256", required=True)
    qualify.add_argument("--evaluator-source-revision", required=True)
    qualify.add_argument("--dependency-lock", type=_path, required=True)
    qualify.add_argument("--roots", type=_path, required=True)
    qualify.add_argument("--output", type=_path, required=True)

    registry = domains.add_parser("registry")
    registry_commands = registry.add_subparsers(dest="command", required=True)
    registry_validate = registry_commands.add_parser("validate")
    registry_validate.add_argument("registry", type=_path)
    registry_validate.add_argument(
        "--mode", choices=("public-fixture", "development", "qualification"), required=True
    )

    rights = domains.add_parser("rights")
    rights_commands = rights.add_subparsers(dest="command", required=True)
    rights_verify = rights_commands.add_parser("verify")
    rights_verify.add_argument("registry", type=_path)
    rights_verify.add_argument(
        "--mode", choices=("public-fixture", "development", "qualification"), required=True
    )

    splits = domains.add_parser("splits")
    splits_commands = splits.add_subparsers(dest="command", required=True)
    splits_audit = splits_commands.add_parser("audit")
    splits_audit.add_argument("registry", type=_path)

    labels = domains.add_parser("labels")
    labels_commands = labels.add_subparsers(dest="command", required=True)
    labels_verify = labels_commands.add_parser("verify")
    labels_verify.add_argument("labels", type=_path)

    run = domains.add_parser("run")
    run.add_argument(
        "--mode", choices=("public-fixture", "development", "qualification"), required=True
    )
    run.add_argument("--registry", type=_path, required=True)
    run.add_argument("--configuration", type=_path, required=True)
    run.add_argument("--runtime-executable", type=_path, required=True)
    run.add_argument("--runtime-artifact", type=_path, required=True)
    run.add_argument("--source-root", type=_path, required=True)
    run.add_argument("--workspace-root", type=_path, required=True)
    run.add_argument("--output", type=_path, required=True)

    replay = domains.add_parser("replay")
    replay.add_argument("run_package", type=_path)
    replay.add_argument("--registry", type=_path, required=True)
    replay.add_argument("--configuration", type=_path, required=True)
    replay.add_argument("--runtime-executable", type=_path, required=True)
    replay.add_argument("--runtime-artifact", type=_path, required=True)
    replay.add_argument("--source-root", type=_path, required=True)
    replay.add_argument("--workspace-root", type=_path, required=True)
    replay.add_argument("--output", type=_path, required=True)

    verify = domains.add_parser("verify")
    verify.add_argument("input", type=_path)

    report = domains.add_parser("report")
    report.add_argument("run_package", type=_path)
    report.add_argument("--registry", type=_path, required=True)
    report.add_argument("--labels", type=_path, required=True)
    report.add_argument("--metric-specification", type=_path, required=True)
    report.add_argument("--output", type=_path, required=True)

    readiness = domains.add_parser("readiness")
    readiness_commands = readiness.add_subparsers(dest="command", required=True)
    evaluate = readiness_commands.add_parser("evaluate")
    evaluate.add_argument("evidence_root", type=_path)
    evaluate.add_argument("--environment-record", type=_path, required=True)
    evaluate.add_argument("--registry", type=_path, required=True)
    evaluate.add_argument("--run-package", type=_path, required=True)
    evaluate.add_argument("--scored-package", type=_path, required=True)
    evaluate.add_argument("--replay-package", type=_path, required=True)

    code = domains.add_parser("code")
    code_commands = code.add_subparsers(dest="command", required=True)
    metric_spec = code_commands.add_parser("metric-specification")
    metric_spec.add_argument("--output", type=_path, required=True)

    ir = domains.add_parser("ir")
    ir_commands = ir.add_subparsers(dest="command", required=True)
    ir_normalise = ir_commands.add_parser("normalise")
    ir_normalise.add_argument("input", type=_path)
    ir_normalise.add_argument("--output", type=_path, required=True)
    ir_rank = ir_commands.add_parser("rank")
    ir_rank.add_argument("episode_package", type=_path)
    ir_rank.add_argument("--output", type=_path, required=True)

    assurance = domains.add_parser("assurance")
    assurance_commands = assurance.add_subparsers(dest="command", required=True)
    sample_plan = assurance_commands.add_parser("sample-plan")
    sample_plan.add_argument("--output", type=_path, required=True)
    metrics = assurance_commands.add_parser("metric-specification")
    metrics.add_argument("--output", type=_path, required=True)
    scan = assurance_commands.add_parser("scan-quarantine")
    scan.add_argument("entries", type=_path)
    scan.add_argument("--subject-id", required=True)
    scan.add_argument("--output", type=_path, required=True)
    transitions = assurance_commands.add_parser("verify-transitions")
    transitions.add_argument("records", type=_path)
    card = assurance_commands.add_parser("validate-card")
    card.add_argument("card", type=_path)
    card.add_argument("--rights", type=_path)
    partitions = assurance_commands.add_parser("seal-partitions")
    partitions.add_argument("cards", type=_path)
    partitions.add_argument("--independence-audit-id", required=True)
    partitions.add_argument("--duplicate-audit-id", required=True)
    partitions.add_argument("--output", type=_path, required=True)
    admission = assurance_commands.add_parser("training-admission")
    admission.add_argument("cards", type=_path)
    admission.add_argument("--rights", type=_path, required=True)
    admission.add_argument("--partition-seal", type=_path, required=True)
    admission.add_argument("--gates", type=_path, required=True)
    admission.add_argument("--created-at", required=True)
    admission.add_argument("--output", type=_path, required=True)
    return parser


def dispatch(args: argparse.Namespace) -> None:
    if args.domain == "environment":
        roots = load_json(args.roots)
        if not isinstance(roots, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in roots.items()
        ):
            raise TraceEvalError("environment roots must be a JSON string map")
        record = qualify_environment(
            runtime_artifact=args.runtime_artifact,
            expected_runtime_sha256=args.runtime_sha256,
            evaluator_artifact=args.evaluator_artifact,
            expected_evaluator_sha256=args.evaluator_sha256,
            evaluator_source_revision=args.evaluator_source_revision,
            dependency_lock=args.dependency_lock,
            roots=roots,
            output=args.output,
        )
        _summary(qualified=True, environment_id=record["record_id"])
    elif args.domain == "registry":
        result = validate_registry(load_registry(args.registry), mode=args.mode)
        _summary(**result)
    elif args.domain == "rights":
        registry = load_registry(args.registry)
        records = records_by_schema(registry, "repository-rights-manifest-v1")
        for record in records:
            verify_rights(record, mode=args.mode)
        _summary(valid=True, repositories=len(records))
    elif args.domain == "splits":
        registry = load_registry(args.registry)
        splits = records_by_schema(registry, "split-manifest-v1")
        if len(splits) != 1:
            raise TraceEvalError("registry must contain exactly one split manifest")
        result = audit_repository_independence(
            records_by_schema(registry, "repository-rights-manifest-v1"), splits[0]
        )
        _summary(**result)
    elif args.domain == "labels":
        result = verify_labels(load_registry(args.labels))
        _summary(**result)
    elif args.domain == "run":
        configuration = load_json(args.configuration)
        if (
            not isinstance(configuration, dict)
            or configuration.get("payload", {}).get("mode") != args.mode
        ):
            raise TraceEvalError("--mode does not match the sealed evaluator configuration")
        result = run_registry(
            registry_path=args.registry,
            configuration_path=args.configuration,
            executable=args.runtime_executable,
            runtime_artifact=args.runtime_artifact,
            source_root=args.source_root,
            workspace_root=args.workspace_root,
            output=args.output,
        )
        _summary(
            run_id=result["run_record"]["payload"]["run_id"],
            package_id=result["manifest"]["package_id"],
        )
    elif args.domain == "replay":
        result = replay_run(
            original=args.run_package,
            registry=args.registry,
            configuration=args.configuration,
            executable=args.runtime_executable,
            runtime_artifact=args.runtime_artifact,
            source_root=args.source_root,
            workspace_root=args.workspace_root,
            output=args.output,
        )
        _summary(
            replay_id=result["record"]["record_id"],
            identity_agreement=result["record"]["payload"]["identity_agreement"],
        )
    elif args.domain == "verify":
        if args.input.is_dir():
            if (args.input / "aggregate-metrics.json").exists():
                manifest = verify_scored_package(args.input)
            else:
                manifest = verify_package(args.input)
            _summary(valid=True, package_id=manifest["package_id"])
        else:
            value = load_json(args.input)
            if not isinstance(value, dict):
                raise TraceEvalError("record input must be an object")
            validate_record(value)
            _summary(valid=True, record_id=value["record_id"])
    elif args.domain == "report":
        result = score_run(
            run_root=args.run_package,
            registry_path=args.registry,
            labels_path=args.labels,
            metric_spec_path=args.metric_specification,
            output=args.output,
        )
        _summary(
            aggregate_id=result["aggregate"]["record_id"],
            package_id=result["manifest"]["package_id"],
        )
    elif args.domain == "readiness":
        result = evaluate_readiness(
            environment_record_path=args.environment_record,
            registry_path=args.registry,
            run_package=args.run_package,
            scored_package=args.scored_package,
            replay_package=args.replay_package,
            output=args.evidence_root,
        )
        _summary(
            closure_state=result["readiness"]["payload"]["closure_state"],
            recommendation=result["readiness"]["payload"]["recommendation"],
            package_id=result["manifest"]["package_id"],
        )
    elif args.domain == "code":
        if args.output.exists():
            raise TraceEvalError("metric specification output already exists")
        record = default_metric_specification()
        dump_json(args.output, record)
        _summary(record_id=record["record_id"])
    elif args.domain == "ir" and args.command == "normalise":
        if args.output.exists():
            raise TraceEvalError("Trace IR normalised output already exists")
        document = load_json(args.input)
        if not isinstance(document, dict):
            raise TraceEvalError("Trace IR input package must be an object")
        episode, events = normalise_episode(document)
        args.output.mkdir(parents=True)
        dump_json(args.output / "episode.json", episode)
        for index, event in enumerate(events):
            dump_json(args.output / "events" / f"{index:06d}.json", event)
        manifest = seal_package(args.output)
        _summary(
            episode_id=episode["record_id"],
            event_count=len(events),
            package_id=manifest["package_id"],
        )
    elif args.domain == "ir" and args.command == "rank":
        if args.output.exists():
            raise TraceEvalError("Trace IR result output already exists")
        verify_package(args.episode_package)
        episode = load_json(args.episode_package / "episode.json")
        events = [
            load_json(path) for path in sorted((args.episode_package / "events").glob("*.json"))
        ]
        if not isinstance(episode, dict) or not all(isinstance(item, dict) for item in events):
            raise TraceEvalError("Trace IR normalised package is malformed")
        result = rank_episode(episode, events)
        args.output.mkdir(parents=True)
        dump_json(args.output / "result.json", result)
        manifest = seal_package(args.output)
        _summary(result_id=result["record_id"], package_id=manifest["package_id"])
    elif args.domain == "assurance" and args.command == "sample-plan":
        if args.output.exists():
            raise TraceEvalError("sample plan output already exists")
        record = build_sample_plan()
        dump_json(args.output, record)
        _summary(record_id=record["record_id"])
    elif args.domain == "assurance" and args.command == "metric-specification":
        if args.output.exists():
            raise TraceEvalError("metric specification output already exists")
        record = v04_metric_specification()
        dump_json(args.output, record)
        _summary(record_id=record["record_id"])
    elif args.domain == "assurance" and args.command == "scan-quarantine":
        entries = load_json(args.entries)
        if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
            raise TraceEvalError("quarantine entries must be a JSON array of objects")
        record = scan_quarantine_entries(entries, subject_id=args.subject_id)
        dump_json(args.output, record)
        _summary(record_id=record["record_id"], decision=record["payload"]["decision"])
    elif args.domain == "assurance" and args.command == "verify-transitions":
        records = load_json(args.records)
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise TraceEvalError("transition input must be a JSON array of records")
        _summary(valid=True, final_state=verify_transition_chain(records))
    elif args.domain == "assurance" and args.command == "validate-card":
        card_record = load_json(args.card)
        rights_record = load_json(args.rights) if args.rights else None
        if not isinstance(card_record, dict) or (
            rights_record is not None and not isinstance(rights_record, dict)
        ):
            raise TraceEvalError("audit card and rights inputs must be records")
        if rights_record is not None:
            validate_rights_matrix(rights_record)
        validate_group_audit_card(card_record, rights_matrix=rights_record)
        _summary(valid=True, record_id=card_record["record_id"])
    elif args.domain == "assurance" and args.command == "seal-partitions":
        cards = load_json(args.cards)
        if not isinstance(cards, list) or not all(isinstance(item, dict) for item in cards):
            raise TraceEvalError("cards input must be a JSON array of records")
        audit = audit_partition_independence(cards)
        record = seal_partitions(
            cards,
            independence_audit_id=args.independence_audit_id,
            duplicate_audit_id=args.duplicate_audit_id,
        )
        dump_json(args.output, record)
        _summary(
            record_id=record["record_id"],
            group_count=audit["group_count"],
            family_count=audit["family_count"],
        )
    elif args.domain == "assurance" and args.command == "training-admission":
        cards = load_json(args.cards)
        rights = load_json(args.rights)
        seal = load_json(args.partition_seal)
        gates = load_json(args.gates)
        if (
            not isinstance(cards, list)
            or not all(isinstance(item, dict) for item in cards)
            or not isinstance(rights, list)
            or not all(isinstance(item, dict) for item in rights)
            or not isinstance(seal, dict)
            or not isinstance(gates, dict)
        ):
            raise TraceEvalError("training-admission inputs are malformed")
        rights_by_id = {item["record_id"]: item for item in rights}
        manifest = build_training_manifest(
            cards,
            rights_by_id,
            partition_seal=seal,
            created_at=args.created_at,
        )
        readiness_record = evaluate_training_readiness(manifest, gates=gates)
        args.output.mkdir(parents=True)
        dump_json(args.output / "training-eligibility-manifest.json", manifest)
        dump_json(args.output / "training-readiness.json", readiness_record)
        _summary(
            recommendation=readiness_record["payload"]["recommendation"],
            manifest_id=manifest["record_id"],
            readiness_id=readiness_record["record_id"],
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        dispatch(args)
    except (TraceEvalError, OSError, ValueError) as exc:
        print(f"trace-eval: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 2)
    return 0
