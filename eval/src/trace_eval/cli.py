# SPDX-License-Identifier: Apache-2.0
"""Trace-Eval V0.2 command surface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import load_json
from .contracts import validate_record
from .environment import qualify_environment
from .errors import TraceEvalError
from .metrics import score_run, verify_labels, verify_scored_package
from .package import verify_package
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        dispatch(args)
    except (TraceEvalError, OSError, ValueError) as exc:
        print(f"trace-eval: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 2)
    return 0
