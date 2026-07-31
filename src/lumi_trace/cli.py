# SPDX-License-Identifier: Apache-2.0
"""Command line interface for Lumi Trace."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from . import __version__
from .canonical import canonical_sha256, dump_json, load_json, sha256_file, stable_id
from .errors import InputError, LumiTraceError
from .findings import (
    import_manual,
    import_sarif,
    load_normalized_finding,
    validate_normalized_finding,
)
from .indexing import build_repository_index, verify_repository_index
from .learned_ranker import LEARNED_RANKER, verify_model_artifact
from .localization import (
    DEFAULT_RANKER,
    RAW_OUTPUT_SCHEMA,
    REQUEST_SCHEMA,
    STEP1_MAXIMUM_CANDIDATES,
    build_raw_localization,
    construct_inference_request,
    repository_artifact_identity,
    validate_inference_request,
    verify_raw_localization,
)
from .pipeline import load_bundle, trace_repository
from .ranking import rank_candidates, verify_candidate_set
from .reporting import classify_evidence, export_sarif, verify_evidence_bundle
from .repository import RepositoryWorkspace
from .sandbox import (
    DockerSandbox,
    load_reproduction_plan,
    plan_identity,
    validate_reproduction_plan,
    verify_reproduction_receipt,
)


def _path(value: str) -> Path:
    return Path(value)


def _write_summary(**values: object) -> None:
    print(json.dumps(values, ensure_ascii=True, sort_keys=True))


def _write_trace_summary(result: dict[str, object]) -> None:
    """Write a human summary to stderr and a stable machine summary to stdout."""

    bundle = result["bundle"]
    candidate_set = result["candidate_set"]
    output = Path(result["output_directory"])
    if not isinstance(bundle, dict) or not isinstance(candidate_set, dict):
        raise RuntimeError("trace result is missing its canonical bundle or candidate set")
    classification = bundle["classification"]
    reproduction = bundle["reproduction"]
    candidates = candidate_set["candidates"]
    ranking_abstention = candidate_set.get("abstention")
    if (
        not isinstance(classification, dict)
        or not isinstance(reproduction, dict)
        or not isinstance(candidates, list)
        or not isinstance(ranking_abstention, dict)
    ):
        raise RuntimeError("trace result summary fields are malformed")

    outcome = str(classification["outcome"])
    reason_codes = list(classification["reason_codes"])
    ranking_abstained = bool(ranking_abstention["abstained"])
    reproduction_abstained = outcome != "CONFIRMED"

    def summarize_location(candidate: dict[str, object]) -> dict[str, object]:
        symbol = candidate.get("symbol") or {}
        if not isinstance(symbol, dict):
            raise RuntimeError("trace candidate symbol is malformed")
        return {
            "rank": candidate["rank"],
            "path": candidate["path"],
            "symbol": symbol.get("qualified_name"),
            "role": candidate.get("role"),
            "integer_score": candidate["integer_score"],
        }

    top_ranked_locations = [
        summarize_location(candidate) for candidate in candidates[:3] if isinstance(candidate, dict)
    ]
    top_implementation_locations = [
        summarize_location(candidate)
        for candidate in candidates
        if isinstance(candidate, dict) and candidate.get("role") == "implementation"
    ][:3]
    displayed_locations = top_implementation_locations or top_ranked_locations
    displayed_location_label = (
        "Top implementation locations (true overall rank)"
        if top_implementation_locations
        else "Top ranked locations (no implementation-role candidate emitted)"
    )
    if reproduction["requested"]:
        confirmation_summary = (
            "attempted"
            if reproduction["attempted"]
            else "requested but not attempted; see evidence reason codes"
        )
    else:
        confirmation_summary = "not attempted (NO_REPRODUCTION_PLAN)"
    localisation_summary = "complete"
    if ranking_abstained:
        localisation_summary += f"; abstained ({ranking_abstention['reason']})"

    print("Lumi Trace result", file=sys.stderr)
    print(f"  Localisation: {localisation_summary}", file=sys.stderr)
    print(f"  Ranker: {candidate_set['algorithm']}", file=sys.stderr)
    print(
        f"  Ranked locations: {len(candidates)}; integer ordering scores are not probabilities",
        file=sys.stderr,
    )
    print(
        f"  Ranking confidence: {candidate_set['confidence_descriptor']}; "
        f"abstained={str(ranking_abstained).lower()}",
        file=sys.stderr,
    )
    if ranking_abstention["reason"]:
        print(f"  Ranking reason: {ranking_abstention['reason']}", file=sys.stderr)
    if displayed_locations:
        print(f"  {displayed_location_label}:", file=sys.stderr)
    for location in displayed_locations:
        symbol = f"::{location['symbol']}" if location["symbol"] else ""
        print(
            f"    {location['rank']}. {location['path']}{symbol} "
            f"(score {location['integer_score']})",
            file=sys.stderr,
        )
    print(f"  Confirmation: {confirmation_summary}", file=sys.stderr)
    print(
        f"  Evidence classification: {outcome}; confidence {classification['confidence_grade']} / "
        f"{classification['confidence_basis_points']} basis points "
        "(deterministic descriptor, not probability)",
        file=sys.stderr,
    )
    print(f"  Reasons: {', '.join(map(str, reason_codes))}", file=sys.stderr)
    print(f"  Output: {output}", file=sys.stderr)
    print(f'  Verify: lumi-trace verify "{output}"', file=sys.stderr)

    _write_summary(
        bundle_id=bundle["bundle_id"],
        classification=outcome,
        reason_codes=reason_codes,
        confidence_grade=classification["confidence_grade"],
        confidence_basis_points=classification["confidence_basis_points"],
        confidence_is_not_probability=True,
        ranking_abstained=ranking_abstained,
        ranking_abstention_reason=ranking_abstention["reason"],
        ranking_confidence_descriptor=candidate_set["confidence_descriptor"],
        ranking_algorithm=candidate_set["algorithm"],
        candidate_algorithm=candidate_set["candidate_algorithm"],
        ranking_id=candidate_set["ranking_id"],
        ranked_locations=len(candidates),
        top_ranked_locations=top_ranked_locations,
        top_implementation_locations=top_implementation_locations,
        reproduction_requested=reproduction["requested"],
        reproduction_attempted=reproduction["attempted"],
        reproduction_abstained=reproduction_abstained,
        output=str(output),
    )


def _actionable_hint(exc: Exception) -> str | None:
    message = str(exc).casefold()
    if "output directory already exists" in message:
        return "Choose a new --output path; Lumi Trace will not overwrite existing evidence."
    if "sarif selection produced" in message or "sarif run index" in message:
        return "Select exactly one result with --run-index and --result-index."
    if "sarif result index" in message:
        return "Check the SARIF result count, then supply a valid --result-index."
    if "--image is required" in message:
        return "Omit --plan for the no-Docker path, or supply a preloaded digest-form --image."
    if "archive" in message:
        return (
            "Use a regular ZIP/TAR-family archive with portable relative paths and no links "
            "or special members."
        )
    if "permission" in message or isinstance(exc, PermissionError):
        return "Check read access to the finding/repository and write access to the output parent."
    if isinstance(exc, FileNotFoundError) or "no such file" in message:
        return "Check that every input path exists and is readable."
    if "docker" in message or "image" in message:
        return (
            "Docker is optional. For reproduction, start a local Linux-container engine and "
            "preload the exact digest-form image; Lumi Trace never pulls."
        )
    return None


def _add_repository_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository",
        type=_path,
        help="local repository used to relativize absolute finding locations",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lumi-trace",
        description="Deterministic local vulnerability evidence instrument",
    )
    parser.add_argument("--version", action="version", version=f"Lumi Trace {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("version", help="show version and model status")

    status = commands.add_parser("status", help="show local runtime and sandbox availability")
    status.add_argument(
        "--image",
        required=True,
        help="preloaded immutable digest-form image to inspect",
    )

    manual = commands.add_parser("import-manual", help="normalize a manual finding")
    manual.add_argument("input", type=_path)
    manual.add_argument("--output", "-o", type=_path, required=True)
    _add_repository_option(manual)

    sarif = commands.add_parser("import-sarif", help="normalize SARIF 2.1.0 results")
    sarif.add_argument("input", type=_path)
    sarif.add_argument("--output", "-o", type=_path, required=True)
    sarif.add_argument("--run-index", type=int)
    sarif.add_argument("--result-index", type=int)
    _add_repository_option(sarif)

    index = commands.add_parser("index", help="snapshot and index a repository or archive")
    index.add_argument("repository", type=_path)
    index.add_argument("--output", "-o", type=_path, required=True)

    rank = commands.add_parser("rank", help="rank indexed files and symbols")
    rank.add_argument("--finding", type=_path, required=True)
    rank.add_argument("--index", type=_path, required=True)
    rank.add_argument("--output", "-o", type=_path, required=True)
    rank.add_argument("--top-k", type=int, default=20)

    localize = commands.add_parser(
        "localize",
        help="run the label-blind role-aware V0.4.1 pre-release localizer",
    )
    localize.add_argument("--finding", type=_path, required=True)
    localize.add_argument("--repository", type=_path, required=True)
    localize.add_argument("--output", "-o", type=_path, required=True)
    localize.add_argument(
        "--ranker",
        choices=(
            "role-aware-sparse-v0.4.1.1",
            "role-aware-sparse-v0.4.1.2",
            "role-aware-sparse-v0.4.1.3",
            "structured-role-sparse-v0.4.1.4",
            LEARNED_RANKER,
        ),
        default=DEFAULT_RANKER,
    )
    localize.add_argument("--top-k", type=int, default=1000)
    localize.add_argument(
        "--maximum-candidates",
        type=int,
        default=STEP1_MAXIMUM_CANDIDATES,
        help=(
            "bounded candidate inventory; any truncation forces a machine-readable "
            "ranking abstention"
        ),
    )
    localize.add_argument("--model", type=_path)

    reproduce = commands.add_parser("reproduce", help="run a plan in a network-denied OCI sandbox")
    reproduce.add_argument("--repository", type=_path, required=True)
    reproduce.add_argument("--plan", type=_path, required=True)
    reproduce.add_argument("--image", required=True)
    reproduce.add_argument("--output", "-o", type=_path, required=True)

    trace = commands.add_parser("trace", help="run the complete evidence pipeline")
    trace.add_argument("--finding", type=_path, required=True)
    trace.add_argument("--finding-format", choices=("manual", "sarif", "normalized"), required=True)
    trace.add_argument("--repository", type=_path, required=True)
    trace.add_argument("--output", "-o", type=_path, required=True)
    trace.add_argument("--plan", type=_path)
    trace.add_argument("--image")
    trace.add_argument("--top-k", type=int, default=20)
    trace.add_argument("--run-index", type=int)
    trace.add_argument("--result-index", type=int)

    export = commands.add_parser("export-sarif", help="export an evidence bundle as SARIF 2.1.0")
    export.add_argument("bundle", type=_path)
    export.add_argument("--output", "-o", type=_path, required=True)

    validate = commands.add_parser("validate", help="validate a Lumi Trace JSON contract")
    validate.add_argument("input", type=_path)

    verify = commands.add_parser("verify", help="verify a bundle or evidence package")
    verify.add_argument("input", type=_path)
    return parser


def _import_sarif(args: argparse.Namespace) -> None:
    findings = import_sarif(
        args.input,
        run_index=args.run_index,
        result_index=args.result_index,
        repository_root=args.repository,
    )
    if not findings:
        raise InputError("SARIF selection contains no findings")
    if len(findings) == 1 and args.output.suffix.lower() == ".json":
        dump_json(args.output, findings[0])
        _write_summary(findings=1, output=str(args.output))
        return
    args.output.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, object]] = []
    for finding in findings:
        source = finding["source"]
        name = f"finding-{source['sarif_run_index']:03d}-{source['sarif_result_index']:05d}.json"
        destination = args.output / name
        dump_json(destination, finding)
        artifacts.append({"path": name, "sha256": sha256_file(destination)})
    manifest: dict[str, object] = {
        "schema_version": "normalized-finding-collection-v1",
        "artifacts": artifacts,
    }
    manifest["manifest_id"] = stable_id("finding-collection", manifest)
    dump_json(args.output / "manifest.json", manifest)
    _write_summary(findings=len(findings), output=str(args.output))


def _validate_document(path: Path) -> str:
    value = load_json(path)
    if not isinstance(value, dict):
        raise InputError("contract document must be a JSON object")
    version = value.get("schema_version")
    if version == "normalized-finding-v1":
        validate_normalized_finding(value)
    elif version == "evidence-bundle-v1":
        verify_evidence_bundle(value)
    elif version == "repository-index-v1":
        verify_repository_index(value)
    elif version == "candidate-set-v1":
        verify_candidate_set(value)
    elif version == REQUEST_SCHEMA:
        validate_inference_request(value)
    elif version == RAW_OUTPUT_SCHEMA:
        verify_raw_localization(value)
    elif version in {"reproduction-plan-v1", "reproduction-receipt-v1"}:
        if version == "reproduction-plan-v1":
            validate_reproduction_plan(value)
        else:
            verify_reproduction_receipt(value)
    else:
        raise InputError(f"unsupported schema_version: {version!r}")
    return str(version)


def _verify_package(path: Path) -> None:
    if path.is_file():
        bundle = load_bundle(path)
        verify_evidence_bundle(bundle)
        return
    if path.is_symlink() or not path.is_dir():
        raise InputError("evidence package path must be a regular directory or bundle file")
    manifest_path = path / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise InputError("evidence package manifest is missing or unsafe")
    manifest = load_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "artifacts", "manifest_id"}
        or manifest.get("schema_version") != "evidence-package-manifest-v1"
    ):
        raise InputError("directory has no evidence-package-manifest-v1")
    expected = stable_id("evidence-package", manifest, omit_keys=("manifest_id",))
    if manifest.get("manifest_id") != expected:
        raise InputError("evidence package manifest identity mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not 5 <= len(artifacts) <= 7:
        raise InputError("evidence package must declare five to seven artifacts")
    required = {
        "normalized-finding.json",
        "repository-index.json",
        "candidates.json",
        "evidence-bundle.json",
        "evidence.sarif",
    }
    reproduction_artifacts = {"reproduction-plan.json", "reproduction-receipt.json"}
    allowed = required | reproduction_artifacts
    expected_files: set[str] = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256", "size_bytes"}
            or not isinstance(artifact.get("path"), str)
            or not isinstance(artifact.get("sha256"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["sha256"]) is None
            or isinstance(artifact.get("size_bytes"), bool)
            or not isinstance(artifact.get("size_bytes"), int)
            or artifact["size_bytes"] < 0
        ):
            raise InputError("evidence package artifact entry is invalid")
        name = artifact["path"]
        relative = PurePosixPath(name)
        if relative.is_absolute() or len(relative.parts) != 1 or name not in allowed:
            raise InputError(f"evidence package artifact path is invalid: {name}")
        if name in expected_files:
            raise InputError(f"duplicate evidence package artifact: {name}")
        expected_files.add(name)
        candidate = path / name
        if candidate.is_symlink() or not candidate.is_file():
            raise InputError(f"evidence package artifact is missing or unsafe: {name}")
        if sha256_file(candidate) != artifact.get("sha256"):
            raise InputError(f"evidence package artifact hash mismatch: {name}")
        if candidate.stat().st_size != artifact.get("size_bytes"):
            raise InputError(f"evidence package artifact size mismatch: {name}")
    if not required.issubset(expected_files):
        raise InputError("evidence package is missing required artifacts")
    if bool(expected_files & reproduction_artifacts) and not reproduction_artifacts.issubset(
        expected_files
    ):
        raise InputError("evidence package must contain both reproduction plan and receipt")
    actual_files = {item.name for item in path.iterdir() if item.is_file()}
    if any(item.is_dir() or item.is_symlink() for item in path.iterdir()):
        raise InputError("evidence package contains an unexpected directory or symbolic link")
    if actual_files != expected_files | {"manifest.json"}:
        raise InputError("evidence package contains unmanifested or missing files")
    bundle = load_bundle(path / "evidence-bundle.json")
    verify_evidence_bundle(bundle)
    finding = load_json(path / "normalized-finding.json")
    index = load_json(path / "repository-index.json")
    candidates = load_json(path / "candidates.json")
    sarif = load_json(path / "evidence.sarif")
    if not all(isinstance(item, dict) for item in (finding, index, candidates, sarif)):
        raise InputError("evidence package contains a non-object contract")
    validate_normalized_finding(finding)
    verify_repository_index(index)
    verify_candidate_set(candidates)
    if bundle.get("finding") != finding:
        raise InputError("evidence bundle finding does not match normalized-finding.json")
    bundle_repository = (
        bundle.get("repository") if isinstance(bundle.get("repository"), dict) else {}
    )
    if index.get("repository") != bundle_repository:
        raise InputError("evidence bundle repository does not match repository-index.json")
    expected_index_summary = {
        key: index.get(key)
        for key in (
            "index_id",
            "algorithm",
            "file_count",
            "indexed_text_file_count",
            "symbol_count",
            "exclusions",
        )
    }
    if bundle.get("index") != expected_index_summary:
        raise InputError("evidence bundle index summary does not match repository-index.json")
    if candidates.get("finding_id") != finding.get("finding_id"):
        raise InputError("candidate set finding identity mismatch")
    if candidates.get("index_id") != index.get("index_id"):
        raise InputError("candidate set index identity mismatch")
    if bundle.get("candidates") != candidates.get("candidates"):
        raise InputError("evidence bundle candidates do not match candidates.json")
    expected_ranking = None
    if "candidate_algorithm" in candidates:
        expected_ranking = {
            "ranker": candidates.get("algorithm"),
            "candidate_algorithm": candidates.get("candidate_algorithm"),
            "ranking_id": candidates.get("ranking_id"),
            "candidate_count_considered": candidates.get("candidate_count_considered"),
            "candidates_emitted": len(candidates.get("candidates", [])),
            "score_basis": "DETERMINISTIC_INTEGER_COMPONENTS_WITH_ROLE_PRIORS",
            "roles_emitted": sorted(
                {
                    candidate["role"]
                    for candidate in candidates.get("candidates", [])
                    if isinstance(candidate, dict) and isinstance(candidate.get("role"), str)
                }
            ),
            "abstention": candidates.get("abstention"),
            "confidence_descriptor": candidates.get("confidence_descriptor"),
            "confidence_is_not_probability": True,
        }
    if bundle.get("ranking") != expected_ranking:
        raise InputError("evidence bundle ranking does not match candidates.json")
    provenance = bundle.get("provenance") if isinstance(bundle.get("provenance"), dict) else {}
    if (
        provenance.get("repository_manifest_id") != bundle_repository.get("manifest_id")
        or provenance.get("finding_input_sha256") != finding.get("source", {}).get("input_sha256")
        or provenance.get("index_id") != index.get("index_id")
        or provenance.get("candidate_set_id") != candidates.get("candidate_set_id")
    ):
        raise InputError("evidence bundle provenance identities are inconsistent")

    receipt = None
    if "reproduction-receipt.json" in expected_files:
        plan = load_json(path / "reproduction-plan.json")
        receipt = load_json(path / "reproduction-receipt.json")
        if not isinstance(plan, dict) or not isinstance(receipt, dict):
            raise InputError("reproduction plan and receipt must be JSON objects")
        normalized_plan = validate_reproduction_plan(plan)
        if normalized_plan != plan:
            raise InputError("packaged reproduction plan is not canonical")
        verify_reproduction_receipt(receipt)
        if receipt.get("plan_id") != plan_identity(plan):
            raise InputError("reproduction receipt does not match reproduction-plan.json")
        if receipt.get("repository_identity") != bundle_repository.get("repository_id"):
            raise InputError("reproduction receipt repository identity mismatch")
        receipt_steps = receipt["steps"]
        plan_steps = plan["steps"]
        if len(receipt_steps) > len(plan_steps) or (
            receipt.get("status") == "COMPLETED" and len(receipt_steps) != len(plan_steps)
        ):
            raise InputError("reproduction receipt step count does not match its plan")
        for index, observed in enumerate(receipt_steps):
            declared = plan_steps[index]
            if (
                observed.get("index") != index
                or observed.get("cwd") != declared.get("cwd")
                or observed.get("argv_id") != canonical_sha256(declared.get("argv"))
                or observed.get("expect_id") != canonical_sha256(declared.get("expect"))
            ):
                raise InputError("reproduction receipt step does not match its declared plan")
            declared_expect = declared["expect"]
            witness = observed["witness"]
            predicate_values: list[bool] = []
            for predicate in ("exit_code", "stdout_contains", "stderr_contains"):
                witness_value = witness[predicate]
                if predicate in declared_expect:
                    if not isinstance(witness_value, bool):
                        raise InputError("reproduction witness omits a declared predicate")
                    predicate_values.append(witness_value)
                elif witness_value is not None:
                    raise InputError("reproduction witness asserts an undeclared predicate")
            if "exit_code" in declared_expect and witness["exit_code"] != (
                observed.get("exit_code") == declared_expect["exit_code"]
            ):
                raise InputError("reproduction exit-code witness is inconsistent")
            if witness["matched"] != (bool(predicate_values) and all(predicate_values)):
                raise InputError("reproduction witness aggregate is inconsistent")
    reproduction = (
        bundle.get("reproduction") if isinstance(bundle.get("reproduction"), dict) else {}
    )
    if reproduction.get("requested") is not (receipt is not None):
        raise InputError("evidence bundle reproduction request state is inconsistent")
    if reproduction.get("receipts") != ([receipt] if receipt is not None else []):
        raise InputError("evidence bundle reproduction receipt is inconsistent")
    if receipt is not None and (
        reproduction.get("plan_id") != receipt.get("plan_id")
        or reproduction.get("policy_id") != receipt.get("policy_id")
        or reproduction.get("sandbox_qualified")
        is not bool(receipt.get("sandbox", {}).get("qualified"))
    ):
        raise InputError("evidence bundle reproduction provenance is inconsistent")
    expected_classification = classify_evidence(
        reproduction_requested=receipt is not None, receipt=receipt
    )
    if bundle.get("classification") != expected_classification:
        raise InputError("evidence bundle classification does not match its receipt")

    expected_sarif = export_sarif(bundle)
    if sarif != expected_sarif:
        raise InputError("evidence SARIF does not match the evidence bundle")


def dispatch(args: argparse.Namespace) -> None:
    if args.command == "version":
        _write_summary(
            name="Lumi Trace",
            version=__version__,
            inventory_id="skylark.lumi.trace",
            model_status="DEVELOPMENT_RUNTIME_NO_PACKAGED_WEIGHTS",
            checkpoint=None,
            current_weights=0,
        )
    elif args.command == "status":
        status = DockerSandbox(image=args.image).status()
        _write_summary(
            version=__version__,
            checkpoint=None,
            current_weights=0,
            api_keys_required=False,
            hosted_inference=False,
            sandbox=status,
        )
    elif args.command == "import-manual":
        finding = import_manual(args.input, args.repository)
        dump_json(args.output, finding)
        _write_summary(finding_id=finding["finding_id"], output=str(args.output))
    elif args.command == "import-sarif":
        _import_sarif(args)
    elif args.command == "index":
        with RepositoryWorkspace(args.repository) as workspace:
            index = build_repository_index(workspace.root, workspace.identity)
        dump_json(args.output, index)
        _write_summary(index_id=index["index_id"], output=str(args.output))
    elif args.command == "rank":
        finding = load_normalized_finding(args.finding)
        index = load_json(args.index)
        if not isinstance(index, dict):
            raise InputError("index must be a JSON object")
        result = rank_candidates(finding, index, top_k=args.top_k)
        dump_json(args.output, result)
        _write_summary(candidate_set_id=result["candidate_set_id"], output=str(args.output))
    elif args.command == "localize":
        finding = load_normalized_finding(args.finding)
        artifact_sha256, source_kind = repository_artifact_identity(args.repository)
        model = None
        if args.model is not None:
            loaded_model = load_json(args.model)
            if not isinstance(loaded_model, dict):
                raise InputError("localization model must be a JSON object")
            model = verify_model_artifact(loaded_model)
        request = construct_inference_request(
            finding=finding,
            repository_artifact_sha256=artifact_sha256,
            source_kind=source_kind,
            ranker=args.ranker,
            top_k=args.top_k,
            maximum_candidates=args.maximum_candidates,
            model_artifact=model,
        )
        result = build_raw_localization(
            request,
            repository_source=args.repository,
            model_artifact=model,
        )
        dump_json(args.output, result)
        _write_summary(
            raw_output_seal=result["raw_output_seal"],
            ranking_id=result["ranking_id"],
            abstained=result["abstention"]["abstained"],
            output=str(args.output),
        )
    elif args.command == "reproduce":
        plan = load_reproduction_plan(args.plan)
        with RepositoryWorkspace(args.repository) as workspace:
            receipt = DockerSandbox(image=args.image).run(
                workspace.root, str(workspace.identity["repository_id"]), plan
            )
        dump_json(args.output, receipt)
        _write_summary(receipt_id=receipt["receipt_id"], status=receipt["status"])
    elif args.command == "trace":
        result = trace_repository(
            finding_path=args.finding,
            finding_format=args.finding_format,
            repository_source=args.repository,
            output_directory=args.output,
            reproduction_plan_path=args.plan,
            image=args.image,
            top_k=args.top_k,
            run_index=args.run_index,
            result_index=args.result_index,
        )
        _write_trace_summary(result)
    elif args.command == "export-sarif":
        bundle = load_bundle(args.bundle)
        sarif = export_sarif(bundle)
        dump_json(args.output, sarif)
        _write_summary(bundle_id=bundle["bundle_id"], output=str(args.output))
    elif args.command == "validate":
        version = _validate_document(args.input)
        _write_summary(valid=True, schema_version=version, input=str(args.input))
    elif args.command == "verify":
        _verify_package(args.input)
        _write_summary(valid=True, input=str(args.input))
    else:  # pragma: no cover - argparse enforces the command set
        raise InputError(f"unknown command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        dispatch(args)
    except (LumiTraceError, ValueError, OSError) as exc:
        print(f"lumi-trace: {exc}", file=sys.stderr)
        hint = _actionable_hint(exc)
        if hint:
            print(f"hint: {hint}", file=sys.stderr)
        return getattr(exc, "exit_code", 2)
    return 0
