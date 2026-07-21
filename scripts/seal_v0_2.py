# SPDX-License-Identifier: Apache-2.0
"""Seal public-safe V0.2 synthetic evaluation evidence from governed packages."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from trace_eval.canonical import dump_json, load_json, sha256_file, stable_id
from trace_eval.contracts import validate_record
from trace_eval.metrics import verify_scored_package
from trace_eval.package import verify_package
from trace_eval.policy import verify_public_document
from trace_eval.runner import load_run_package

ROOT = Path(__file__).resolve().parents[1]


def _copy_record(source: Path, destination: Path) -> dict[str, Any]:
    value = load_json(source)
    if not isinstance(value, dict):
        raise ValueError(f"expected an object: {source.name}")
    validate_record(value)
    verify_public_document(value)
    shutil.copyfile(source, destination)
    return value


def seal(args: argparse.Namespace) -> dict[str, Any]:
    output: Path = args.output
    if output.exists():
        raise ValueError("refusing to overwrite an existing V0.2 evidence seal")
    run_record, _, run_manifest = load_run_package(args.run_package)
    scored_manifest = verify_scored_package(args.scored_package)
    replay_manifest = verify_package(args.replay_package)
    readiness_manifest = verify_package(args.readiness_package)
    environment = load_json(args.environment_record)
    public_summary = load_json(args.scored_package / "public-summary.json")
    if not isinstance(environment, dict) or not isinstance(public_summary, dict):
        raise ValueError("environment and public summary must be objects")
    validate_record(environment)
    verify_public_document(public_summary)
    evaluator_hash = sha256_file(args.evaluator_artifact)
    expected_evaluator = environment["payload"]["evaluator"]["artifact_sha256"]
    if evaluator_hash != expected_evaluator:
        raise ValueError("evaluator artifact differs from the qualified environment")

    output.mkdir(parents=True)
    dump_json(output / "public-summary.json", public_summary)
    qualification = _copy_record(
        args.readiness_package / "qualification-decision.json",
        output / "qualification-decision.json",
    )
    readiness = _copy_record(
        args.readiness_package / "training-readiness-decision.json",
        output / "training-readiness-decision.json",
    )
    facts = environment["payload"]["facts"]
    environment_summary = {
        "schema_version": "trace-eval-public-environment-summary-v1",
        "environment_id": environment["record_id"],
        "environment": environment["payload"]["environment"],
        "os": facts["os"],
        "architecture": facts["architecture"],
        "python": facts["python"],
        "docker_available": facts["docker"]["available"],
        "sut": environment["payload"]["sut"],
        "evaluator": environment["payload"]["evaluator"],
        "machine_paths_excluded": True,
    }
    verify_public_document(environment_summary)
    dump_json(output / "environment-summary.json", environment_summary)
    provenance = {
        "schema_version": "trace-eval-public-baseline-provenance-v1",
        "source_revision": args.source_revision,
        "run_id": run_record["payload"]["run_id"],
        "run_package_id": run_manifest["package_id"],
        "scored_package_id": scored_manifest["package_id"],
        "replay_package_id": replay_manifest["package_id"],
        "readiness_package_id": readiness_manifest["package_id"],
        "qualification_decision_id": qualification["record_id"],
        "training_readiness_decision_id": readiness["record_id"],
        "runtime_artifact_sha256": environment["payload"]["sut"]["artifact_sha256"],
        "evaluator_artifact_sha256": evaluator_hash,
        "inputs": "SKYLARK_AUTHORED_PUBLIC_SYNTHETIC_ONLY",
        "natural_performance_claim": False,
        "holdback_opened": False,
        "training_started": False,
        "weights_downloaded": False,
    }
    verify_public_document(provenance)
    dump_json(output / "baseline-provenance.json", provenance)
    review = {
        "schema_version": "trace-eval-public-boundary-review-v1",
        "review_type": "CONTROLLED_INTERNAL_RELEASE_REVIEW",
        "scope": "public synthetic V0.2 evidence candidate",
        "source_or_private_paths_present": False,
        "third_party_repository_substance_present": False,
        "customer_or_protected_evidence_present": False,
        "model_weights_or_training_data_present": False,
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "trace_001_decision": "NO_GO",
    }
    dump_json(output / "public-boundary-review.json", review)

    artifacts = [
        {
            "path": path.relative_to(output).as_posix(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(output.iterdir())
        if path.is_file()
    ]
    manifest: dict[str, Any] = {
        "schema_version": "lumi-trace-v0.2-public-evidence-seal-v1",
        "source_revision": args.source_revision,
        "artifacts": artifacts,
    }
    manifest["seal_id"] = stable_id("lumi-trace-v0.2-public-evidence", manifest)
    dump_json(output / "seal-manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-record", type=Path, required=True)
    parser.add_argument("--evaluator-artifact", type=Path, required=True)
    parser.add_argument("--run-package", type=Path, required=True)
    parser.add_argument("--scored-package", type=Path, required=True)
    parser.add_argument("--replay-package", type=Path, required=True)
    parser.add_argument("--readiness-package", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "v0.2.0")
    args = parser.parse_args()
    manifest = seal(args)
    print(manifest["seal_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
