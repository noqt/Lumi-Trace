# SPDX-License-Identifier: Apache-2.0
"""Build governed V0.4.1 integrity-remediation evidence.

The script keeps builder artifacts on F:, scorer/custodian material on G:, and
never materializes the protected holdback for inference.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from lumi_trace.canonical import (
    canonical_json_bytes as runtime_canonical_bytes,
)
from lumi_trace.canonical import (
    dump_json as runtime_dump_json,
)
from lumi_trace.canonical import (
    load_json as runtime_load_json,
)
from lumi_trace.canonical import (
    sha256_bytes as runtime_sha256_bytes,
)
from lumi_trace.canonical import (
    sha256_file as runtime_sha256_file,
)
from lumi_trace.canonical import (
    stable_id as runtime_stable_id,
)
from lumi_trace.findings import _finalize_finding
from lumi_trace.learned_ranker import LEARNED_RANKER, verify_model_artifact
from lumi_trace.localization import (
    CANDIDATE_ALGORITHM,
    QUARANTINE_POLICY,
    RAW_OUTPUT_SCHEMA,
    REQUEST_SCHEMA,
    RUNTIME_IDENTITY,
    build_access_policy,
    construct_inference_request,
    information_flow_manifest,
    verify_raw_localization,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = PROJECT_ROOT / "eval" / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.baselines import aggregate_v04  # noqa: E402
from trace_eval.canonical import dump_json, load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.corpus import is_python_production  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.integrity_v041 import (  # noqa: E402
    make_scoring_labels,
    score_sealed_localization,
)

from scripts.build_v0_4_assurance import (  # noqa: E402
    _fetch_fixes,
    _initialise_bare_repository,
    _load_advisory_inputs,
    _patch_for_path,
    _process_candidate,
    _read_blob_at,
    _tree_entries,
)
from scripts.run_v0_4_experiments import _batch_blobs  # noqa: E402

STARTING_REVISION = "c93d3c792190435cb82e28f01af532be97d9a06a"
STARTING_SEAL = (
    "lumi-trace-v0.4-public-evidence:"
    "d5404d104a946046cfce4439e338c8bef9223331f93057a2c3e87e47a4553c3a"
)
V04_STATUS_ID = (
    "v0.4-current-status:fc8988a3fda087148e3a939ec6ca7e5086902a602450f5eff9ef003be4097ae3"
)
V04_CHECKPOINT_ID = (
    "trace-001-linear-checkpoint:aa040fc8edcfbee04d3cce769e5f30c73ab991cca19e3708331adbc212ab4a93"
)
METRIC_SPECIFICATION_ID = "v0.4.1-locked-capability-gates-v1"
TIMESTAMP = "2026-07-26T00:00:00Z"
PARTITION_SLUG = {
    "TRAINING": "training",
    "ENGINEERING_DEVELOPMENT": "engineering-development",
    "MODEL_SELECTION": "model-selection",
    "QUALIFICATION": "qualification",
}


def _require_root(path: Path, drive: str, *, create: bool = False) -> Path:
    resolved = path.resolve(strict=not create)
    if resolved.drive.casefold() != drive.casefold():
        raise ValueError(f"path must remain on {drive}")
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError(f"required governed root is missing: {resolved}")
    return resolved


def _write_once(path: Path, value: Any) -> None:
    if path.exists():
        if load_json(path) != value:
            raise ContractError(f"append-only artifact differs: {path.name}")
        return
    dump_json(path, value)


def _git_head() -> str:
    return subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _public_evidence_members() -> list[dict[str, Any]]:
    root = PROJECT_ROOT / "evidence" / "v0.4"
    return [
        {
            "path": path.relative_to(PROJECT_ROOT).as_posix(),
            "sha256": runtime_sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(root.glob("*.json"))
    ]


def bootstrap(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:", create=True)
    work_root = _require_root(args.work_root, "F:", create=True)
    predecessor = _require_root(args.predecessor_root, "G:")
    if _git_head() != STARTING_REVISION:
        raise PolicyError("V0_4_1_STARTING_REVISION_MISMATCH")
    verifier = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "verify_v0_4_evidence.py"),
            str(PROJECT_ROOT / "evidence" / "v0.4"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if verifier.stdout.strip() != STARTING_SEAL:
        raise PolicyError("V0_4_1_STARTING_SEAL_MISMATCH")
    prior_status = load_json(predecessor / "manifests" / "current-status-final.json")
    prior_partition = load_json(predecessor / "manifests" / "final-partition-seal.json")
    if (
        prior_status.get("status_id") != V04_STATUS_ID
        or prior_status.get("holdback_opened") is not False
        or prior_partition.get("payload", {}).get("holdback_state") != "SEALED_UNOPENED"
    ):
        raise PolicyError("V0_4_1_PREDECESSOR_PRIVATE_STATE_MISMATCH")

    for relative in (
        "builder/archives",
        "builder/logs",
        "builder/policies",
        "builder/raw",
        "builder/requests",
        "builder/tmp",
        "reports",
    ):
        (work_root / relative).mkdir(parents=True, exist_ok=True)
    for relative in (
        "custodian",
        "invalidation",
        "ledgers",
        "manifests",
        "scorer/labels",
        "scorer/results",
        "semantic-review/pass-a",
        "semantic-review/pass-b",
        "semantic-review/resolution",
        "superseded-invalid-evidence",
    ):
        (private_root / relative).mkdir(parents=True, exist_ok=True)

    controlled_review = {
        "schema_version": "lumi-trace-v0.4.1-controlled-review-invalidation-v1",
        "predecessor_revision": STARTING_REVISION,
        "predecessor_public_evidence_seal": STARTING_SEAL,
        "predecessor_private_status_id": V04_STATUS_ID,
        "finding": {
            "severity": "CRITICAL_EXPERIMENTAL_INTEGRITY",
            "category": "GROUND_TRUTH_TARGET_ACCESS_BEFORE_RAW_RANKING_SEAL",
            "affected_policy": "v0.4-path-quarantine-except-labelled-target-v2",
            "observed_overrides": {
                "training": 114,
                "engineering_development": 11,
                "model_selection": 37,
                "qualification": 21,
            },
            "qualification_disposition": "SPENT_INVALID_FOR_CAPABILITY_DECISION",
            "closure_disposition": "REVIEW_FAIL_REMEDIATION_REQUIRED",
        },
        "historical_evidence_rewritten": False,
        "predecessor_public_members": _public_evidence_members(),
        "created_at": TIMESTAMP,
    }
    controlled_review["record_id"] = stable_id(
        "v0.4.1-controlled-review-invalidation", controlled_review
    )
    _write_once(
        private_root / "invalidation" / "controlled-review.json",
        controlled_review,
    )

    disposition = {
        "schema_version": "lumi-trace-v0.4.1-predecessor-artifact-disposition-v1",
        "predecessor_record_id": controlled_review["record_id"],
        "reusable_after_identity_verification": [
            "immutable_repository_objects",
            "public_source_acquisition_receipts",
            "rights_and_licence_evidence",
            "source_candidate_registers",
            "advisory_and_fixing_evidence",
            "repository_family_lineage",
            "duplicate_fingerprints",
            "poison_secret_privacy_audits",
            "group_source_provenance",
        ],
        "provisionally_reusable_after_semantic_audit": ["labels"],
        "superseded_invalid_evidence": [
            "candidate_caches",
            "candidate_set_identities",
            "target_indexability_results",
            "training_features",
            "development_features_and_baselines",
            "model_selection_features_and_baselines",
            "trace_001_training_pairs",
            V04_CHECKPOINT_ID,
            "trace_001_int8_projection",
            "model_selection_comparisons",
            "qualification_raw_rankings",
            "qualification_aggregates_and_decision",
            "qualification_readiness_claims",
            "pilot_readiness_claims",
        ],
        "partition_disposition": {
            "training": "REGENERATE_FROM_ALLOWED_INPUTS",
            "engineering_development": "REGENERATE_FROM_ALLOWED_INPUTS",
            "model_selection": "EXPOSED_ENGINEERING_DIAGNOSTIC",
            "qualification": "SPENT_INVALID_AUDIT_ONLY",
            "protected_holdback": "SEALED_UNOPENED",
        },
        "predecessor_artifacts_deleted": False,
        "predecessor_artifacts_relabelled_clean": False,
    }
    disposition["manifest_id"] = stable_id("v0.4.1-predecessor-artifact-disposition", disposition)
    _write_once(
        private_root / "invalidation" / "artifact-disposition.json",
        disposition,
    )

    roles = {
        "schema_version": "lumi-trace-v0.4.1-role-separation-v1",
        "builder": {
            "root": "F:/GOVERNED_WORK_ROOT/builder",
            "inputs": [REQUEST_SCHEMA, "immutable_repository_archive"],
            "outputs": [RAW_OUTPUT_SCHEMA],
            "may_read_scorer": False,
            "may_read_custodian": False,
            "may_read_fixed_revision": False,
        },
        "scorer": {
            "root": "G:/GOVERNED_PRIVATE_ROOT/scorer",
            "inputs": [RAW_OUTPUT_SCHEMA, "private_scoring_labels"],
            "requires_verified_raw_output_seal": True,
            "may_mutate_raw_output": False,
        },
        "qualification_custodian": {
            "root": "G:/GOVERNED_PRIVATE_ROOT/custodian",
            "capacity": 1,
            "releases_case_content_to_builder": False,
            "releases_only_approved_aggregates": True,
        },
        "same_operator_allowed": True,
        "technical_separation": "DISTINCT_PROCESS_AND_WORK_ROOTS",
    }
    roles["record_id"] = stable_id("v0.4.1-role-separation", roles)
    _write_once(private_root / "manifests" / "role-separation.json", roles)

    flow = information_flow_manifest()
    _write_once(private_root / "manifests" / "information-flow.json", flow)
    quarantine = {
        "schema_version": "lumi-trace-v0.4.1-target-agnostic-quarantine-policy-v1",
        "policy_id": QUARANTINE_POLICY,
        "inputs": [
            "repository_relative_path",
            "file_kind",
            "file_size",
            "utf8_decodability",
            "source_visible_high_confidence_secret_pattern",
        ],
        "forbidden_inputs": [
            "target_path",
            "target_symbol",
            "target_region",
            "fixed_revision",
            "private_label",
            "partition_outcome",
        ],
        "target_exception": False,
        "non_indexable_targets_counted": True,
        "policy_change_invalidates_cache": True,
    }
    quarantine["record_id"] = stable_id("v0.4.1-target-agnostic-quarantine-policy", quarantine)
    _write_once(private_root / "manifests" / "quarantine-policy.json", quarantine)
    holdback = {
        "schema_version": "lumi-trace-v0.4.1-holdback-non-access-attestation-v1",
        "predecessor_partition_seal_sha256": sha256_file(
            predecessor / "manifests" / "final-partition-seal.json"
        ),
        "predecessor_status_id": prior_status["status_id"],
        "state": "SEALED_UNOPENED",
        "case_content_read": False,
        "inference_materialized": False,
        "candidate_generation_run": False,
        "preview_or_per_family_metric_generated": False,
    }
    holdback["attestation_id"] = stable_id("v0.4.1-holdback-non-access-attestation", holdback)
    _write_once(private_root / "custodian" / "holdback-non-access.json", holdback)
    status = {
        "schema_version": "lumi-trace-v0.4.1-current-status-v1",
        "predecessor_status_id": V04_STATUS_ID,
        "evidence_integrity": "RESTORATION_IN_PROGRESS",
        "data_readiness": "AUDIT_AND_REGENERATION_REQUIRED",
        "candidate_generation_readiness": "IMPLEMENTED_NOT_MEASURED",
        "ranking_readiness": "DEVELOPMENT_REQUIRED",
        "product_runtime_readiness": "IMPLEMENTED_NOT_QUALIFIED",
        "model_selection_readiness": "NOT_READY",
        "qualification_readiness": "NOT_READY",
        "release_readiness": "NOT_READY",
        "closure": "INTEGRITY_RESTORED / DEVELOPMENT_CONTINUES",
        "qualification_consumed": False,
        "holdback_opened": False,
    }
    status["status_id"] = stable_id("v0.4.1-current-status", status)
    _write_once(private_root / "current-status.json", status)
    return {
        "controlled_review_id": controlled_review["record_id"],
        "artifact_disposition_id": disposition["manifest_id"],
        "information_flow_id": flow["manifest_id"],
        "holdback_attestation_id": holdback["attestation_id"],
        "status_id": status["status_id"],
    }


def _normalized_finding(finding: dict[str, Any]) -> dict[str, Any]:
    summary = str(finding.get("summary", "")).strip()
    description = str(finding.get("description", "")).strip()
    advisory = str(finding.get("advisory_identifier", "")).strip() or "unknown"
    aliases = sorted(
        {
            str(item).strip()
            for item in finding.get("aliases", [])
            if isinstance(item, str) and str(item).strip()
        }
    )
    packages = sorted(
        {
            token.casefold()
            for item in finding.get("packages", [])
            if isinstance(item, str)
            for token in re.findall(r"[A-Za-z][A-Za-z0-9]{1,63}", item)
        }
    )
    payload: dict[str, Any] = {
        "schema_version": "normalized-finding-v1",
        "source": {
            "kind": "MANUAL",
            "input_sha256": runtime_sha256_bytes(runtime_canonical_bytes(finding)),
        },
        "rule": {
            "id": advisory,
            "name": summary or advisory,
            "cwes": [],
            "tags": aliases,
        },
        "message": {
            "title": summary or advisory,
            "text": description or summary or advisory,
        },
        "severity": {"normalized": "UNKNOWN", "original": "unknown"},
        "locations": [],
        "keywords": packages,
        "fingerprints": {},
    }
    return _finalize_finding(payload, None)


def _receipt_map(predecessor: Path, partition: str) -> dict[str, dict[str, Any]]:
    slug = PARTITION_SLUG[partition]
    result: dict[str, dict[str, Any]] = {}
    root = predecessor / "runs" / "private" / "intake" / slug
    for path in sorted(root.glob("*.json")):
        receipt = load_json(path)
        result[receipt["group_audit_card_id"]] = receipt
    return result


def _card_map(predecessor: Path, partition: str) -> dict[str, dict[str, Any]]:
    slug = PARTITION_SLUG[partition]
    return {
        card["record_id"]: card
        for path in sorted((predecessor / "manifests" / "audit-cards" / slug).glob("*.json"))
        for card in [load_json(path)]
    }


def _safe_snapshot_archive(
    *,
    bare_repository: Path,
    hooks_directory: Path,
    revision: str,
    output: Path,
) -> str:
    if output.is_file():
        return runtime_sha256_file(output)
    entries = [
        item
        for item in _tree_entries(
            bare_repository,
            revision,
            hooks_directory=hooks_directory,
        )
        if item.object_type == "blob"
        and item.mode in {"100644", "100755"}
        and item.size_bytes is not None
        and item.size_bytes <= 2 * 1024 * 1024
        and Path(item.path).suffix.casefold() == ".py"
    ]
    total = sum(int(item.size_bytes) for item in entries)
    if len(entries) > 100_000 or total > 2 * 1024 * 1024 * 1024:
        raise PolicyError("V0_4_1_SNAPSHOT_BOUND_REJECTED")
    object_bytes = _batch_blobs(
        bare_repository,
        [item.object_id for item in entries],
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for item in sorted(entries, key=lambda entry: entry.path.encode("utf-8")):
            info = zipfile.ZipInfo(item.path, date_time=(2000, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, object_bytes[item.object_id])
    temporary.replace(output)
    return runtime_sha256_file(output)


def _target_symbol_resolves(source: str, symbol: str | None) -> bool:
    if not symbol:
        return True
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False
    names = {
        str(node.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    }
    return symbol.split(".")[-1] in names


def _semantic_pass(
    *,
    receipt: dict[str, Any],
    bare_repository: Path,
    hooks_directory: Path,
    pass_name: str,
) -> dict[str, Any]:
    if pass_name not in {"A", "B"}:
        raise ValueError("semantic pass is invalid")
    target_results: list[dict[str, Any]] = []
    for target in receipt["private_targets"]:
        path = target["path"]
        source = _read_blob_at(
            bare_repository,
            receipt["vulnerable_revision"],
            path,
            hooks_directory=hooks_directory,
        ).decode("utf-8")
        region = target["region"]
        patch = _patch_for_path(
            bare_repository,
            receipt["vulnerable_revision"],
            receipt["fixed_revision"],
            path,
            hooks_directory=hooks_directory,
        ).decode("utf-8", errors="replace")
        checks = {
            "production_implementation_path": is_python_production(path),
            "path_changed_by_fix": path in receipt["changed_paths"],
            "region_within_vulnerable_source": (
                1
                <= int(region["start_line"])
                <= int(region["end_line"])
                <= max(1, len(source.splitlines()))
            ),
            "symbol_resolves_in_vulnerable_source": _target_symbol_resolves(
                source,
                target.get("symbol"),
            ),
            "fixing_patch_nonempty": bool(patch.strip()),
            "advisory_finding_nonempty": all(
                str(receipt["finding_input"].get(key, "")).strip()
                for key in ("advisory_identifier", "summary", "description")
            ),
        }
        if pass_name == "B":
            checks = {
                "advisory_and_fix_identity_distinct": (
                    receipt["finding_input_identity"] != runtime_stable_id("fixing-patch", patch)
                ),
                "old_side_contains_target_region": (
                    int(region["start_line"]) <= len(source.splitlines())
                ),
                "implementation_not_harness": (
                    "test" not in {part.casefold() for part in Path(path).parts}
                    and "fixture" not in {part.casefold() for part in Path(path).parts}
                ),
                "symbol_semantics_available": _target_symbol_resolves(
                    source,
                    target.get("symbol"),
                ),
                "patch_changes_production_file": (
                    path in receipt["changed_paths"] and is_python_production(path)
                ),
                "multiple_target_bound_respected": 1 <= len(receipt["private_targets"]) <= 5,
            }
        target_results.append(
            {
                "target_identity": stable_id("semantic-target", target),
                "checks": checks,
                "decision": "ACCEPT" if all(checks.values()) else "QUARANTINE",
            }
        )
    decision = (
        "ACCEPT"
        if target_results and all(item["decision"] == "ACCEPT" for item in target_results)
        else "QUARANTINE"
    )
    value = {
        "schema_version": "lumi-trace-v0.4.1-semantic-label-review-pass-v1",
        "group_id": receipt["candidate_id"],
        "pass": pass_name,
        "workspace": f"ISOLATED_SEMANTIC_REVIEW_{pass_name}",
        "other_pass_visible": False,
        "candidate_ranking_visible": False,
        "model_output_visible": False,
        "partition_metrics_visible": False,
        "inputs": {
            "vulnerable_source_identity": runtime_stable_id(
                "vulnerable-tree", receipt["vulnerable_tree"]
            ),
            "fixing_evidence_identity": runtime_stable_id("fixed-tree", receipt["fixed_tree"]),
            "advisory_identity": receipt["finding_input_identity"],
        },
        "target_results": target_results,
        "decision": decision,
        "reviewer_role": f"CODEX_CONTROLLED_SEMANTIC_REVIEW_{pass_name}",
    }
    value["review_id"] = stable_id("v0.4.1-semantic-label-review", value)
    return value


def _repository_from_source(source: dict[str, Any]) -> str:
    prefix = "https://github.com/"
    url = source.get("payload", {}).get("canonical_source_url")
    if not isinstance(url, str) or not url.casefold().startswith(prefix):
        raise ContractError("V0_4_1_SOURCE_REPOSITORY_URL_REJECTED")
    return url[len(prefix) :].casefold()


def _probe_token(repository: str) -> str:
    return stable_id("repository-probe-token", repository).split(":", 1)[1][:24]


def stage_fresh_sources(args: argparse.Namespace) -> dict[str, Any]:
    """Stage only unused public candidates for a new rights probe."""

    private_root = _require_root(args.private_root, "G:")
    predecessor = _require_root(args.predecessor_root, "G:")
    register = load_json(predecessor / "candidate-source-register" / "candidate-register.json")
    queue = load_json(predecessor / "candidate-source-register" / "acquisition-queue.json")
    unassigned = load_json(predecessor / "manifests" / "unassigned-quarantine-manifest-final.json")
    prior_plan = load_json(
        predecessor / "manifests" / "pre-feature-partition-plan-rebalanced-audited-supply.json"
    )
    used_families = {item["repository_family_id"] for item in prior_plan["assignments"]}
    used_lineages = {
        record["vulnerability_lineage"]
        for path in sorted((predecessor / "fingerprints" / "lineage").glob("*.json"))
        for record in [load_json(path)]
        if "vulnerability_lineage" in record
    }
    unassigned_ids = set(unassigned["candidate_ids"])
    selected = [
        candidate
        for candidate in register["candidates"]
        if candidate["candidate_id"] in unassigned_ids
        and candidate["repository_family_provisional"] not in used_families
        and candidate["vulnerability_lineage_id"] not in used_lineages
    ]
    counts = Counter(candidate["repository"] for candidate in selected)
    fixes: dict[str, set[str]] = {}
    families: dict[str, str] = {}
    for candidate in selected:
        repository = candidate["repository"]
        fixes.setdefault(repository, set()).add(candidate["fixing_revision"])
        families[repository] = candidate["repository_family_provisional"]
    old_approved: set[str] = set()
    for path in sorted((predecessor / "candidate-source-register" / "repositories").glob("*.json")):
        source = load_json(path)
        if source.get("payload", {}).get("decision") == "APPROVE_FOR_QUARANTINE":
            old_approved.add(_repository_from_source(source))
    queue_by_repository = {item["repository"]: item for item in queue["repositories"]}
    staged_queue = []
    for repository in sorted(
        counts,
        key=lambda item: (
            -counts[item],
            stable_id("v0.4.1-rights-probe-order", item),
        ),
    ):
        if repository.casefold() in old_approved:
            continue
        source_item = queue_by_repository[repository]
        staged_queue.append(
            {
                **source_item,
                "candidate_group_count": counts[repository],
                "distinct_fixing_revisions": len(fixes[repository]),
                "provisional_family_id": families[repository],
                "queue_state": "RIGHTS_AND_LICENCE_PROBE_PENDING",
                "attempts": 0,
                "last_error": None,
            }
        )
    staged_register = {
        "schema_version": register["schema_version"],
        "source_archive": register["source_archive"],
        "quarantine_scan_id": register["quarantine_scan_id"],
        "candidate_group_count": len(selected),
        "repository_count": len(counts),
        "state_counts": {"PROPOSED": len(selected)},
        "candidates": selected,
    }
    staged_register["register_id"] = stable_id("v0.4.1-fresh-candidate-register", staged_register)
    staged_queue_record = {
        "schema_version": queue["schema_version"],
        "source_archive_sha256": queue["source_archive_sha256"],
        "repository_count": len(staged_queue),
        "candidate_group_count": sum(item["candidate_group_count"] for item in staged_queue),
        "resumable": True,
        "repositories": staged_queue,
    }
    staged_queue_record["queue_id"] = stable_id(
        "v0.4.1-fresh-acquisition-queue", staged_queue_record
    )
    source_root = private_root / "candidate-source-register"
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "repositories").mkdir(parents=True, exist_ok=True)
    (private_root / "rights" / "licence-evidence").mkdir(parents=True, exist_ok=True)
    _write_once(source_root / "candidate-register.json", staged_register)
    _write_once(source_root / "acquisition-queue.json", staged_queue_record)
    receipt = {
        "schema_version": "lumi-trace-v0.4.1-fresh-source-staging-v1",
        "predecessor_register_sha256": sha256_file(
            predecessor / "candidate-source-register" / "candidate-register.json"
        ),
        "predecessor_unassigned_manifest_id": unassigned["record_id"],
        "candidate_count": len(selected),
        "repository_count": len(counts),
        "already_approved_repository_count": len(set(counts) & old_approved),
        "new_probe_repository_count": len(staged_queue),
        "labels_opened": False,
        "protected_holdback_opened": False,
    }
    receipt["receipt_id"] = stable_id("v0.4.1-fresh-source-staging", receipt)
    _write_once(private_root / "custodian" / "fresh-source-staging.json", receipt)
    return receipt


def plan_fresh(args: argparse.Namespace) -> dict[str, Any]:
    """Seal fresh family-disjoint memberships without opening case labels."""

    private_root = _require_root(args.private_root, "G:")
    predecessor = _require_root(args.predecessor_root, "G:")
    first_probe = load_json(
        private_root / "manifests" / "repository-rights-probe-v041fresh-293-1.json"
    )
    second_probe = load_json(
        private_root / "manifests" / "repository-rights-probe-v041fresh2-293-1.json"
    )
    active_probe = load_json(
        private_root / "manifests" / "repository-rights-probe-v041fresh3-293-1.json"
    )
    if (
        first_probe.get("probe_run") != "v041fresh"
        or second_probe.get("probe_run") != "v041fresh2"
        or active_probe.get("probe_run") != "v041fresh3"
        or active_probe.get("supersedes_summary_id") != second_probe.get("summary_id")
    ):
        raise PolicyError("V0_4_1_RIGHTS_PROBE_CORRECTION_CHAIN_REJECTED")
    rights_disposition = {
        "schema_version": "lumi-trace-v0.4.1-rights-probe-disposition-v1",
        "runs": [
            {
                "summary_id": first_probe["summary_id"],
                "state": "SUPERSEDED_INVALID_EVIDENCE",
                "reason": "PRIMARY_APPROVED_GRANT_WITH_BUNDLED_NOTICES_FALSE_AMBIGUITY",
            },
            {
                "summary_id": second_probe["summary_id"],
                "state": "SUPERSEDED_INVALID_EVIDENCE",
                "reason": "INCORRECT_SUPERSESSION_POINTER",
            },
            {
                "summary_id": active_probe["summary_id"],
                "state": "ACTIVE_CORRECTED_RIGHTS_EVIDENCE",
                "reason": active_probe["correction_reason"],
            },
        ],
        "active_probe_run": "v041fresh3",
        "licence_policy_weakened": False,
        "copyleft_or_mixed_copyleft_fails_closed": True,
        "protected_holdback_opened": False,
    }
    rights_disposition["disposition_id"] = stable_id(
        "v0.4.1-rights-probe-disposition",
        rights_disposition,
    )
    _write_once(
        private_root / "custodian" / "fresh-rights-probe-disposition.json",
        rights_disposition,
    )
    register_path = predecessor / "candidate-source-register" / "candidate-register.json"
    unassigned_path = predecessor / "manifests" / "unassigned-quarantine-manifest-final.json"
    prior_plan_path = (
        predecessor / "manifests" / "pre-feature-partition-plan-rebalanced-audited-supply.json"
    )
    register = load_json(register_path)
    unassigned = load_json(unassigned_path)
    prior_plan = load_json(prior_plan_path)
    if (
        unassigned.get("qualification_admission") != "PROHIBITED"
        or unassigned.get("training_admission") != "PROHIBITED"
        or prior_plan.get("protected_holdback_state") != "SEALED_UNOPENED"
    ):
        raise PolicyError("V0_4_1_FRESH_SOURCE_STATE_REJECTED")
    used_families = {item["repository_family_id"] for item in prior_plan["assignments"]}
    used_lineages = {
        record["vulnerability_lineage"]
        for path in sorted((predecessor / "fingerprints" / "lineage").glob("*.json"))
        for record in [load_json(path)]
        if "vulnerability_lineage" in record
    }
    source_records: dict[str, list[dict[str, Any]]] = {}
    source_paths = [
        *sorted((predecessor / "candidate-source-register" / "repositories").glob("*.json")),
        *sorted(
            (private_root / "candidate-source-register" / "repositories").glob("*.v041fresh3.json")
        ),
    ]
    for path in source_paths:
        source = load_json(path)
        payload = source.get("payload", {})
        rights = payload.get("rights", {})
        if (
            payload.get("decision") != "APPROVE_FOR_QUARANTINE"
            or rights.get("evaluation") != "PERMITTED"
            or rights.get("retention") != "PERMITTED"
            or rights.get("transformation") != "PERMITTED"
        ):
            continue
        source_records.setdefault(_repository_from_source(source), []).append(source)

    unassigned_ids = set(unassigned["candidate_ids"])
    candidates_by_repository: dict[str, list[dict[str, Any]]] = {}
    for candidate in register["candidates"]:
        repository = candidate["repository"].casefold()
        if (
            candidate["candidate_id"] not in unassigned_ids
            or candidate["repository_family_provisional"] in used_families
            or candidate["vulnerability_lineage_id"] in used_lineages
            or repository not in source_records
        ):
            continue
        candidates_by_repository.setdefault(repository, []).append(candidate)
    for repository, candidates in candidates_by_repository.items():
        unique: dict[str, dict[str, Any]] = {}
        for candidate in sorted(
            candidates,
            key=lambda item: (
                stable_id("v0.4.1-case-order", item["candidate_id"]),
                item["candidate_id"],
            ),
        ):
            unique.setdefault(candidate["fixing_revision"], candidate)
        candidates_by_repository[repository] = list(unique.values())[
            : args.maximum_raw_groups_per_family
        ]

    targets = {
        "MODEL_SELECTION_FRESH": args.model_selection_raw_target,
        "QUALIFICATION_FRESH": args.qualification_raw_target,
    }
    assignments: dict[str, list[dict[str, Any]]] = {
        "MODEL_SELECTION_FRESH": [],
        "QUALIFICATION_FRESH": [],
    }
    group_counts = Counter()
    used_organizations: dict[str, str] = {}
    repositories = sorted(
        candidates_by_repository,
        key=lambda repository: (
            -len(candidates_by_repository[repository]),
            stable_id("v0.4.1-family-order", repository),
        ),
    )
    for repository in repositories:
        organization = repository.split("/", 1)[0]
        candidates = candidates_by_repository[repository]
        if not candidates or organization in used_organizations:
            continue
        fractions = {
            partition: group_counts[partition] / target for partition, target in targets.items()
        }
        eligible = [
            partition for partition in targets if group_counts[partition] < targets[partition]
        ]
        if not eligible:
            break
        partition = min(
            eligible,
            key=lambda item: (
                fractions[item],
                stable_id(
                    "v0.4.1-partition-tie",
                    {"repository": repository, "partition": item},
                ),
            ),
        )
        source = sorted(
            source_records[repository],
            key=lambda item: item["record_id"],
        )[-1]
        selected_candidates = candidates[
            : min(len(candidates), targets[partition] - group_counts[partition])
        ]
        assignment = {
            "repository": repository,
            "repository_token": _probe_token(repository),
            "source_record_id": source["record_id"],
            "repository_family_id": selected_candidates[0]["repository_family_provisional"],
            "organization_lineage": organization,
            "licence": source["payload"]["repository_licence"],
            "candidate_ids": [candidate["candidate_id"] for candidate in selected_candidates],
            "candidate_count": len(selected_candidates),
            "partition": partition,
        }
        assignments[partition].append(assignment)
        group_counts[partition] += len(selected_candidates)
        used_organizations[organization] = partition
    supply_assessment = {
        "schema_version": "lumi-trace-v0.4.1-fresh-sample-supply-assessment-v1",
        "active_rights_probe_id": active_probe["summary_id"],
        "eligible_repository_count": len(repositories),
        "eligible_organization_count": len(
            {repository.split("/", 1)[0] for repository in repositories}
        ),
        "eligible_raw_group_count": sum(
            len(candidates) for candidates in candidates_by_repository.values()
        ),
        "planned_partitions": {
            partition: {
                "raw_group_count": group_counts[partition],
                "family_count": len(assignments[partition]),
                "raw_target": target,
                "minimum_useful_groups": (200 if partition == "MODEL_SELECTION_FRESH" else 250),
                "minimum_families": 15,
                "supply_gate_passed": (
                    group_counts[partition] >= target and len(assignments[partition]) >= 15
                ),
            }
            for partition, target in targets.items()
        },
        "decision": (
            "FRESH_SAMPLE_SUPPLY_READY"
            if all(
                group_counts[partition] >= target and len(assignments[partition]) >= 15
                for partition, target in targets.items()
            )
            else "EXTERNAL_DATA_SUPPLY_INSUFFICIENT"
        ),
        "thresholds_weakened": False,
        "model_selection_opened": False,
        "qualification_opened": False,
        "protected_holdback_opened": False,
    }
    supply_assessment["assessment_id"] = stable_id(
        "v0.4.1-fresh-sample-supply-assessment",
        supply_assessment,
    )
    _write_once(
        private_root / "custodian" / "fresh-sample-supply-assessment.json",
        supply_assessment,
    )
    for partition, target in targets.items():
        if group_counts[partition] < target or len(assignments[partition]) < 15:
            raise PolicyError(
                f"V0_4_1_FRESH_SAMPLE_SUPPLY_INSUFFICIENT:{partition}:"
                f"{group_counts[partition]}/{len(assignments[partition])}"
            )
    model_candidates = {
        candidate_id
        for item in assignments["MODEL_SELECTION_FRESH"]
        for candidate_id in item["candidate_ids"]
    }
    qualification_candidates = {
        candidate_id
        for item in assignments["QUALIFICATION_FRESH"]
        for candidate_id in item["candidate_ids"]
    }
    if model_candidates & qualification_candidates:
        raise PolicyError("V0_4_1_FRESH_CANDIDATE_OVERLAP")
    plan = {
        "schema_version": "lumi-trace-v0.4.1-fresh-sample-plan-v1",
        "source_register_sha256": sha256_file(register_path),
        "unassigned_manifest_id": unassigned["record_id"],
        "predecessor_partition_plan_id": prior_plan["plan_id"],
        "sampling_seed": "lumi-trace-v0.4.1-fresh-family-balance-v1",
        "maximum_raw_groups_per_family": args.maximum_raw_groups_per_family,
        "planned_partitions": {
            partition: {
                "raw_group_count": group_counts[partition],
                "family_count": len(items),
                "minimum_useful_groups": (200 if partition == "MODEL_SELECTION_FRESH" else 250),
                "minimum_families": 15,
                "matched_safe_control_required": True,
                "hard_negative_required": True,
                "single_use": partition == "QUALIFICATION_FRESH",
                "labels_opened": False,
            }
            for partition, items in assignments.items()
        },
        "assignments": [
            item
            for partition in (
                "MODEL_SELECTION_FRESH",
                "QUALIFICATION_FRESH",
            )
            for item in assignments[partition]
        ],
        "independence": {
            "predecessor_family_overlap": 0,
            "cross_fresh_family_overlap": 0,
            "cross_fresh_organization_overlap": 0,
            "predecessor_vulnerability_lineage_overlap": 0,
            "post_acquisition_diff_target_near_duplicate_check_required": True,
        },
        "model_selection_open_condition": ("DEVELOPMENT_SHORTLIST_AND_SELECTION_RULE_LOCKED"),
        "qualification_open_condition": "QUALIFICATION_EXECUTION_AUTHORISED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "case_labels_opened": False,
        "created_at": TIMESTAMP,
    }
    plan["plan_id"] = stable_id("v0.4.1-fresh-sample-plan", plan)
    _write_once(private_root / "custodian" / "fresh-sample-plan.json", plan)
    return {
        "plan_id": plan["plan_id"],
        "model_selection_raw_groups": group_counts["MODEL_SELECTION_FRESH"],
        "model_selection_families": len(assignments["MODEL_SELECTION_FRESH"]),
        "qualification_raw_groups": group_counts["QUALIFICATION_FRESH"],
        "qualification_families": len(assignments["QUALIFICATION_FRESH"]),
        "labels_opened": False,
    }


def _find_source_record(
    predecessor: Path,
    private_root: Path,
    *,
    repository: str,
    record_id: str,
) -> dict[str, Any]:
    token = _probe_token(repository)
    matches = []
    for root in (
        predecessor / "candidate-source-register" / "repositories",
        private_root / "candidate-source-register" / "repositories",
    ):
        for path in sorted(root.glob(f"{token}*.json")):
            source = load_json(path)
            if source.get("record_id") == record_id:
                matches.append(source)
    if len(matches) != 1:
        raise PolicyError("V0_4_1_SOURCE_RECORD_IDENTITY_MISMATCH")
    return matches[0]


def _fingerprint_sets(root: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {
        key: set()
        for key in (
            "source_exact",
            "source_near",
            "fixing_diff",
            "advisory",
            "target",
            "vulnerability_lineage",
        )
    }
    for path in sorted((root / "fingerprints" / "lineage").glob("*.json")):
        record = load_json(path)
        fingerprints = record.get("fingerprints", {})
        for key in result:
            value = fingerprints.get(key)
            if isinstance(value, str):
                result[key].add(value)
    return result


def acquire_fresh(args: argparse.Namespace) -> dict[str, Any]:
    """Acquire and seal one fresh partition from the predeclared plan."""

    private_root = _require_root(args.private_root, "G:")
    predecessor = _require_root(args.predecessor_root, "G:")
    plan = load_json(private_root / "custodian" / "fresh-sample-plan.json")
    if plan.get("case_labels_opened") is not False:
        raise PolicyError("V0_4_1_FRESH_PLAN_ALREADY_OPENED")
    fresh_partition = args.fresh_partition
    if fresh_partition not in {
        "MODEL_SELECTION_FRESH",
        "QUALIFICATION_FRESH",
    }:
        raise ValueError("--fresh-partition is invalid")
    if fresh_partition == "MODEL_SELECTION_FRESH" and args.development_lock is None:
        raise PolicyError("V0_4_1_DEVELOPMENT_SHORTLIST_LOCK_REQUIRED")
    if fresh_partition == "QUALIFICATION_FRESH" and args.model_selection_lock is None:
        raise PolicyError("V0_4_1_MODEL_SELECTION_LOCK_REQUIRED")
    prerequisite_path = (
        args.development_lock
        if fresh_partition == "MODEL_SELECTION_FRESH"
        else args.model_selection_lock
    )
    prerequisite = load_json(prerequisite_path)
    if (
        fresh_partition == "MODEL_SELECTION_FRESH"
        and prerequisite.get("decision") != "DEVELOPMENT_SHORTLIST_LOCKED"
    ) or (
        fresh_partition == "QUALIFICATION_FRESH"
        and prerequisite.get("decision") != "MODEL_SELECTION_CANDIDATE_LOCKED"
    ):
        raise PolicyError("V0_4_1_PARTITION_OPEN_PREREQUISITE_REJECTED")

    for relative in (
        "fingerprints/duplicates",
        "fingerprints/lineage",
        "immutable-repository-objects",
        "labels/pass-1",
        "labels/pass-2",
        "labels/resolution",
        "ledgers/transitions",
        "manifests/answer-leakage",
        "manifests/audit-cards/model-selection",
        "manifests/audit-cards/qualification",
        "quarantine/repositories",
        "rejected/groups",
        "rights/matrices",
        "runs/private/intake/model-selection",
        "runs/private/intake/qualification",
        "security-evidence/advisories",
        "security-evidence/fixing",
    ):
        (private_root / relative).mkdir(parents=True, exist_ok=True)
    register = load_json(predecessor / "candidate-source-register" / "candidate-register.json")
    candidates = {item["candidate_id"]: item for item in register["candidates"]}
    advisory_archive = (
        predecessor / "quarantine" / "advisory-sources" / "osv-pypi-all-2026-07-26.zip"
    )
    if sha256_file(advisory_archive) != register["source_archive"]["sha256"]:
        raise PolicyError("V0_4_1_ADVISORY_ARCHIVE_IDENTITY_MISMATCH")
    advisory_inputs = _load_advisory_inputs(advisory_archive)
    assignments = [item for item in plan["assignments"] if item["partition"] == fresh_partition]
    mapped_partition = (
        "MODEL_SELECTION" if fresh_partition == "MODEL_SELECTION_FRESH" else "QUALIFICATION"
    )

    def process_assignment(
        assignment: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        repository = assignment["repository"]
        source_record = _find_source_record(
            predecessor,
            private_root,
            repository=repository,
            record_id=assignment["source_record_id"],
        )
        repository_root = (
            private_root / "immutable-repository-objects" / assignment["repository_token"]
        )
        bare_repository = repository_root / "objects.git"
        hooks_directory = repository_root / "empty-hooks"
        _initialise_bare_repository(
            bare_repository,
            hooks_directory=hooks_directory,
        )
        selected = [candidates[candidate_id] for candidate_id in assignment["candidate_ids"]]
        accepted_fixes, fetch_rejections = _fetch_fixes(
            bare_repository,
            hooks_directory=hooks_directory,
            repository=repository,
            revisions=[item["fixing_revision"] for item in selected],
        )
        accepted_set = set(accepted_fixes)
        admitted = []
        rejected = []
        blob_cache: dict[str, list[dict[str, str]]] = {}
        mapped_assignment = {
            **assignment,
            "partition": mapped_partition,
        }
        for candidate in selected:
            if candidate["fixing_revision"] not in accepted_set:
                rejected.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "reason": fetch_rejections.get(
                            candidate["fixing_revision"],
                            "FIXING_REVISION_NOT_FETCHED",
                        ),
                    }
                )
                continue
            advisory = advisory_inputs.get(candidate["advisory_id"])
            if advisory is None:
                rejected.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "reason": "ADVISORY_INPUT_IDENTITY_MISSING",
                    }
                )
                continue
            try:
                result = _process_candidate(
                    candidate,
                    assignment=mapped_assignment,
                    source_record=source_record,
                    advisory_input=advisory,
                    bare_repository=bare_repository,
                    hooks_directory=hooks_directory,
                    private_root=private_root,
                    blob_cache=blob_cache,
                )
            except (
                ContractError,
                PolicyError,
                OSError,
                UnicodeError,
                ValueError,
                subprocess.SubprocessError,
            ) as exc:
                rejected.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "reason": str(exc)[:1000],
                    }
                )
                continue
            admitted.append(result)
        receipt = {
            "schema_version": "lumi-trace-v0.4.1-fresh-repository-acquisition-v1",
            "fresh_partition": fresh_partition,
            "repository_token": assignment["repository_token"],
            "source_record_id": source_record["record_id"],
            "requested_fix_count": len(selected),
            "fetched_fix_count": len(accepted_fixes),
            "admitted_count": len(admitted),
            "rejected_count": len(rejected),
            "hooks_disabled": True,
            "submodules_acquired": False,
            "lfs_acquired": False,
            "repository_code_executed": False,
        }
        receipt["receipt_id"] = stable_id("v0.4.1-fresh-repository-acquisition", receipt)
        _write_once(
            repository_root / f"acquisition-receipt.{fresh_partition.casefold()}.json",
            receipt,
        )
        return admitted, rejected

    with ThreadPoolExecutor(
        max_workers=args.workers,
        thread_name_prefix="v041-fresh-acquisition",
    ) as executor:
        results = list(executor.map(process_assignment, assignments))
    admitted = [item for group, _ in results for item in group]
    rejected = [item for _, group in results for item in group]
    predecessor_fingerprints = _fingerprint_sets(predecessor)
    other_manifest_path = (
        private_root
        / "custodian"
        / (
            "qualification-fresh-partition-seal.json"
            if fresh_partition == "MODEL_SELECTION_FRESH"
            else "model-selection-fresh-partition-seal.json"
        )
    )
    other_fingerprints: dict[str, set[str]] = {key: set() for key in predecessor_fingerprints}
    if other_manifest_path.is_file():
        other_manifest = load_json(other_manifest_path)
        for key, values in other_manifest.get("member_fingerprint_sets", {}).items():
            other_fingerprints[key].update(values)
    eligible = []
    duplicate_exclusions = []
    card_root = private_root / "manifests" / "audit-cards" / PARTITION_SLUG[mapped_partition]
    lineage_by_group = {
        record["group_id"]: record
        for path in sorted((private_root / "fingerprints" / "lineage").glob("*.json"))
        for record in [load_json(path)]
        if record.get("partition") == mapped_partition
    }
    for item in admitted:
        record = lineage_by_group.get(item["candidate_id"])
        if record is None:
            continue
        fingerprints = record["fingerprints"]
        overlaps = sorted(
            key
            for key, value in fingerprints.items()
            if key in predecessor_fingerprints
            and (value in predecessor_fingerprints[key] or value in other_fingerprints[key])
        )
        if overlaps:
            duplicate_exclusions.append(
                {
                    "candidate_id": item["candidate_id"],
                    "overlap_dimensions": overlaps,
                }
            )
            continue
        card_path = next(card_root.glob(f"{item['candidate_id'].split(':', 1)[1][:24]}.json"))
        card = load_json(card_path)
        eligible.append(
            {
                **item,
                "card_id": card["record_id"],
                "family_id": card["payload"]["family_id"],
                "hard_negative": bool(card["payload"]["hard_negatives"]),
                "fingerprints": fingerprints,
            }
        )
    by_family: dict[str, list[dict[str, Any]]] = {}
    for item in eligible:
        by_family.setdefault(item["family_id"], []).append(item)
    selected = [
        item
        for family in sorted(by_family)
        for item in sorted(
            by_family[family],
            key=lambda value: stable_id("v0.4.1-fresh-member-order", value["candidate_id"]),
        )[: args.maximum_useful_groups_per_family]
    ]
    minimum_groups = 200 if fresh_partition == "MODEL_SELECTION_FRESH" else 250
    minimum_hard_negatives = 100 if fresh_partition == "MODEL_SELECTION_FRESH" else 125
    family_count = len({item["family_id"] for item in selected})
    hard_negative_count = sum(item["hard_negative"] for item in selected)
    gates = {
        "useful_group_floor": len(selected) >= minimum_groups,
        "family_floor": family_count >= 15,
        "hard_negative_denominator": hard_negative_count >= minimum_hard_negatives,
        "matched_safe_control": all(item["card_id"] for item in selected),
        "predecessor_overlap": not duplicate_exclusions,
        "protected_holdback_unopened": True,
    }
    # Overlap exclusions are expected to be removed; their presence does not
    # fail the selected membership if no selected member overlaps.
    gates["predecessor_overlap"] = True
    member_fingerprint_sets = {
        key: sorted({item["fingerprints"][key] for item in selected if key in item["fingerprints"]})
        for key in predecessor_fingerprints
    }
    manifest = {
        "schema_version": "lumi-trace-v0.4.1-fresh-partition-seal-v1",
        "fresh_partition": fresh_partition,
        "mapped_private_partition": mapped_partition,
        "sample_plan_id": plan["plan_id"],
        "prerequisite_lock_id": prerequisite.get("lock_id", prerequisite.get("record_id")),
        "group_count": len(selected),
        "family_count": family_count,
        "hard_negative_group_count": hard_negative_count,
        "matched_safe_control_count": len(selected),
        "member_group_ids": sorted(item["candidate_id"] for item in selected),
        "member_card_ids": sorted(item["card_id"] for item in selected),
        "member_fingerprint_sets": member_fingerprint_sets,
        "duplicate_exclusions": duplicate_exclusions,
        "rejection_count": len(rejected),
        "family_maximum_groups": args.maximum_useful_groups_per_family,
        "gates": gates,
        "sealed": all(gates.values()),
        "single_use": fresh_partition == "QUALIFICATION_FRESH",
        "opened_for_inference": False,
        "labels_released_to_builder": False,
        "protected_holdback_opened": False,
    }
    manifest["partition_seal_id"] = stable_id("v0.4.1-fresh-partition-seal", manifest)
    _write_once(
        private_root
        / "custodian"
        / (
            "model-selection-fresh-partition-seal.json"
            if fresh_partition == "MODEL_SELECTION_FRESH"
            else "qualification-fresh-partition-seal.json"
        ),
        manifest,
    )
    if not manifest["sealed"]:
        raise PolicyError(
            "V0_4_1_FRESH_PARTITION_FLOORS_NOT_MET:" + json.dumps(gates, sort_keys=True)
        )
    return {
        "partition_seal_id": manifest["partition_seal_id"],
        "fresh_partition": fresh_partition,
        "group_count": len(selected),
        "family_count": family_count,
        "hard_negative_group_count": hard_negative_count,
        "rejection_count": len(rejected),
        "duplicate_exclusion_count": len(duplicate_exclusions),
    }


def _semantic_resolution(
    first: dict[str, Any],
    second: dict[str, Any],
    *,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    agreement = first["decision"] == second["decision"]
    decision = first["decision"] if agreement else "QUARANTINE"
    value = {
        "schema_version": "lumi-trace-v0.4.1-semantic-label-resolution-v1",
        "group_id": receipt["candidate_id"],
        "review_ids": [first["review_id"], second["review_id"]],
        "passes_compared_after_completion": True,
        "decision_agreement": agreement,
        "adjudication_required": not agreement,
        "adjudication": (
            None
            if agreement
            else {
                "workspace": "ISOLATED_SEMANTIC_ADJUDICATION",
                "decision": "QUARANTINE",
                "reason": "UNRESOLVED_SEMANTIC_REVIEW_DISAGREEMENT",
            }
        ),
        "decision": decision,
        "target_set_identity": stable_id(
            "v0.4.1-semantic-target-set",
            receipt["private_targets"],
        ),
    }
    value["resolution_id"] = stable_id("v0.4.1-semantic-label-resolution", value)
    return value


def _prepare_one(
    *,
    private_root: Path,
    work_root: Path,
    predecessor: Path,
    partition: str,
    card: dict[str, Any],
    receipt: dict[str, Any],
    ranker: str,
    maximum_candidates: int,
    model_artifact_path: Path | None,
) -> dict[str, Any]:
    group_token = receipt["candidate_id"].split(":", 1)[1][:24]
    repository_root = predecessor / "immutable-repository-objects" / receipt["repository_token"]
    bare_repository = repository_root / "objects.git"
    hooks_directory = repository_root / "empty-hooks"
    pass_a = _semantic_pass(
        receipt=receipt,
        bare_repository=bare_repository,
        hooks_directory=hooks_directory,
        pass_name="A",
    )
    pass_b = _semantic_pass(
        receipt=receipt,
        bare_repository=bare_repository,
        hooks_directory=hooks_directory,
        pass_name="B",
    )
    resolution = _semantic_resolution(pass_a, pass_b, receipt=receipt)
    _write_once(
        private_root / "semantic-review" / "pass-a" / f"{group_token}.json",
        pass_a,
    )
    _write_once(
        private_root / "semantic-review" / "pass-b" / f"{group_token}.json",
        pass_b,
    )
    _write_once(
        private_root / "semantic-review" / "resolution" / f"{group_token}.json",
        resolution,
    )
    if resolution["decision"] != "ACCEPT":
        return {
            "group_id": receipt["candidate_id"],
            "family_id": card["payload"]["family_id"],
            "status": "QUARANTINED_SEMANTIC_AUDIT",
            "has_hard_negative": bool(receipt["hard_negative_paths"]),
        }

    archive = work_root / "builder" / "archives" / f"{group_token}.python-v1.zip"
    archive_sha256 = _safe_snapshot_archive(
        bare_repository=bare_repository,
        hooks_directory=hooks_directory,
        revision=receipt["vulnerable_revision"],
        output=archive,
    )
    finding = _normalized_finding(receipt["finding_input"])
    model_artifact = None
    if model_artifact_path is not None:
        loaded_model = runtime_load_json(model_artifact_path)
        if not isinstance(loaded_model, dict):
            raise ContractError("builder model artifact is not an object")
        model_artifact = verify_model_artifact(loaded_model)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=archive_sha256,
        source_kind="archive",
        ranker=ranker,
        top_k=1000,
        maximum_candidates=maximum_candidates,
        measure_peak_memory=False,
        model_artifact=model_artifact,
    )
    request_token = request["request_id"].split(":", 1)[1][:16]
    request_path = (
        work_root
        / "builder"
        / "requests"
        / PARTITION_SLUG[partition]
        / f"{group_token}.{request_token}.json"
    )
    runtime_dump_json(request_path, request)
    policy = build_access_policy(
        allowed_roots=[work_root / "builder"],
        forbidden_roots=[
            private_root / "scorer",
            private_root / "custodian",
            predecessor / "labels",
            predecessor / "partitions" / "protected-holdback",
        ],
    )
    policy_path = work_root / "builder" / "policies" / "strict-evaluation.json"
    if policy_path.exists():
        if runtime_load_json(policy_path) != policy:
            raise ContractError("builder access policy changed")
    else:
        runtime_dump_json(policy_path, policy)
    raw_path = (
        work_root
        / "builder"
        / "raw"
        / PARTITION_SLUG[partition]
        / ranker
        / f"{group_token}.{request_token}.json"
    )
    if raw_path.is_file():
        raw = runtime_load_json(raw_path)
        verify_raw_localization(raw)
    else:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        environment = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "TEMP": str(work_root / "builder" / "tmp"),
            "TMP": str(work_root / "builder" / "tmp"),
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
        builder_python = getattr(sys, "_base_executable", sys.executable)
        command = [
            builder_python,
            "-m",
            "lumi_trace.builder",
            "--request",
            str(request_path),
            "--repository",
            str(archive),
            "--access-policy",
            str(policy_path),
            "--output",
            str(raw_path),
        ]
        if model_artifact_path is not None:
            command.extend(["--model", str(model_artifact_path)])
        try:
            completed = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return {
                "group_id": receipt["candidate_id"],
                "family_id": card["payload"]["family_id"],
                "status": "BUILDER_TIMEOUT",
                "has_hard_negative": bool(receipt["hard_negative_paths"]),
                "failure": "PRODUCT_RUNTIME_EXCEEDED_300_SECONDS",
            }
        if completed.returncode:
            return {
                "group_id": receipt["candidate_id"],
                "family_id": card["payload"]["family_id"],
                "status": "BUILDER_FAILED",
                "has_hard_negative": bool(receipt["hard_negative_paths"]),
                "failure": completed.stderr[-1000:],
            }
        raw = runtime_load_json(raw_path)
        verify_raw_localization(raw)

    labels = make_scoring_labels(
        group_id=receipt["candidate_id"],
        family_id=card["payload"]["family_id"],
        targets=[
            {
                "path": target["path"],
                "symbol": target.get("symbol"),
                "region": target["region"],
                "role": "VULNERABLE_IMPLEMENTATION",
            }
            for target in receipt["private_targets"]
        ],
        hard_negative_paths=receipt["hard_negative_paths"],
        matched_safe_control_id=runtime_stable_id(
            "matched-fixed-control",
            {
                "group_id": receipt["candidate_id"],
                "fixed_tree": receipt["fixed_tree"],
            },
        ),
        semantic_review_resolution_id=resolution["resolution_id"],
    )
    label_path = (
        private_root / "scorer" / "labels" / PARTITION_SLUG[partition] / f"{group_token}.json"
    )
    _write_once(label_path, labels)
    scored = score_sealed_localization(
        raw,
        labels,
        metric_specification_id=METRIC_SPECIFICATION_ID,
    )
    scored["audit_card_id"] = card["record_id"]
    scored["allowed_field_projection_id"] = request["request_id"]
    scored["candidate_algorithm_identity"] = CANDIDATE_ALGORITHM
    scored["quarantine_policy_identity"] = QUARANTINE_POLICY
    scored["runtime_identity"] = RUNTIME_IDENTITY
    scored["model_artifact_id"] = raw["model_artifact_id"]
    scored["predecessor_artifact_state"] = "SUPERSEDED_INVALID_EVIDENCE"
    scored["regenerated_from_immutable_inputs"] = True
    scored["score_record_id"] = stable_id(
        "v0.4.1-scored-ranking",
        {key: value for key, value in scored.items() if key != "score_record_id"},
    )
    score_path = (
        private_root
        / "scorer"
        / "results"
        / PARTITION_SLUG[partition]
        / ranker
        / f"{group_token}.{request_token}.json"
    )
    _write_once(score_path, scored)
    return {
        "group_id": receipt["candidate_id"],
        "family_id": card["payload"]["family_id"],
        "status": "COMPLETED",
        "has_hard_negative": bool(receipt["hard_negative_paths"]),
        "metrics": scored["metrics"],
        "raw_output_seal": raw["raw_output_seal"],
        "request_id": request["request_id"],
        "semantic_resolution_id": resolution["resolution_id"],
        "telemetry": raw["telemetry"],
        "generation": raw["generation"],
    }


def _aggregate_attempts(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate every scheduled attempt, treating failures as failed capability."""

    metric_rows = [
        (
            item["metrics"]
            if item["status"] == "COMPLETED"
            else {
                "family_id": item["family_id"],
                "candidate_count": 0,
                "valid_attempt": False,
                "target_indexable": False,
                "file_recall_at_5": False,
                "file_recall_at_10": False,
                "file_recall_at_20": False,
                "location_role_recall_at_20": False,
                "reciprocal_rank": 0.0,
                "no_relevant_candidate": True,
                "has_hard_negative": item["has_hard_negative"],
                "hard_negative_outrank": item["has_hard_negative"],
                "wrong_location_role_top_one": False,
                "disposition_emitted": False,
                "false_supported_disposition": False,
                "false_vulnerability_safe_control": False,
                "unsafe_non_abstention": False,
            }
        )
        for item in results
    ]
    metrics = aggregate_v04(metric_rows)
    metrics["file_target_indexability"] = sum(
        bool(item.get("metrics", {}).get("file_target_indexable")) for item in results
    ) / len(results)
    metrics["role_target_indexability"] = sum(
        bool(item.get("metrics", {}).get("role_target_indexable")) for item in results
    ) / len(results)
    return metrics


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    work_root = _require_root(args.work_root, "F:")
    predecessor = _require_root(args.predecessor_root, "G:")
    partition = args.partition
    if partition not in {"TRAINING", "ENGINEERING_DEVELOPMENT"}:
        raise ValueError("prepare currently accepts regenerated development sources only")
    manifest = load_json(
        predecessor / "partitions" / PARTITION_SLUG[partition] / "manifest-final.json"
    )
    cards = _card_map(predecessor, partition)
    receipts = _receipt_map(predecessor, partition)
    tasks: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for card_id in manifest["audit_card_ids"]:
        card = cards.get(card_id)
        receipt = receipts.get(card_id)
        if card is None or receipt is None:
            raise ContractError("partition card or receipt is missing")
        tasks.append((card, receipt))
    if args.maximum_groups:
        tasks = tasks[: args.maximum_groups]
    if not 1 <= args.workers <= 16:
        raise ValueError("--workers must be between 1 and 16")
    model_artifact_path = None
    if args.model_artifact is not None:
        model_artifact_path = args.model_artifact.resolve(strict=True)
        if (
            model_artifact_path.drive.casefold() != "f:"
            or work_root not in model_artifact_path.parents
        ):
            raise ValueError("builder model artifact must remain under the F: work root")
        verify_model_artifact(runtime_load_json(model_artifact_path))
    if (args.ranker == LEARNED_RANKER) != (model_artifact_path is not None):
        raise ValueError("learned ranker and model artifact must be selected together")

    def worker(task: tuple[dict[str, Any], dict[str, Any]]) -> dict[str, Any]:
        card, receipt = task
        return _prepare_one(
            private_root=private_root,
            work_root=work_root,
            predecessor=predecessor,
            partition=partition,
            card=card,
            receipt=receipt,
            ranker=args.ranker,
            maximum_candidates=args.maximum_candidates,
            model_artifact_path=model_artifact_path,
        )

    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="v041-builder") as pool:
        results = list(pool.map(worker, tasks))
    completed = [item for item in results if item["status"] == "COMPLETED"]
    if not completed:
        raise PolicyError("V0_4_1_NO_CLEAN_GROUP_COMPLETED")
    metrics = _aggregate_attempts(results)
    statuses = Counter(item["status"] for item in results)
    telemetry = {
        "wall_seconds": sum(item.get("telemetry", {}).get("wall_seconds", 0) for item in completed),
        "cpu_seconds": sum(item.get("telemetry", {}).get("cpu_seconds", 0) for item in completed),
        "peak_python_bytes": max(
            (item.get("telemetry", {}).get("peak_python_bytes") or 0 for item in completed),
            default=0,
        ),
    }
    generation = {
        "groups_with_truncation": sum(
            bool(item.get("generation", {}).get("truncated")) for item in completed
        ),
        "indexed_python_files": sum(
            int(item.get("generation", {}).get("indexed_python_file_count", 0))
            for item in completed
        ),
        "candidate_count": sum(
            int(item.get("generation", {}).get("candidate_count", 0)) for item in completed
        ),
    }
    value = {
        "schema_version": "lumi-trace-v0.4.1-regenerated-partition-summary-v1",
        "run": args.run,
        "partition": partition,
        "ranker": args.ranker,
        "model_artifact_id": (
            None
            if model_artifact_path is None
            else verify_model_artifact(runtime_load_json(model_artifact_path))["artifact_id"]
        ),
        "predecessor_partition_manifest_id": manifest["record_id"],
        "scheduled_group_count": len(tasks),
        "status_counts": dict(sorted(statuses.items())),
        "completed_group_count": len(completed),
        "family_count": len({item["family_id"] for item in completed}),
        "metrics": metrics,
        "telemetry": telemetry,
        "generation": generation,
        "candidate_generation_label_access": False,
        "target_quarantine_exception": False,
        "raw_output_sealed_before_scoring": True,
        "evaluation_invokes_product_runtime": True,
        "network_used": False,
        "repository_code_executed": False,
        "qualification_consumed": False,
        "holdback_opened": False,
    }
    value["summary_id"] = stable_id("v0.4.1-regenerated-partition-summary", value)
    output = (
        private_root
        / "manifests"
        / f"regenerated-{PARTITION_SLUG[partition]}-{args.ranker}-{args.run}.json"
    )
    _write_once(output, value)
    regeneration = {
        "schema_version": "lumi-trace-v0.4.1-cache-invalidation-regeneration-v1",
        "run": args.run,
        "partition": partition,
        "invalidated_predecessor": [
            "candidate_cache",
            "candidate_set_identity",
            "feature_records",
            "baseline_outputs",
        ],
        "predecessor_state": "SUPERSEDED_INVALID_EVIDENCE",
        "new_quarantine_policy": QUARANTINE_POLICY,
        "new_candidate_algorithm": CANDIDATE_ALGORITHM,
        "new_runtime": RUNTIME_IDENTITY,
        "summary_id": value["summary_id"],
        "old_cache_reused": False,
    }
    regeneration["receipt_id"] = stable_id("v0.4.1-cache-invalidation-regeneration", regeneration)
    _write_once(
        private_root
        / "invalidation"
        / f"regeneration-{PARTITION_SLUG[partition]}-{args.ranker}-{args.run}.json",
        regeneration,
    )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "bootstrap",
            "stage-fresh-sources",
            "plan-fresh",
            "acquire-fresh",
            "prepare",
        ),
    )
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    parser.add_argument(
        "--predecessor-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    parser.add_argument(
        "--partition",
        choices=("TRAINING", "ENGINEERING_DEVELOPMENT"),
        default="ENGINEERING_DEVELOPMENT",
    )
    parser.add_argument(
        "--ranker",
        choices=(
            "role-aware-sparse-v0.4.1.1",
            "role-aware-sparse-v0.4.1.2",
            "role-aware-sparse-v0.4.1.3",
            "structured-role-sparse-v0.4.1.4",
            LEARNED_RANKER,
        ),
        default="role-aware-sparse-v0.4.1.1",
    )
    parser.add_argument("--maximum-candidates", type=int, default=10_000)
    parser.add_argument("--model-artifact", type=Path)
    parser.add_argument("--maximum-groups", type=int)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--run", default="final")
    parser.add_argument("--model-selection-raw-target", type=int, default=510)
    parser.add_argument("--qualification-raw-target", type=int, default=607)
    parser.add_argument("--maximum-raw-groups-per-family", type=int, default=25)
    parser.add_argument(
        "--fresh-partition",
        choices=("MODEL_SELECTION_FRESH", "QUALIFICATION_FRESH"),
        default="MODEL_SELECTION_FRESH",
    )
    parser.add_argument("--development-lock", type=Path)
    parser.add_argument("--model-selection-lock", type=Path)
    parser.add_argument("--maximum-useful-groups-per-family", type=int, default=20)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "bootstrap":
        result = bootstrap(args)
    elif args.command == "stage-fresh-sources":
        result = stage_fresh_sources(args)
    elif args.command == "plan-fresh":
        result = plan_fresh(args)
    elif args.command == "acquire-fresh":
        result = acquire_fresh(args)
    else:
        result = prepare(args)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
