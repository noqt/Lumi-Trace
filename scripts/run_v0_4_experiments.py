# SPDX-License-Identifier: Apache-2.0
"""Prepare label-blind V0.4 candidates and run bounded simple baselines."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
import warnings
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager, nullcontext
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
RUNTIME_SRC = ROOT / "src"
for source_path in (EVAL_SRC, RUNTIME_SRC, ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.assurance import (  # noqa: E402
    PARTITIONS,
    evaluate_training_readiness,
    v04_metric_specification,
    validate_group_audit_card,
    wilson_interval,
)
from trace_eval.baselines import (  # noqa: E402
    aggregate_v04,
    lexical_rank,
    random_control,
    score_v04_group,
    sparse_rank,
    tokens,
)
from trace_eval.canonical import (  # noqa: E402
    canonical_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
    stable_id,
)
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.features import (  # noqa: E402
    CANDIDATE_CACHE_TOKEN,
    CANDIDATE_GENERATION_ALGORITHM,
    apply_private_labels,
    baseline_candidate_projection,
    build_candidate_features,
    training_candidate_projection,
)
from trace_eval.trace001 import (  # noqa: E402
    TrainingConfig,
    rank_with_checkpoint,
    verify_checkpoint,
)

from lumi_trace.canonical import stable_id as runtime_stable_id  # noqa: E402
from lumi_trace.errors import LumiTraceError  # noqa: E402
from lumi_trace.findings import _finalize_finding  # noqa: E402
from lumi_trace.indexing import build_repository_index  # noqa: E402
from lumi_trace.ranking import rank_candidates  # noqa: E402
from lumi_trace.repository import RepositoryWorkspace  # noqa: E402
from scripts.build_v0_4_assurance import (  # noqa: E402
    RECONSIDERED_PATH_QUARANTINE_POLICY,
    _git,
    _git_environment,
    _tree_entries,
    _write_once,
)

_PARTITION_SLUG = {partition: partition.casefold().replace("_", "-") for partition in PARTITIONS}
_RECONSIDERED_LOCK = "v0.4-candidate-lock-file-coverage.json"
_RECONSIDERED_SUPPLY_CHAIN = "trace-001-model-supply-chain-file-coverage.json"
_RECONSIDERED_EXECUTION_LOCK = "trace-001-training-execution-lock-file-coverage.json"
_IDENTITY_REMEDIATION_EXECUTION_LOCK = (
    "trace-001-training-execution-lock-json-identity-remediation.json"
)
_IDENTITY_REMEDIATION_FAILURE = "trace-001-preflight-failure-json-item-limit.json"
_IDENTITY_REMEDIATION_GATES = "training-entry-gates-final-json-identity-remediation.json"
_IDENTITY_REMEDIATION_READINESS = "training-readiness-final-json-identity-remediation.json"


def _active_candidate_lock(private_root: Path) -> dict[str, Any]:
    revised = private_root / "manifests" / _RECONSIDERED_LOCK
    path = revised if revised.is_file() else private_root / "manifests" / "v0.4-candidate-lock.json"
    return load_json(path)


def _active_training_locks(
    private_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    revised_supply = private_root / "manifests" / _RECONSIDERED_SUPPLY_CHAIN
    revised_execution = private_root / "manifests" / _RECONSIDERED_EXECUTION_LOCK
    if revised_supply.is_file() != revised_execution.is_file():
        raise PolicyError("V0_4_TRAINING_LOCK_RECONSIDERATION_INCOMPLETE")
    supply = load_json(
        revised_supply
        if revised_supply.is_file()
        else private_root / "manifests" / "trace-001-model-supply-chain.json"
    )
    execution = load_json(
        revised_execution
        if revised_execution.is_file()
        else private_root / "manifests" / "trace-001-training-execution-lock.json"
    )
    remediated = private_root / "manifests" / _IDENTITY_REMEDIATION_EXECUTION_LOCK
    if remediated.is_file():
        execution = load_json(remediated)
    return supply, execution


def _active_final_authority_paths(private_root: Path) -> tuple[Path, Path]:
    remediated_execution = private_root / "manifests" / _IDENTITY_REMEDIATION_EXECUTION_LOCK
    if remediated_execution.is_file():
        return (
            private_root / "manifests" / _IDENTITY_REMEDIATION_GATES,
            private_root / "manifests" / _IDENTITY_REMEDIATION_READINESS,
        )
    return (
        private_root / "manifests" / "training-entry-gates-final.json",
        private_root / "manifests" / "training-readiness-final.json",
    )


@contextmanager
def _python_network_denied() -> Iterator[None]:
    """Deny Python socket creation while a sealed qualification is running."""

    original_socket = socket.socket
    original_create_connection = socket.create_connection

    def deny(*_args: Any, **_kwargs: Any) -> Any:
        raise PolicyError("V0_4_QUALIFICATION_NETWORK_DENIED")

    socket.socket = deny  # type: ignore[assignment]
    socket.create_connection = deny
    try:
        yield
    finally:
        socket.socket = original_socket
        socket.create_connection = original_create_connection


def _require_root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _batch_blobs(
    bare_repository: Path,
    object_ids: list[str],
    *,
    maximum_blob_bytes: int = 2 * 1024 * 1024,
) -> dict[str, bytes]:
    process = subprocess.Popen(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            f"--git-dir={bare_repository}",
            "cat-file",
            "--batch",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise ContractError("Git batch pipes are unavailable")
    result: dict[str, bytes] = {}
    try:
        for object_id in object_ids:
            process.stdin.write(f"{object_id}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", errors="strict").strip()
            parts = header.split()
            if len(parts) != 3 or parts[0] != object_id or parts[1] != "blob":
                raise ContractError("Git batch object header is invalid")
            size = int(parts[2])
            if size < 0 or size > maximum_blob_bytes:
                raise PolicyError("V0_4_FEATURE_BLOB_SIZE_LIMIT")
            body = process.stdout.read(size)
            terminator = process.stdout.read(1)
            if len(body) != size or terminator != b"\n":
                raise ContractError("Git batch object body is truncated")
            result[object_id] = body
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    if process.returncode:
        error = (
            process.stderr.read().decode("utf-8", errors="replace")
            if process.stderr is not None
            else ""
        )
        raise ContractError(f"Git batch reader failed: {error[-1000:]}")
    return result


def _receipt_for_group(private_root: Path, group_id: str) -> dict[str, Any]:
    token = group_id.split(":", 1)[1][:24]
    paths = sorted((private_root / "runs" / "private" / "intake").rglob(f"{token}.json"))
    if len(paths) != 1:
        raise PolicyError("V0_4_EXPERIMENT_RECEIPT_MISSING_OR_AMBIGUOUS")
    return load_json(paths[0])


def _finding_tokens(finding: dict[str, Any]) -> list[str]:
    return tokens(
        [
            str(finding.get("advisory_identifier", "")),
            *[str(value) for value in finding.get("aliases", [])],
            *[str(value) for value in finding.get("packages", [])],
            str(finding.get("summary", "")),
            str(finding.get("description", "")),
        ]
    )


def _candidate_files(
    bare_repository: Path,
    revision: str,
    *,
    hooks_directory: Path,
    excluded_path_identities: set[str],
) -> list[dict[str, str]]:
    entries = [
        entry
        for entry in _tree_entries(
            bare_repository,
            revision,
            hooks_directory=hooks_directory,
        )
        if entry.object_type == "blob"
        and entry.mode in {"100644", "100755"}
        and entry.size_bytes is not None
        and entry.size_bytes <= 2 * 1024 * 1024
        and PurePosixPath(entry.path).suffix.casefold() == ".py"
        and stable_id("repository-path", entry.path) not in excluded_path_identities
    ]
    blobs = _batch_blobs(
        bare_repository,
        [entry.object_id for entry in entries],
    )
    files: list[dict[str, str]] = []
    for entry in entries:
        try:
            source = blobs[entry.object_id].decode("utf-8")
        except UnicodeDecodeError:
            continue
        files.append({"path": entry.path, "source": source})
    return files


def _score_algorithm(
    name: str,
    ranked: list[dict[str, Any]],
    *,
    labels: dict[str, Any],
    family_id: str,
) -> dict[str, Any]:
    metrics = score_v04_group(
        ranked,
        file_target_candidate_ids=set(labels["file_target_candidate_ids"]),
        role_target_candidate_ids=set(labels["role_target_candidate_ids"]),
        hard_negative_candidate_ids=set(labels["hard_negative_candidate_ids"]),
        family_id=family_id,
    )
    return {
        "algorithm": name,
        "ranking_id": stable_id(
            "v0.4-sealed-ranking",
            [item["candidate_id"] for item in ranked],
        ),
        "metrics": metrics,
    }


def _normalized_runtime_finding(finding: dict[str, Any]) -> dict[str, object]:
    summary = str(finding.get("summary", "")).strip()
    description = str(finding.get("description", "")).strip()
    advisory = str(finding.get("advisory_identifier", "")).strip() or "unknown"
    payload: dict[str, object] = {
        "schema_version": "normalized-finding-v1",
        "source": {
            "kind": "MANUAL",
            "input_sha256": sha256_bytes(canonical_bytes(finding)),
        },
        "rule": {
            "id": advisory,
            "name": summary or advisory,
            "cwes": [],
            "tags": [],
        },
        "message": {
            "title": summary or advisory,
            "text": description or summary or advisory,
        },
        "severity": {"normalized": "UNKNOWN", "original": "unknown"},
        "locations": [],
        "keywords": [],
        "fingerprints": {},
    }
    return _finalize_finding(payload, None)


def _runtime_rank_metrics(
    candidates: list[dict[str, Any]],
    *,
    targets: list[dict[str, Any]],
    hard_negative_paths: list[str],
    family_id: str,
) -> dict[str, Any]:
    target_paths = {target["path"] for target in targets}
    target_symbols = {
        (target["path"], target["symbol"]) for target in targets if target.get("symbol")
    }
    hard_paths = set(hard_negative_paths)
    ranked = [{"candidate_id": str(candidate["candidate_id"])} for candidate in candidates]
    file_target_ids = {
        str(candidate["candidate_id"])
        for candidate in candidates
        if candidate["path"] in target_paths
    }
    role_target_ids = {
        str(candidate["candidate_id"])
        for candidate in candidates
        if (
            candidate["path"],
            str((candidate.get("symbol") or {}).get("qualified_name", "")),
        )
        in target_symbols
    }
    hard_negative_ids = {
        str(candidate["candidate_id"])
        for candidate in candidates
        if candidate["path"] in hard_paths
    }
    return score_v04_group(
        ranked,
        file_target_candidate_ids=file_target_ids,
        role_target_candidate_ids=role_target_ids,
        hard_negative_candidate_ids=hard_negative_ids,
        family_id=family_id,
    )


def _v012_record(
    private_root: Path,
    work_root: Path,
    card: dict[str, Any],
) -> dict[str, Any]:
    payload = card["payload"]
    receipt = _receipt_for_group(private_root, payload["group_id"])
    repository_root = private_root / "immutable-repository-objects" / receipt["repository_token"]
    bare_repository = repository_root / "objects.git"
    hooks_directory = repository_root / "empty-hooks"
    temporary_root = work_root / "workspaces" / "v0-1-2"
    temporary_root.mkdir(parents=True, exist_ok=True)
    old_tempdir = tempfile.tempdir
    status = "COMPLETED"
    failure = None
    metrics: dict[str, Any]
    index_id: str | None = None
    candidate_set_id: str | None = None
    try:
        tempfile.tempdir = str(temporary_root)
        with tempfile.TemporaryDirectory(
            prefix="v04-v012-",
            dir=temporary_root,
        ) as directory:
            archive = Path(directory) / "repository.zip"
            _git(
                bare_repository,
                [
                    "archive",
                    "--format=zip",
                    f"--output={archive}",
                    receipt["vulnerable_revision"],
                ],
                hooks_directory=hooks_directory,
            )
            with RepositoryWorkspace(archive) as workspace:
                if workspace.root is None or workspace.identity is None:
                    raise ContractError("V0.1.2 workspace identity is unavailable")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    index = build_repository_index(
                        workspace.root,
                        workspace.identity,
                    )
                finding = _normalized_runtime_finding(receipt["finding_input"])
                candidate_set = rank_candidates(finding, index, top_k=1_000)
                index_id = str(index["index_id"])
                candidate_set_id = str(candidate_set["candidate_set_id"])
                metrics = _runtime_rank_metrics(
                    candidate_set["candidates"],
                    targets=receipt["private_targets"],
                    hard_negative_paths=receipt["hard_negative_paths"],
                    family_id=payload["family_id"],
                )
    except (
        LumiTraceError,
        ContractError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        status = "UNSUPPORTED"
        failure = type(exc).__name__
        metrics = score_v04_group(
            [],
            file_target_candidate_ids=set(),
            role_target_candidate_ids=set(),
            hard_negative_candidate_ids=set(),
            family_id=payload["family_id"],
        )
        metrics["valid_attempt"] = False
    finally:
        tempfile.tempdir = old_tempdir
    value = {
        "schema_version": "lumi-trace-v0.4-private-v0.1.2-replay-v1",
        "group_id": payload["group_id"],
        "family_id": payload["family_id"],
        "audit_card_id": card["record_id"],
        "runtime_version": "0.1.2",
        "runtime_algorithm": "deterministic-candidate-ranking-v2",
        "runtime_algorithm_identity": runtime_stable_id(
            "runtime-comparator",
            {
                "runtime_version": "0.1.2",
                "algorithm": "deterministic-candidate-ranking-v2",
            },
        ),
        "status": status,
        "failure_category": failure,
        "index_id": index_id,
        "candidate_set_id": candidate_set_id,
        "metrics": metrics,
        "temporary_root_drive": "F:",
        "repository_code_executed": False,
        "network_used": False,
    }
    value["record_id"] = stable_id("v0.4-v0.1.2-replay", value)
    return value


def _effective_quarantine(
    excluded_path_identities: set[str],
    targets: list[dict[str, Any]],
) -> tuple[set[str], int]:
    """Apply the sealed audited-target exception without exposing labels to ranking."""

    target_path_identities = {stable_id("repository-path", target["path"]) for target in targets}
    overrides = excluded_path_identities & target_path_identities
    return excluded_path_identities - target_path_identities, len(overrides)


def _group_record(
    private_root: Path,
    card: dict[str, Any],
    *,
    maximum_candidates: int,
) -> dict[str, Any]:
    payload = card["payload"]
    receipt = _receipt_for_group(private_root, payload["group_id"])
    if (
        receipt["group_audit_card_id"] != card["record_id"]
        or receipt["partition"] != payload["partition"]
        or receipt["state"] != payload["final_state"]
    ):
        raise PolicyError("V0_4_EXPERIMENT_CARD_RECEIPT_MISMATCH")
    repository_root = private_root / "immutable-repository-objects" / receipt["repository_token"]
    bare_repository = repository_root / "objects.git"
    hooks_directory = repository_root / "empty-hooks"
    excluded_path_identities = {
        *receipt["snapshot_scans"]["vulnerable"].get(
            "quarantined_path_identities",
            receipt["snapshot_scans"]["vulnerable"].get(
                "quarantined_nonproduction_path_identities",
                [],
            ),
        ),
        *receipt["snapshot_scans"]["fixed"].get(
            "quarantined_path_identities",
            receipt["snapshot_scans"]["fixed"].get(
                "quarantined_nonproduction_path_identities",
                [],
            ),
        ),
    }
    effective_quarantine, audited_target_override_count = _effective_quarantine(
        excluded_path_identities,
        receipt["private_targets"],
    )
    files = _candidate_files(
        bare_repository,
        receipt["vulnerable_revision"],
        hooks_directory=hooks_directory,
        excluded_path_identities=effective_quarantine,
    )
    candidates = build_candidate_features(
        receipt["finding_input"],
        files,
        maximum_candidates=maximum_candidates,
    )
    labels = apply_private_labels(
        candidates,
        targets=receipt["private_targets"],
        hard_negative_paths=receipt["hard_negative_paths"],
    )
    baseline_candidates = [baseline_candidate_projection(candidate) for candidate in candidates]
    finding_tokens = _finding_tokens(receipt["finding_input"])
    rankings = {
        "lexical": lexical_rank(finding_tokens, baseline_candidates),
        "sparse": sparse_rank(finding_tokens, baseline_candidates),
        "random": random_control(payload["group_id"], baseline_candidates),
        "always_abstain": [],
    }
    scores = [
        _score_algorithm(
            name,
            ranked,
            labels=labels,
            family_id=payload["family_id"],
        )
        for name, ranked in rankings.items()
    ]
    role_targets = set(labels["role_target_candidate_ids"])
    training_targets = role_targets or set(labels["file_target_candidate_ids"])
    value = {
        "schema_version": "lumi-trace-v0.4-private-feature-group-v1",
        "group_id": payload["group_id"],
        "family_id": payload["family_id"],
        "audit_card_id": card["record_id"],
        "partition": payload["partition"],
        "candidate_set_id": labels["candidate_set_id"],
        "candidate_count": len(candidates),
        "maximum_candidates": maximum_candidates,
        "file_target_present": labels["file_target_present"],
        "role_target_present": labels["role_target_present"],
        "private_scoring_labels": labels,
        "training_candidates": [
            training_candidate_projection(
                candidate,
                target_ids=training_targets,
            )
            for candidate in candidates
        ],
        "baseline_scores": scores,
        "repository_code_executed": False,
        "runner_or_model_output_used_for_labels": False,
        "network_used": False,
        "assurance_policy_id": RECONSIDERED_PATH_QUARANTINE_POLICY,
        "audited_target_quarantine_override_count": audited_target_override_count,
        "candidate_generation_label_access": "AUDITED_TARGET_PATH_ALLOWLIST_ONLY",
        "candidate_generation_algorithm": CANDIDATE_GENERATION_ALGORITHM,
        "training_target_level": ("LOCATION_ROLE" if role_targets else "FILE_FALLBACK"),
    }
    value["record_id"] = stable_id("v0.4-feature-group", value)
    return value


def _compact_feature_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record["record_id"],
        "group_id": record["group_id"],
        "family_id": record["family_id"],
        "audit_card_id": record["audit_card_id"],
        "baseline_scores": record["baseline_scores"],
        "audited_target_quarantine_override_count": record[
            "audited_target_quarantine_override_count"
        ],
    }


def _prepare_card_worker(
    task: tuple[str, str, dict[str, Any], int, bool, bool],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    (
        private_root_text,
        work_root_text,
        card,
        maximum_candidates,
        include_v012,
        deny_network,
    ) = task
    private_root = Path(private_root_text)
    work_root = Path(work_root_text)
    partition = card["payload"]["partition"]
    slug = _PARTITION_SLUG[partition]
    output_root = (
        private_root / "training-derived" / "features"
        if partition == "TRAINING"
        else private_root / "runs" / "private" / "baselines" / slug
    )
    token = card["payload"]["group_id"].split(":", 1)[1][:24]
    path = output_root / f"{token}.{CANDIDATE_CACHE_TOKEN}.c{maximum_candidates}.json"
    with _python_network_denied() if deny_network else nullcontext():
        if path.is_file():
            record = load_json(path)
            if (
                record["audit_card_id"] != card["record_id"]
                or record.get("maximum_candidates") != maximum_candidates
            ):
                raise PolicyError("V0_4_FEATURE_RECORD_CARD_MISMATCH")
        else:
            record = _group_record(
                private_root,
                card,
                maximum_candidates=maximum_candidates,
            )
            _write_once(path, record)
        v012_record: dict[str, Any] | None = None
        if include_v012:
            v012_path = private_root / "runs" / "private" / "v0-1-2" / slug / f"{token}.json"
            if v012_path.is_file():
                v012_record = load_json(v012_path)
                if v012_record["audit_card_id"] != card["record_id"]:
                    raise PolicyError("V0_1_2_RECORD_CARD_MISMATCH")
            else:
                v012_record = _v012_record(private_root, work_root, card)
                _write_once(v012_path, v012_record)
    return _compact_feature_record(record), v012_record


def _confidence_intervals(results: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "valid_attempt",
        "target_indexable",
        "file_recall_at_5",
        "file_recall_at_10",
        "file_recall_at_20",
        "location_role_recall_at_20",
        "no_relevant_candidate",
        "wrong_location_role_top_one",
    )
    intervals = {
        field: wilson_interval(
            sum(bool(item[field]) for item in results),
            len(results),
        )
        for field in fields
    }
    hard = [item for item in results if item["has_hard_negative"]]
    intervals["hard_negative_outrank"] = wilson_interval(
        sum(bool(item["hard_negative_outrank"]) for item in hard),
        len(hard),
    )
    return intervals


def _gate_results(aggregate: dict[str, Any]) -> dict[str, bool]:
    gates = v04_metric_specification()["payload"]["gates"]
    return {
        "valid_attempt_completion": aggregate["valid_attempt_completion"]
        >= gates["valid_attempt_completion_minimum"],
        "target_indexability": aggregate["target_indexability"]
        >= gates["target_indexability_minimum"],
        "file_recall_at_5": aggregate["file_recall_at_5"] >= gates["file_recall_at_5_minimum"],
        "file_recall_at_10": aggregate["file_recall_at_10"] >= gates["file_recall_at_10_minimum"],
        "file_recall_at_20": aggregate["file_recall_at_20"] >= gates["file_recall_at_20_minimum"],
        "location_role_correct_recall_at_20": aggregate["location_role_correct_recall_at_20"]
        >= gates["location_role_correct_recall_at_20_minimum"],
        "mean_reciprocal_rank": aggregate["mean_reciprocal_rank"]
        >= gates["mean_reciprocal_rank_minimum"],
        "no_relevant_candidate": aggregate["no_relevant_candidate"]
        <= gates["no_relevant_candidate_maximum"],
        "hard_negative_outrank": aggregate["hard_negative_outrank"]
        <= gates["hard_negative_outrank_maximum"],
        "wrong_location_role_top_one": aggregate["wrong_location_role_top_one"]
        <= gates["wrong_location_role_top_one_maximum"],
        "repository_family_macro_recall_at_20": aggregate["repository_family_macro_recall_at_20"]
        >= gates["repository_family_macro_recall_at_20_minimum"],
        "minimum_family_recall_at_20": aggregate["minimum_family_recall_at_20"]
        >= gates["minimum_family_recall_at_20_minimum"],
        "zero_recall_family_count": aggregate["zero_recall_family_count"]
        <= gates["zero_recall_family_count_maximum"],
        "false_supported_disposition": aggregate["false_supported_disposition"]
        <= gates["false_supported_disposition_maximum"],
        "false_vulnerability_safe_control": aggregate["false_vulnerability_safe_control"]
        <= gates["false_vulnerability_safe_control_maximum"],
        "unsafe_non_abstention": aggregate["unsafe_non_abstention"]
        <= gates["unsafe_non_abstention_maximum"],
    }


def _deterministic_selection_key(
    algorithm: str,
    result: dict[str, Any],
) -> tuple[float | int, ...]:
    """Apply the predeclared deterministic comparator selection order."""

    aggregate = result["aggregate"]
    gate_results = result["gate_results"]
    maintenance_preference = {
        "lexical": 3,
        "sparse": 2,
        "v0.1.2": 1,
    }
    return (
        sum(bool(value) for value in gate_results.values()),
        float(aggregate["location_role_correct_recall_at_20"]),
        float(aggregate["file_recall_at_20"]),
        float(aggregate["repository_family_macro_recall_at_20"]),
        float(aggregate["mean_reciprocal_rank"]),
        -float(aggregate["hard_negative_outrank"]),
        maintenance_preference[algorithm],
    )


def build_candidate_lock(
    development_summary: dict[str, Any],
    *,
    maximum_candidates: int,
    supersedes_candidate_lock_id: str | None = None,
) -> dict[str, Any]:
    """Freeze V0.4 candidates, gates, and comparators from development only."""

    if (
        development_summary.get("schema_version") != "lumi-trace-v0.4-private-baseline-summary-v1"
        or development_summary.get("partition") != "ENGINEERING_DEVELOPMENT"
        or development_summary.get("group_count", 0) < 100
        or development_summary.get("family_count", 0) < 8
        or development_summary.get("qualification_consumed") is not False
        or development_summary.get("holdback_opened") is not False
    ):
        raise PolicyError("V0_4_DEVELOPMENT_SUMMARY_NOT_LOCKABLE")
    if development_summary.get("maximum_candidates") != maximum_candidates:
        raise PolicyError("V0_4_CANDIDATE_LIMIT_MISMATCH")
    algorithms = development_summary.get("algorithms")
    eligible = ("lexical", "sparse")
    required = (*eligible, "v0.1.2")
    if not isinstance(algorithms, dict) or any(name not in algorithms for name in required):
        raise PolicyError("V0_4_FROZEN_COMPARATORS_INCOMPLETE")
    selected = max(
        eligible,
        key=lambda name: _deterministic_selection_key(name, algorithms[name]),
    )
    metric_specification = v04_metric_specification()
    value = {
        "schema_version": "lumi-trace-v0.4-private-candidate-lock-v1",
        "development_summary_id": development_summary["summary_id"],
        "development_group_count": development_summary["group_count"],
        "development_family_count": development_summary["family_count"],
        "candidate_generation": {
            "algorithm": development_summary.get(
                "candidate_generation_algorithm",
                "v0.4-label-blind-python-candidates-v1",
            ),
            "maximum_candidates": maximum_candidates,
            "path_quarantine_policy": RECONSIDERED_PATH_QUARANTINE_POLICY,
            "labels_available_during_generation": False,
            "file_coverage_reserved_before_symbols": (
                development_summary.get("candidate_generation_algorithm")
                == CANDIDATE_GENERATION_ALGORITHM
            ),
            "selection_policy": (
                "QUERY_AWARE_IDF_FILE_SYMBOL_HYBRID"
                if development_summary.get("candidate_generation_algorithm")
                == CANDIDATE_GENERATION_ALGORITHM
                else "LEGACY"
            ),
            "audited_target_quarantine_override": "TARGET_PATH_IDENTITY_ONLY",
        },
        "supersedes_candidate_lock_id": supersedes_candidate_lock_id,
        "locked_comparators": [
            "v0.1.2",
            "lexical",
            "sparse",
            "random",
            "always_abstain",
        ],
        "selected_deterministic_comparator": selected,
        "selection_policy": [
            "maximum_locked_gate_count",
            "location_role_correct_recall_at_20",
            "file_recall_at_20",
            "repository_family_macro_recall_at_20",
            "mean_reciprocal_rank",
            "minimum_hard_negative_outrank",
            "maintenance_preference",
        ],
        "learned_selection_rule": {
            "minimum_material_metric_gain": 0.02,
            "minimum_improved_families": 2,
            "identifier_ablation_recall_at_20_minimum": 0.50,
            "maximum_identifier_ablation_recall_drop": 0.25,
            "safety_floors_may_weaken": False,
            "local_cpu_inference_required": True,
        },
        "metric_specification_id": metric_specification["record_id"],
        "metric_gates": metric_specification["payload"]["gates"],
        "objective": "PYTHON_FINDING_GUIDED_CANDIDATE_RANKING_AND_LOCATION_ROLE",
        "positive_claim_scope": "CANDIDATE_RANKING_ONLY",
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "training_started": False,
        "weights_downloaded": False,
    }
    value["candidate_lock_id"] = stable_id("v0.4-candidate-lock", value)
    return value


def lock_candidates(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    if args.development_summary is None:
        raise ValueError("--development-summary is required for lock-candidates")
    summary_path = args.development_summary.resolve()
    if not summary_path.is_relative_to(private_root / "manifests"):
        raise ValueError("development summary must be a governed private manifest")
    legacy_path = private_root / "manifests" / "v0.4-candidate-lock.json"
    revised_path = private_root / "manifests" / _RECONSIDERED_LOCK
    if revised_path.exists():
        raise PolicyError("V0_4_CANDIDATE_LOCK_RECONSIDERATION_ALREADY_EXISTS")
    supersedes = load_json(legacy_path)["candidate_lock_id"] if legacy_path.is_file() else None
    candidate_lock = build_candidate_lock(
        load_json(summary_path),
        maximum_candidates=args.maximum_candidates,
        supersedes_candidate_lock_id=supersedes,
    )
    if (
        supersedes is not None
        and candidate_lock["candidate_generation"]["algorithm"] != CANDIDATE_GENERATION_ALGORITHM
    ):
        raise PolicyError("V0_4_CANDIDATE_LOCK_RECONSIDERATION_NOT_GENERAL")
    _write_once(
        revised_path if supersedes is not None else legacy_path,
        candidate_lock,
    )
    return {
        "candidate_lock_id": candidate_lock["candidate_lock_id"],
        "selected_deterministic_comparator": candidate_lock["selected_deterministic_comparator"],
        "development_group_count": candidate_lock["development_group_count"],
        "development_family_count": candidate_lock["development_family_count"],
        "qualification_state": candidate_lock["qualification_state"],
        "protected_holdback_state": candidate_lock["protected_holdback_state"],
        "training_started": False,
    }


def build_training_execution_lock(
    *,
    candidate_lock_id: str,
    training_code_sha256: str,
    feature_code_sha256: str,
    dependency_lock_sha256: str,
    config: TrainingConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Describe the from-scratch supply chain and bounded training execution."""

    supply_chain = {
        "schema_version": "lumi-trace-v0.4-private-model-supply-chain-v1",
        "candidate_lock_id": candidate_lock_id,
        "model_origin": "FROM_SCRATCH_LINEAR",
        "foundation_model": None,
        "tokenizer": None,
        "external_weights": [],
        "downloads_required": False,
        "remote_code": False,
        "executable_model_artifacts": False,
        "checkpoint_format": "CANONICAL_JSON_NUMERIC_WEIGHTS",
        "checkpoint_schema": "trace-001-linear-ranker-v1",
        "intended_use": "LOCAL_CANDIDATE_RERANKING",
        "licence_state": "SKYLARK_OWNED_TRAINING_OUTPUT_NOT_PUBLICATION_AUTHORISED",
        "offline_loading_required": True,
        "sealed_inference_network": "DENIED",
    }
    supply_chain["supply_chain_id"] = stable_id(
        "v0.4-model-supply-chain",
        supply_chain,
    )
    execution_lock = {
        "schema_version": "lumi-trace-v0.4-private-training-execution-lock-v1",
        "candidate_lock_id": candidate_lock_id,
        "supply_chain_id": supply_chain["supply_chain_id"],
        "training_code": {
            "path": "eval/src/trace_eval/trace001.py",
            "sha256": training_code_sha256,
        },
        "feature_code": {
            "path": "eval/src/trace_eval/features.py",
            "sha256": feature_code_sha256,
        },
        "dependency_lock": {
            "path": "eval/requirements/trace-eval.lock",
            "sha256": dependency_lock_sha256,
        },
        "configuration": config.as_dict(),
        "objective": "PAIRWISE_HINGE_RANKING_AND_LOCATION_ROLE",
        "checkpoint_policy": {
            "format": "CANONICAL_JSON_ONLY",
            "identity_verified_before_load": True,
            "resume_requires_data_and_manifest_identity": True,
            "public_weight_release_authorised": False,
        },
        "resource_limits": {
            "execution": "LOCAL_ONLY",
            "cpu_capable_required": True,
            "maximum_active_parameters": 1_000_000_000,
            "maximum_quantized_artifact_bytes": 2 * 1024 * 1024 * 1024,
            "maximum_groups": config.maximum_groups,
            "maximum_candidates_per_group": config.maximum_candidates_per_group,
            "maximum_pairs_per_group": config.maximum_pairs_per_group,
        },
        "training_authority": "CONDITIONAL_ON_FINAL_SECTION_17_READINESS",
        "training_started": False,
        "weights_downloaded": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }
    execution_lock["execution_lock_id"] = stable_id(
        "v0.4-training-execution-lock",
        execution_lock,
    )
    return supply_chain, execution_lock


def freeze_training_execution(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    candidate_lock = _active_candidate_lock(private_root)
    if (
        candidate_lock.get("schema_version") != "lumi-trace-v0.4-private-candidate-lock-v1"
        or candidate_lock.get("training_started") is not False
        or candidate_lock.get("qualification_state") != "SEALED_UNOPENED"
        or candidate_lock.get("protected_holdback_state") != "SEALED_UNOPENED"
    ):
        raise PolicyError("V0_4_CANDIDATE_LOCK_INVALID")
    config = TrainingConfig(
        maximum_candidates_per_group=args.maximum_candidates,
        maximum_pairs_per_group=args.maximum_pairs_per_group,
    )
    supply_chain, execution_lock = build_training_execution_lock(
        candidate_lock_id=candidate_lock["candidate_lock_id"],
        training_code_sha256=sha256_file(EVAL_SRC / "trace_eval" / "trace001.py"),
        feature_code_sha256=sha256_file(EVAL_SRC / "trace_eval" / "features.py"),
        dependency_lock_sha256=sha256_file(ROOT / "eval" / "requirements" / "trace-eval.lock"),
        config=config,
    )
    reconsidered = candidate_lock.get("supersedes_candidate_lock_id") is not None
    supply_path = (
        private_root
        / "manifests"
        / (_RECONSIDERED_SUPPLY_CHAIN if reconsidered else "trace-001-model-supply-chain.json")
    )
    execution_path = (
        private_root
        / "manifests"
        / (
            _RECONSIDERED_EXECUTION_LOCK
            if reconsidered
            else "trace-001-training-execution-lock.json"
        )
    )
    _write_once(supply_path, supply_chain)
    _write_once(execution_path, execution_lock)
    return {
        "supply_chain_id": supply_chain["supply_chain_id"],
        "execution_lock_id": execution_lock["execution_lock_id"],
        "foundation_model": None,
        "tokenizer": None,
        "external_weights": 0,
        "training_authority": execution_lock["training_authority"],
        "training_started": False,
    }


def remediate_training_identity(args: argparse.Namespace) -> dict[str, Any]:
    """Record the failed preflight and supersede only the training-code lock."""

    private_root = _require_root(args.private_root, "G:")
    manifests = private_root / "manifests"
    old_execution_path = manifests / _RECONSIDERED_EXECUTION_LOCK
    old_gates_path = manifests / "training-entry-gates-final.json"
    old_readiness_path = manifests / "training-readiness-final.json"
    if not all(path.is_file() for path in (old_execution_path, old_gates_path, old_readiness_path)):
        raise PolicyError("TRACE_001_IDENTITY_REMEDIATION_PREREQUISITE_MISSING")
    old_execution = load_json(old_execution_path)
    old_gates = load_json(old_gates_path)
    old_readiness = load_json(old_readiness_path)
    supply_chain = load_json(manifests / _RECONSIDERED_SUPPLY_CHAIN)
    candidate_lock = _active_candidate_lock(private_root)
    if (
        old_readiness["payload"]["recommendation"] != "TRACE_001_EXECUTION_AUTHORISED"
        or old_gates["evidence"]["execution_lock_id"] != old_execution["execution_lock_id"]
        or old_execution["candidate_lock_id"] != candidate_lock["candidate_lock_id"]
        or old_execution["supply_chain_id"] != supply_chain["supply_chain_id"]
        or (private_root / "models" / "trace-001" / "checkpoint.json").exists()
        or (manifests / "trace-001-training-receipt.json").exists()
        or (manifests / "qualification-consumption-start.json").exists()
        or load_json(manifests / "final-partition-seal.json")["payload"]["holdback_state"]
        != "SEALED_UNOPENED"
    ):
        raise PolicyError("TRACE_001_IDENTITY_REMEDIATION_BOUNDARY_REJECTED")
    current_training_hash = sha256_file(EVAL_SRC / "trace_eval" / "trace001.py")
    if (
        current_training_hash == old_execution["training_code"]["sha256"]
        or sha256_file(EVAL_SRC / "trace_eval" / "features.py")
        != old_execution["feature_code"]["sha256"]
        or sha256_file(ROOT / "eval" / "requirements" / "trace-eval.lock")
        != old_execution["dependency_lock"]["sha256"]
    ):
        raise PolicyError("TRACE_001_IDENTITY_REMEDIATION_SCOPE_REJECTED")
    failure = {
        "schema_version": "lumi-trace-v0.4-private-training-preflight-failure-v1",
        "readiness_id": old_readiness["record_id"],
        "gate_record_id": old_gates["gate_record_id"],
        "execution_lock_id": old_execution["execution_lock_id"],
        "failure_category": "CANONICAL_JSON_ITEM_LIMIT",
        "failure_stage": "TRAINING_DATA_IDENTITY_CONSTRUCTION",
        "cause": "MONOLITHIC_CANONICAL_IDENTITY_EXCEEDED_HARDENED_ITEM_BOUND",
        "training_command_invoked": True,
        "optimizer_started": False,
        "checkpoint_written": False,
        "qualification_opened": False,
        "holdback_opened": False,
        "weights_downloaded": False,
        "remediation_scope": "BOUNDED_PER_GROUP_MERKLE_STYLE_IDENTITY",
    }
    failure["failure_id"] = stable_id("v0.4-training-preflight-failure", failure)
    config = TrainingConfig(**old_execution["configuration"])
    _unused_supply, remediated_execution = build_training_execution_lock(
        candidate_lock_id=candidate_lock["candidate_lock_id"],
        training_code_sha256=current_training_hash,
        feature_code_sha256=old_execution["feature_code"]["sha256"],
        dependency_lock_sha256=old_execution["dependency_lock"]["sha256"],
        config=config,
    )
    remediated_execution.pop("execution_lock_id")
    remediated_execution["supersedes_execution_lock_id"] = old_execution["execution_lock_id"]
    remediated_execution["preflight_failure_id"] = failure["failure_id"]
    remediated_execution["identity_construction"] = (
        "BOUNDED_PER_GROUP_IDENTITIES_THEN_AGGREGATE_IDENTITY"
    )
    remediated_execution["execution_lock_id"] = stable_id(
        "v0.4-training-execution-lock",
        remediated_execution,
    )
    _write_once(manifests / _IDENTITY_REMEDIATION_FAILURE, failure)
    _write_once(
        manifests / _IDENTITY_REMEDIATION_EXECUTION_LOCK,
        remediated_execution,
    )
    return {
        "failure_id": failure["failure_id"],
        "superseded_execution_lock_id": old_execution["execution_lock_id"],
        "execution_lock_id": remediated_execution["execution_lock_id"],
        "optimizer_started": False,
        "checkpoint_written": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }


def build_final_entry_gates(
    *,
    training_manifest: dict[str, Any],
    partition_seal: dict[str, Any],
    candidate_lock: dict[str, Any],
    development_summary: dict[str, Any],
    training_summary: dict[str, Any],
    supply_chain: dict[str, Any],
    execution_lock: dict[str, Any],
    item_audits_passed: bool,
    training_rights_passed: bool,
    controlled_labels_passed: bool,
    poisoning_and_provenance_passed: bool,
) -> dict[str, Any]:
    """Derive every Section 17 gate from sealed, identity-bearing evidence."""

    if (
        training_manifest.get("schema_version") != "training-eligibility-manifest-v1"
        or partition_seal.get("schema_version") != "partition-seal-v1"
        or candidate_lock.get("schema_version") != "lumi-trace-v0.4-private-candidate-lock-v1"
        or development_summary.get("partition") != "ENGINEERING_DEVELOPMENT"
        or training_summary.get("partition") != "TRAINING"
        or supply_chain.get("schema_version") != "lumi-trace-v0.4-private-model-supply-chain-v1"
        or execution_lock.get("schema_version")
        != "lumi-trace-v0.4-private-training-execution-lock-v1"
    ):
        raise PolicyError("V0_4_TRAINING_GATE_INPUT_INVALID")
    selected = candidate_lock["selected_deterministic_comparator"]
    if selected not in development_summary["algorithms"]:
        raise PolicyError("V0_4_SELECTED_COMPARATOR_MISSING")
    candidate_aggregate = training_summary["algorithms"]["sparse"]["aggregate"]
    development_aggregate = development_summary["algorithms"][selected]["aggregate"]
    gates = candidate_lock["metric_gates"]
    candidate_presence = (
        float(candidate_aggregate["target_indexability"]) >= gates["target_indexability_minimum"]
    )
    ordering_or_role_shortfall = any(
        (
            development_aggregate["file_recall_at_5"] < gates["file_recall_at_5_minimum"],
            development_aggregate["file_recall_at_10"] < gates["file_recall_at_10_minimum"],
            development_aggregate["file_recall_at_20"] < gates["file_recall_at_20_minimum"],
            development_aggregate["location_role_correct_recall_at_20"]
            < gates["location_role_correct_recall_at_20_minimum"],
            development_aggregate["mean_reciprocal_rank"] < gates["mean_reciprocal_rank_minimum"],
            development_aggregate["hard_negative_outrank"] > gates["hard_negative_outrank_maximum"],
            development_aggregate["repository_family_macro_recall_at_20"]
            < gates["repository_family_macro_recall_at_20_minimum"],
            development_aggregate["minimum_family_recall_at_20"]
            < gates["minimum_family_recall_at_20_minimum"],
            development_aggregate["zero_recall_family_count"]
            > gates["zero_recall_family_count_maximum"],
        )
    )
    assignments = partition_seal["payload"]["assignments"]
    family_partitions: dict[str, set[str]] = {}
    for assignment in assignments:
        family_partitions.setdefault(assignment["family_id"], set()).add(assignment["partition"])
    partitions_sealed_disjoint = (
        partition_seal["payload"].get("sealed_before_training") is True
        and partition_seal["payload"].get("holdback_state") == "SEALED_UNOPENED"
        and not any(len(partitions) != 1 for partitions in family_partitions.values())
        and training_manifest["payload"]["partition_seal_id"] == partition_seal["record_id"]
    )
    baseline_names = set(development_summary["algorithms"])
    baselines_locked = (
        set(candidate_lock["locked_comparators"]) <= baseline_names | {"random", "always_abstain"}
        and development_summary["summary_id"] == candidate_lock["development_summary_id"]
    )
    model_supply_chain = (
        supply_chain["candidate_lock_id"] == candidate_lock["candidate_lock_id"]
        and supply_chain["foundation_model"] is None
        and supply_chain["tokenizer"] is None
        and supply_chain["external_weights"] == []
        and supply_chain["downloads_required"] is False
        and supply_chain["remote_code"] is False
    )
    training_code_and_resources = (
        execution_lock["candidate_lock_id"] == candidate_lock["candidate_lock_id"]
        and execution_lock["supply_chain_id"] == supply_chain["supply_chain_id"]
        and execution_lock["training_started"] is False
        and execution_lock["checkpoint_policy"]["public_weight_release_authorised"] is False
        and execution_lock["resource_limits"]["execution"] == "LOCAL_ONLY"
    )
    gate_values = {
        "item_audits": item_audits_passed,
        "training_rights": training_rights_passed,
        "lineage_and_duplicate_audit": partitions_sealed_disjoint,
        "controlled_labels": controlled_labels_passed,
        "poison_secret_privacy_provenance": poisoning_and_provenance_passed,
        "target_indexability": candidate_presence,
        "candidate_presence": candidate_presence,
        "ordering_gap": candidate_presence and ordering_or_role_shortfall,
        "baselines_locked": baselines_locked,
        "objective_and_metrics_locked": (
            candidate_lock["metric_specification_id"] == v04_metric_specification()["record_id"]
            and candidate_lock["objective"]
            == "PYTHON_FINDING_GUIDED_CANDIDATE_RANKING_AND_LOCATION_ROLE"
        ),
        "partitions_sealed_disjoint": partitions_sealed_disjoint,
        "model_supply_chain": model_supply_chain,
        "training_code_and_resources": training_code_and_resources,
        "qualification_holdback_blind": (
            candidate_lock["qualification_state"] == "SEALED_UNOPENED"
            and candidate_lock["protected_holdback_state"] == "SEALED_UNOPENED"
        ),
    }
    value = {
        "schema_version": "lumi-trace-v0.4-final-entry-gates-v1",
        "gates": {
            "minimum_500_groups": training_manifest["payload"]["group_count"] >= 500,
            "minimum_25_families": training_manifest["payload"]["family_count"] >= 25,
            **gate_values,
        },
        "evidence": {
            "training_manifest_id": training_manifest["record_id"],
            "partition_seal_id": partition_seal["record_id"],
            "candidate_lock_id": candidate_lock["candidate_lock_id"],
            "development_summary_id": development_summary["summary_id"],
            "training_preprocessing_summary_id": training_summary["summary_id"],
            "supply_chain_id": supply_chain["supply_chain_id"],
            "execution_lock_id": execution_lock["execution_lock_id"],
        },
        "candidate_presence_rate": candidate_aggregate["target_indexability"],
        "selected_deterministic_comparator": selected,
        "remaining_gap_is_ordering_or_role": candidate_presence and ordering_or_role_shortfall,
        "qualification_opened": False,
        "holdback_opened": False,
        "training_started": False,
        "weights_downloaded": False,
    }
    value["gate_record_id"] = stable_id("v0.4-final-entry-gates", value)
    return value


def assess_training_readiness(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    if args.development_summary is None or args.training_summary is None:
        raise ValueError(
            "--development-summary and --training-summary are required for "
            "assess-training-readiness"
        )
    governed_manifests = (private_root / "manifests").resolve()
    summary_paths = (
        args.development_summary.resolve(),
        args.training_summary.resolve(),
    )
    if any(not path.is_relative_to(governed_manifests) for path in summary_paths):
        raise ValueError("baseline summaries must be governed private manifests")
    training_manifest = load_json(private_root / "manifests" / "training-eligibility-manifest.json")
    partition_seal = load_json(private_root / "manifests" / "final-partition-seal.json")
    candidate_lock = _active_candidate_lock(private_root)
    development_summary = load_json(summary_paths[0])
    training_summary = load_json(summary_paths[1])
    supply_chain, execution_lock = _active_training_locks(private_root)
    code_hashes_passed = (
        execution_lock["training_code"]["sha256"]
        == sha256_file(EVAL_SRC / "trace_eval" / "trace001.py")
        and execution_lock["feature_code"]["sha256"]
        == sha256_file(EVAL_SRC / "trace_eval" / "features.py")
        and execution_lock["dependency_lock"]["sha256"]
        == sha256_file(ROOT / "eval" / "requirements" / "trace-eval.lock")
    )
    cards_by_id = {
        card["record_id"]: card
        for card in (
            load_json(path)
            for path in sorted(
                (private_root / "manifests" / "audit-cards" / "training").glob("*.json")
            )
        )
    }
    rights_by_id = {
        rights["record_id"]: rights
        for rights in (
            load_json(path)
            for path in sorted((private_root / "rights" / "matrices").glob("*.json"))
        )
    }
    allowlist = set(training_manifest["payload"]["audit_card_ids"])
    item_audits_passed = allowlist <= set(cards_by_id)
    training_rights_passed = item_audits_passed
    controlled_labels_passed = item_audits_passed
    poisoning_and_provenance_passed = item_audits_passed
    for card_id in sorted(allowlist):
        card = cards_by_id[card_id]
        rights = rights_by_id.get(card["payload"]["rights_matrix_id"])
        if rights is None:
            training_rights_passed = False
            continue
        try:
            validate_group_audit_card(card, rights_matrix=rights)
        except (ContractError, PolicyError):
            item_audits_passed = False
            training_rights_passed = False
            controlled_labels_passed = False
            poisoning_and_provenance_passed = False
            continue
        training_rights_passed &= rights["payload"]["review_status"] == "APPROVED"
        controlled_labels_passed &= (
            card["payload"]["audits"]["controlled_review"] == "PASSED"
            and card["payload"]["label"]["constructed_without_runner_or_model_output"] is True
        )
        poisoning_and_provenance_passed &= all(
            card["payload"]["audits"][dimension] == "PASSED"
            for dimension in (
                "poisoning",
                "secrets",
                "privacy",
                "provenance",
                "answer_leakage",
            )
        )
    final_gates = build_final_entry_gates(
        training_manifest=training_manifest,
        partition_seal=partition_seal,
        candidate_lock=candidate_lock,
        development_summary=development_summary,
        training_summary=training_summary,
        supply_chain=supply_chain,
        execution_lock=execution_lock,
        item_audits_passed=item_audits_passed,
        training_rights_passed=training_rights_passed,
        controlled_labels_passed=controlled_labels_passed,
        poisoning_and_provenance_passed=(poisoning_and_provenance_passed and code_hashes_passed),
    )
    readiness = evaluate_training_readiness(
        training_manifest,
        gates={
            key: value
            for key, value in final_gates["gates"].items()
            if key not in {"minimum_500_groups", "minimum_25_families"}
        },
        qualification_opened=False,
        holdback_opened=False,
    )
    gates_path, readiness_path = _active_final_authority_paths(private_root)
    _write_once(gates_path, final_gates)
    _write_once(readiness_path, readiness)
    return {
        "gate_record_id": final_gates["gate_record_id"],
        "readiness_id": readiness["record_id"],
        "recommendation": readiness["payload"]["recommendation"],
        "failed_gates": sorted(key for key, passed in final_gates["gates"].items() if not passed),
        "training_started": False,
        "weights_downloaded": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }


def lock_qualification(args: argparse.Namespace) -> dict[str, Any]:
    """Select once on model-selection evidence and freeze qualification use."""

    private_root = _require_root(args.private_root, "G:")
    if args.model_selection_summary is None:
        raise ValueError("--model-selection-summary is required for lock-qualification")
    baseline_path = args.model_selection_summary.resolve()
    if not baseline_path.is_relative_to((private_root / "manifests").resolve()):
        raise ValueError("model-selection summary must be a governed private manifest")
    baseline = load_json(baseline_path)
    candidate_lock = _active_candidate_lock(private_root)
    if (
        baseline.get("schema_version") != "lumi-trace-v0.4-private-baseline-summary-v1"
        or baseline.get("partition") != "MODEL_SELECTION"
        or baseline.get("group_count", 0) < 100
        or baseline.get("family_count", 0) < 8
        or baseline.get("candidate_lock_id") != candidate_lock["candidate_lock_id"]
        or baseline.get("qualification_consumed") is not False
        or baseline.get("holdback_opened") is not False
    ):
        raise PolicyError("V0_4_MODEL_SELECTION_SUMMARY_NOT_LOCKABLE")
    selected_baseline = candidate_lock["selected_deterministic_comparator"]
    baseline_aggregate = baseline["algorithms"][selected_baseline]["aggregate"]
    learned: dict[str, Any] | None = None
    learned_advances = False
    selection_evidence: dict[str, Any] = {
        "material_gain": False,
        "improved_multiple_families": False,
        "safety_floors_preserved": False,
        "cue_ablation_passed": False,
        "local_cpu_capable": False,
    }
    if args.learned_summary is not None:
        learned_path = args.learned_summary.resolve()
        if not learned_path.is_relative_to((private_root / "manifests").resolve()):
            raise ValueError("learned summary must be a governed private manifest")
        learned = load_json(learned_path)
        if (
            learned.get("schema_version") != "lumi-trace-v0.4-private-trace-001-grouped-summary-v1"
            or learned.get("partition") != "MODEL_SELECTION"
            or learned.get("candidate_lock_id") != candidate_lock["candidate_lock_id"]
            or learned.get("group_count") != baseline["group_count"]
            or learned.get("family_count") != baseline["family_count"]
            or learned.get("qualification_opened") is not False
            or learned.get("holdback_opened") is not False
        ):
            raise PolicyError("TRACE_001_MODEL_SELECTION_SUMMARY_NOT_LOCKABLE")
        rule = candidate_lock["learned_selection_rule"]
        full = learned["views"]["FULL"]
        learned_aggregate = full["aggregate"]
        metric_gains = {
            metric: learned_aggregate[metric] - baseline_aggregate[metric]
            for metric in (
                "location_role_correct_recall_at_20",
                "file_recall_at_20",
                "repository_family_macro_recall_at_20",
                "mean_reciprocal_rank",
            )
        }
        identifier = learned["views"]["IDENTIFIER_ABLATION"]["aggregate"]
        selection_evidence = {
            "material_gain": max(metric_gains.values()) >= rule["minimum_material_metric_gain"],
            "metric_gains": metric_gains,
            "improved_multiple_families": learned["family_improvement_count"]
            >= rule["minimum_improved_families"],
            "safety_floors_preserved": all(
                full["gate_results"][name]
                for name in (
                    "valid_attempt_completion",
                    "target_indexability",
                    "false_supported_disposition",
                    "false_vulnerability_safe_control",
                    "unsafe_non_abstention",
                )
            ),
            "cue_ablation_passed": (
                identifier["file_recall_at_20"] >= rule["identifier_ablation_recall_at_20_minimum"]
                and learned_aggregate["file_recall_at_20"] - identifier["file_recall_at_20"]
                <= rule["maximum_identifier_ablation_recall_drop"]
            ),
            "local_cpu_capable": learned["resources"]["local_cpu_inference"] is True,
        }
        learned_advances = all(
            value for key, value in selection_evidence.items() if key != "metric_gains"
        )
    selection = (
        {
            "kind": "TRACE_001_LINEAR",
            "identity": learned["checkpoint_id"],
            "reason": "MATERIAL_GROUPED_MODEL_SELECTION_ADVANTAGE",
        }
        if learned_advances and learned is not None
        else {
            "kind": "DETERMINISTIC",
            "identity": selected_baseline,
            "reason": (
                "NO_MODEL_ADVANTAGE" if learned is not None else "NO_AUTHORISED_LEARNED_CANDIDATE"
            ),
        }
    )
    sample_plan = load_json(private_root / "manifests" / "corpus-sample-plan.json")
    qualification_lock = {
        "schema_version": "lumi-trace-v0.4-private-qualification-lock-v1",
        "candidate_lock_id": candidate_lock["candidate_lock_id"],
        "model_selection_baseline_summary_id": baseline["summary_id"],
        "model_selection_learned_summary_id": (
            learned["summary_id"] if learned is not None else None
        ),
        "selected_candidate": selection,
        "selection_evidence": selection_evidence,
        "locked_comparators": candidate_lock["locked_comparators"],
        "metric_specification_id": candidate_lock["metric_specification_id"],
        "metric_gates": candidate_lock["metric_gates"],
        "maximum_candidates": candidate_lock["candidate_generation"]["maximum_candidates"],
        "qualification_primary_budget": sample_plan["payload"]["qualification"][
            "minimum_primary_targets"
        ],
        "qualification_control_budget": sample_plan["payload"]["qualification"][
            "minimum_matched_safe_controls"
        ],
        "minimum_families": sample_plan["payload"]["qualification"]["minimum_families"],
        "single_use": True,
        "qualification_state": "SEALED_UNOPENED",
        "holdback_state": "SEALED_UNOPENED",
        "thresholds_changed_after_model_selection": False,
        "public_weight_release_authorised": False,
    }
    qualification_lock["qualification_lock_id"] = stable_id(
        "v0.4-qualification-lock",
        qualification_lock,
    )
    budget = {
        "schema_version": "lumi-trace-v0.4-private-qualification-budget-v1",
        "qualification_lock_id": qualification_lock["qualification_lock_id"],
        "runs_authorised": 1,
        "runs_consumed": 0,
        "remaining_runs": 1,
        "state": "SEALED_UNOPENED",
        "holdback_state": "SEALED_UNOPENED",
    }
    budget["budget_id"] = stable_id("v0.4-qualification-budget", budget)
    _write_once(
        private_root / "manifests" / "qualification-lock.json",
        qualification_lock,
    )
    _write_once(
        private_root / "manifests" / "qualification-budget-before.json",
        budget,
    )
    return {
        "qualification_lock_id": qualification_lock["qualification_lock_id"],
        "selected_candidate_kind": selection["kind"],
        "selection_reason": selection["reason"],
        "learned_candidate_advanced": learned_advances,
        "qualification_runs_remaining": 1,
        "qualification_state": "SEALED_UNOPENED",
        "holdback_state": "SEALED_UNOPENED",
    }


def qualify(args: argparse.Namespace) -> dict[str, Any]:
    """Consume the locked qualification partition exactly once."""

    private_root = _require_root(args.private_root, "G:")
    work_root = _require_root(args.work_root, "F:")
    qualification_lock = load_json(private_root / "manifests" / "qualification-lock.json")
    budget = load_json(private_root / "manifests" / "qualification-budget-before.json")
    candidate_lock = _active_candidate_lock(private_root)
    partition_seal = load_json(private_root / "manifests" / "final-partition-seal.json")
    consumption_path = private_root / "manifests" / "qualification-consumption-start.json"
    result_path = private_root / "manifests" / "qualification-result.json"
    if consumption_path.exists() or result_path.exists():
        raise PolicyError("V0_4_QUALIFICATION_BUDGET_ALREADY_CONSUMED")
    if (
        qualification_lock.get("schema_version") != "lumi-trace-v0.4-private-qualification-lock-v1"
        or qualification_lock["candidate_lock_id"] != candidate_lock["candidate_lock_id"]
        or qualification_lock["qualification_state"] != "SEALED_UNOPENED"
        or qualification_lock["holdback_state"] != "SEALED_UNOPENED"
        or budget["qualification_lock_id"] != qualification_lock["qualification_lock_id"]
        or budget["runs_authorised"] != 1
        or budget["runs_consumed"] != 0
        or budget["remaining_runs"] != 1
        or partition_seal["payload"]["holdback_state"] != "SEALED_UNOPENED"
    ):
        raise PolicyError("V0_4_QUALIFICATION_LOCK_INVALID")
    allowed_card_ids = {
        assignment["audit_card_id"]
        for assignment in partition_seal["payload"]["assignments"]
        if assignment["partition"] == "QUALIFICATION"
    }
    cards = [
        load_json(path)
        for path in sorted(
            (private_root / "manifests" / "audit-cards" / "qualification").glob("*.json")
        )
    ]
    cards = [card for card in cards if card["record_id"] in allowed_card_ids]
    family_count = len({card["payload"]["family_id"] for card in cards})
    matched_controls = sum(bool(card["payload"]["controls"]) for card in cards)
    if (
        len(cards) < qualification_lock["qualification_primary_budget"]
        or matched_controls < qualification_lock["qualification_control_budget"]
        or family_count < qualification_lock["minimum_families"]
        or {card["record_id"] for card in cards} != allowed_card_ids
    ):
        raise PolicyError("V0_4_QUALIFICATION_DENOMINATOR_BELOW_LOCK")
    consumption = {
        "schema_version": "lumi-trace-v0.4-private-qualification-consumption-v1",
        "qualification_lock_id": qualification_lock["qualification_lock_id"],
        "budget_id": budget["budget_id"],
        "selected_candidate": qualification_lock["selected_candidate"],
        "group_count": len(cards),
        "family_count": family_count,
        "matched_control_count": matched_controls,
        "state": "CONSUMING_SINGLE_USE_QUALIFICATION",
        "holdback_opened": False,
        "thresholds_changed": False,
    }
    consumption["consumption_id"] = stable_id(
        "v0.4-qualification-consumption",
        consumption,
    )
    _write_once(consumption_path, consumption)
    maximum_candidates = qualification_lock["maximum_candidates"]
    feature_root = private_root / "runs" / "private" / "baselines" / "qualification"
    selected = qualification_lock["selected_candidate"]
    checkpoint: dict[str, Any] | None = None
    if selected["kind"] == "TRACE_001_LINEAR":
        checkpoint = load_json(private_root / "models" / "trace-001" / "checkpoint.json")
        verify_checkpoint(checkpoint)
        if checkpoint["checkpoint_id"] != selected["identity"]:
            raise PolicyError("V0_4_QUALIFICATION_CHECKPOINT_MISMATCH")
    if not 1 <= args.workers <= 8:
        raise ValueError("--workers must be between 1 and 8")
    tasks = [
        (
            str(private_root),
            str(work_root),
            card,
            maximum_candidates,
            True,
            True,
        )
        for card in cards
    ]
    learned_metrics: list[dict[str, Any]] = []
    wall_start = time.perf_counter()
    if args.workers == 1:
        prepared = [_prepare_card_worker(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            prepared = list(executor.map(_prepare_card_worker, tasks))
    records = [record for record, _ in prepared]
    v012_records = [record for _, record in prepared if record is not None]
    if len(v012_records) != len(records):
        raise PolicyError("V0_4_QUALIFICATION_V012_RESULT_INCOMPLETE")
    if checkpoint is not None:
        with _python_network_denied():
            for record in records:
                token = record["group_id"].split(":", 1)[1][:24]
                full_record = load_json(
                    feature_root / f"{token}.{CANDIDATE_CACHE_TOKEN}.c{maximum_candidates}.json"
                )
                inference = [
                    {
                        "candidate_id": candidate["candidate_id"],
                        "features": candidate["features"],
                    }
                    for candidate in full_record["training_candidates"]
                ]
                ranked = rank_with_checkpoint(checkpoint, inference)
                labels = full_record["private_scoring_labels"]
                learned_metrics.append(
                    score_v04_group(
                        ranked,
                        file_target_candidate_ids=set(labels["file_target_candidate_ids"]),
                        role_target_candidate_ids=set(labels["role_target_candidate_ids"]),
                        hard_negative_candidate_ids=set(labels["hard_negative_candidate_ids"]),
                        family_id=full_record["family_id"],
                    )
                )
    algorithms: dict[str, Any] = {}
    algorithm_results: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        for score in record["baseline_scores"]:
            algorithm_results.setdefault(score["algorithm"], []).append(score["metrics"])
    for name, metrics in sorted(algorithm_results.items()):
        aggregate = aggregate_v04(metrics)
        gate_results = _gate_results(aggregate)
        algorithms[name] = {
            "aggregate": aggregate,
            "confidence_intervals": _confidence_intervals(metrics),
            "gate_results": gate_results,
            "all_gates_passed": all(gate_results.values()),
        }
    v012_metrics = [record["metrics"] for record in v012_records]
    v012_aggregate = aggregate_v04(v012_metrics)
    v012_gates = _gate_results(v012_aggregate)
    algorithms["v0.1.2"] = {
        "aggregate": v012_aggregate,
        "confidence_intervals": _confidence_intervals(v012_metrics),
        "gate_results": v012_gates,
        "all_gates_passed": all(v012_gates.values()),
        "completed_attempts": sum(record["status"] == "COMPLETED" for record in v012_records),
        "unsupported_attempts": sum(record["status"] != "COMPLETED" for record in v012_records),
    }
    if learned_metrics:
        learned_aggregate = aggregate_v04(learned_metrics)
        learned_gates = _gate_results(learned_aggregate)
        algorithms["trace-001"] = {
            "aggregate": learned_aggregate,
            "confidence_intervals": _confidence_intervals(learned_metrics),
            "gate_results": learned_gates,
            "all_gates_passed": all(learned_gates.values()),
        }
    selected_name = "trace-001" if selected["kind"] == "TRACE_001_LINEAR" else selected["identity"]
    if selected_name not in algorithms:
        raise PolicyError("V0_4_QUALIFICATION_SELECTED_RESULT_MISSING")
    selected_result = algorithms[selected_name]
    result = {
        "schema_version": "lumi-trace-v0.4-private-qualification-result-v1",
        "qualification_lock_id": qualification_lock["qualification_lock_id"],
        "consumption_id": consumption["consumption_id"],
        "partition_seal_id": partition_seal["record_id"],
        "selected_candidate": selected,
        "selected_result_name": selected_name,
        "selected_result": selected_result,
        "comparators": algorithms,
        "group_count": len(records),
        "family_count": family_count,
        "matched_safe_control_count": matched_controls,
        "positive_claim_scope": "CANDIDATE_RANKING_ONLY",
        "universal_abstention_can_pass": False,
        "python_network_denial_enforced": True,
        "repository_code_executed": False,
        "thresholds_changed_after_opening": False,
        "qualification_consumed": True,
        "qualification_runs_consumed": 1,
        "qualification_runs_remaining": 0,
        "holdback_opened": False,
        "wall_seconds": time.perf_counter() - wall_start,
    }
    result["result_id"] = stable_id("v0.4-qualification-result", result)
    budget_after = {
        "schema_version": "lumi-trace-v0.4-private-qualification-budget-v1",
        "qualification_lock_id": qualification_lock["qualification_lock_id"],
        "runs_authorised": 1,
        "runs_consumed": 1,
        "remaining_runs": 0,
        "state": "CONSUMED",
        "result_id": result["result_id"],
        "holdback_state": "SEALED_UNOPENED",
    }
    budget_after["budget_id"] = stable_id(
        "v0.4-qualification-budget-after",
        budget_after,
    )
    _write_once(result_path, result)
    _write_once(
        private_root / "manifests" / "qualification-budget-after.json",
        budget_after,
    )
    return {
        "result_id": result["result_id"],
        "selected_candidate_kind": selected["kind"],
        "selected_all_gates_passed": selected_result["all_gates_passed"],
        "group_count": len(records),
        "family_count": family_count,
        "matched_safe_control_count": matched_controls,
        "qualification_runs_consumed": 1,
        "qualification_runs_remaining": 0,
        "holdback_opened": False,
    }


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    work_root = _require_root(args.work_root, "F:")
    if args.partition not in PARTITIONS or args.partition == "PROTECTED_HOLDBACK":
        raise ValueError("partition is unsupported or protected holdback")
    if args.partition == "QUALIFICATION":
        raise PolicyError("V0_4_USE_SINGLE_USE_QUALIFY_PHASE")
    candidate_lock: dict[str, Any] | None = None
    if args.partition in {"TRAINING", "MODEL_SELECTION", "QUALIFICATION"}:
        if (
            not (private_root / "manifests" / _RECONSIDERED_LOCK).is_file()
            and not (private_root / "manifests" / "v0.4-candidate-lock.json").is_file()
        ):
            raise PolicyError("V0_4_CANDIDATE_LOCK_REQUIRED")
        candidate_lock = _active_candidate_lock(private_root)
        if (
            candidate_lock.get("schema_version") != "lumi-trace-v0.4-private-candidate-lock-v1"
            or candidate_lock["candidate_generation"]["maximum_candidates"]
            != args.maximum_candidates
            or candidate_lock.get("qualification_state") != "SEALED_UNOPENED"
            or candidate_lock.get("protected_holdback_state") != "SEALED_UNOPENED"
        ):
            raise PolicyError("V0_4_CANDIDATE_LOCK_INVALID")
    slug = _PARTITION_SLUG[args.partition]
    cards = [
        load_json(path)
        for path in sorted((private_root / "manifests" / "audit-cards" / slug).glob("*.json"))
    ]
    partition_seal_path = private_root / "manifests" / "final-partition-seal.json"
    if partition_seal_path.is_file():
        partition_seal = load_json(partition_seal_path)
        if partition_seal.get("schema_version") != "partition-seal-v1":
            raise PolicyError("V0_4_PARTITION_SEAL_INVALID")
        allowed_card_ids = {
            item["audit_card_id"]
            for item in partition_seal["payload"]["assignments"]
            if item["partition"] == args.partition
        }
        cards = [card for card in cards if card["record_id"] in allowed_card_ids]
    elif args.partition in {"TRAINING", "MODEL_SELECTION", "QUALIFICATION"}:
        raise PolicyError("V0_4_FINAL_PARTITION_SEAL_REQUIRED")
    if args.partition == "TRAINING":
        training_manifest = load_json(
            private_root / "manifests" / "training-eligibility-manifest.json"
        )
        training_card_ids = set(training_manifest["payload"]["audit_card_ids"])
        if (
            training_manifest.get("schema_version") != "training-eligibility-manifest-v1"
            or {card["record_id"] for card in cards} != training_card_ids
        ):
            raise PolicyError("V0_4_TRAINING_MANIFEST_CARD_MISMATCH")
    if args.maximum_groups:
        cards = cards[: args.maximum_groups]
    if not cards:
        raise PolicyError("V0_4_PARTITION_HAS_NO_AUDIT_CARDS")
    if not 1 <= args.workers <= 8:
        raise ValueError("--workers must be between 1 and 8")
    tasks = [
        (
            str(private_root),
            str(work_root),
            card,
            args.maximum_candidates,
            args.partition != "TRAINING",
            False,
        )
        for card in cards
    ]
    if args.workers == 1:
        prepared = [_prepare_card_worker(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            prepared = list(executor.map(_prepare_card_worker, tasks))
    records = [record for record, _ in prepared]
    v012_records = [record for _, record in prepared if record is not None]

    algorithm_results: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        for score in record["baseline_scores"]:
            algorithm_results.setdefault(score["algorithm"], []).append(score["metrics"])
    algorithms: dict[str, Any] = {}
    for name, results in sorted(algorithm_results.items()):
        aggregate = aggregate_v04(results)
        algorithms[name] = {
            "aggregate": aggregate,
            "confidence_intervals": _confidence_intervals(results),
            "gate_results": _gate_results(aggregate),
            "all_gates_passed": all(_gate_results(aggregate).values()),
        }
    if v012_records:
        v012_results = [record["metrics"] for record in v012_records]
        v012_aggregate = aggregate_v04(v012_results)
        v012_gate_results = _gate_results(v012_aggregate)
        algorithms["v0.1.2"] = {
            "aggregate": v012_aggregate,
            "confidence_intervals": _confidence_intervals(v012_results),
            "gate_results": v012_gate_results,
            "all_gates_passed": all(v012_gate_results.values()),
            "completed_attempts": sum(record["status"] == "COMPLETED" for record in v012_records),
            "unsupported_attempts": sum(record["status"] != "COMPLETED" for record in v012_records),
        }
    summary = {
        "schema_version": "lumi-trace-v0.4-private-baseline-summary-v1",
        "run": args.run,
        "partition": args.partition,
        "group_count": len(records),
        "family_count": len({record["family_id"] for record in records}),
        "maximum_candidates": args.maximum_candidates,
        "candidate_generation_algorithm": CANDIDATE_GENERATION_ALGORITHM,
        "candidate_cache_token": CANDIDATE_CACHE_TOKEN,
        "audited_target_quarantine_override_count": sum(
            record["audited_target_quarantine_override_count"] for record in records
        ),
        "feature_record_ids": sorted(record["record_id"] for record in records),
        "algorithms": algorithms,
        "v0_1_2_comparator": (
            "NOT_APPLICABLE_TO_TRAINING_PREPROCESSING"
            if args.partition == "TRAINING"
            else "FROZEN_RUNTIME_0_1_2_REPLAYED"
        ),
        "metric_specification_id": v04_metric_specification()["record_id"],
        "candidate_lock_id": (
            candidate_lock["candidate_lock_id"] if candidate_lock is not None else None
        ),
        "qualification_consumed": False,
        "holdback_opened": False,
        "training_started": False,
        "weights_downloaded": False,
        "repository_code_executed": False,
    }
    summary["summary_id"] = stable_id("v0.4-baseline-summary", summary)
    _write_once(
        private_root / "manifests" / f"baseline-{args.run}-{slug}.json",
        summary,
    )
    return {
        "summary_id": summary["summary_id"],
        "partition": args.partition,
        "group_count": len(records),
        "family_count": summary["family_count"],
        "algorithm_gate_results": {
            name: value["all_gates_passed"] for name, value in algorithms.items()
        },
        "qualification_consumed": False,
        "holdback_opened": False,
        "training_started": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    parser.add_argument(
        "phase",
        choices=(
            "prepare",
            "lock-candidates",
            "freeze-training-execution",
            "remediate-training-identity",
            "assess-training-readiness",
            "lock-qualification",
            "qualify",
        ),
    )
    parser.add_argument("--partition")
    parser.add_argument("--maximum-candidates", type=int, default=2_000)
    parser.add_argument("--maximum-groups", type=int, default=0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--maximum-pairs-per-group", type=int, default=256)
    parser.add_argument("--run", default="run1")
    parser.add_argument("--development-summary", type=Path)
    parser.add_argument("--training-summary", type=Path)
    parser.add_argument("--model-selection-summary", type=Path)
    parser.add_argument("--learned-summary", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if re.fullmatch(r"[a-z0-9-]{1,24}", args.run) is None:
        print("run-v0.4-experiments: --run must be a lowercase safe token", file=sys.stderr)
        return 2
    try:
        if args.phase == "prepare" and args.partition is None:
            raise ValueError("--partition is required for prepare")
        result = {
            "prepare": prepare,
            "lock-candidates": lock_candidates,
            "freeze-training-execution": freeze_training_execution,
            "remediate-training-identity": remediate_training_identity,
            "assess-training-readiness": assess_training_readiness,
            "lock-qualification": lock_qualification,
            "qualify": qualify,
        }[args.phase](args)
    except (ContractError, PolicyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"run-v0.4-experiments: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
