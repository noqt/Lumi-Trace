# SPDX-License-Identifier: Apache-2.0
"""Bounded multi-result SARIF triage built from the frozen trace pipeline."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path, PurePosixPath

from . import __version__
from .canonical import dump_json, load_json, sha256_file, stable_id
from .errors import InputError, IntegrityError
from .findings import import_sarif_batch, validate_normalized_finding
from .indexing import build_repository_index, verify_repository_index
from .localization import (
    STEP1_MAXIMUM_CANDIDATES,
    build_raw_localization,
    construct_inference_request,
)
from .pipeline import source_revision
from .ranking import project_localization_candidates, verify_candidate_set
from .reporting import build_evidence_bundle, export_sarif, verify_evidence_bundle
from .repository import RepositoryWorkspace

TRIAGE_PACKAGE_SCHEMA = "batch-triage-package-v1"
TRIAGE_PARTIAL_SUCCESS_EXIT_CODE = 5
DEFAULT_MAX_FINDINGS = 100
HARD_MAX_FINDINGS = 1_000
MAX_TRIAGE_CONTRIBUTIONS = 10_000
_RESULT_KEY = re.compile(r"^result-[0-9]{3}-[0-9]{5}-[0-9a-f]{12}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _result_key(item: dict[str, object], sarif_sha256: str) -> str:
    source = item["source"]
    if not isinstance(source, dict):
        raise IntegrityError("batch item source is invalid")
    run_index = source.get("sarif_run_index")
    result_index = source.get("sarif_result_index")
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in (run_index, result_index)
    ):
        raise IntegrityError("batch item source position is invalid")
    finding = item.get("finding")
    finding_id = finding.get("finding_id") if isinstance(finding, dict) else None
    digest = stable_id(
        "triage-result",
        {"sarif_sha256": sarif_sha256, "source": source, "finding_id": finding_id},
    ).rsplit(":", 1)[1][:12]
    return f"result-{run_index:03d}-{result_index:05d}-{digest}"


def _artifact_manifest(
    output_directory: Path, artifacts: list[tuple[str, str]]
) -> dict[str, object]:
    entries = []
    for path, role in sorted(artifacts):
        target = output_directory / PurePosixPath(path)
        entries.append(
            {
                "path": path,
                "role": role,
                "sha256": sha256_file(target),
                "size_bytes": target.stat().st_size,
            }
        )
    payload: dict[str, object] = {
        "schema_version": TRIAGE_PACKAGE_SCHEMA,
        "artifact_type": "manifest",
        "artifacts": entries,
    }
    payload["package_id"] = stable_id("triage-package", payload)
    return payload


def _localize(
    finding: dict[str, object],
    workspace: RepositoryWorkspace,
    index: dict[str, object],
    *,
    top_k: int,
) -> tuple[dict[str, object], dict[str, object]]:
    """Run the unchanged V0.6.1 localization projection against a shared snapshot."""

    if workspace.root is None or workspace.identity is None:
        raise RuntimeError("repository workspace did not materialise")
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=stable_id("sha256", workspace.identity["manifest_id"]),
        source_kind="directory",
        top_k=max(1_000, top_k),
        maximum_candidates=STEP1_MAXIMUM_CANDIDATES,
        measure_peak_memory=False,
    )
    raw_localization = build_raw_localization(request, repository_source=workspace.root)
    candidate_set = project_localization_candidates(finding, index, raw_localization, top_k=top_k)
    return raw_localization, candidate_set


def _severity(value: object) -> str:
    normalized = str(value).upper()
    return normalized if normalized in _SEVERITY_ORDER else "UNKNOWN"


def _build_review_queue(completed: list[dict[str, object]]) -> list[dict[str, object]]:
    """Aggregate existing candidate paths without comparing query-specific scores."""

    by_path: dict[str, list[dict[str, object]]] = {}
    for item in completed:
        key = item["result_key"]
        finding = item["finding"]
        candidates = item["candidate_set"]
        if (
            not isinstance(key, str)
            or not isinstance(finding, dict)
            or not isinstance(candidates, dict)
        ):
            raise IntegrityError("completed batch item is malformed")
        severity_value = finding.get("severity")
        severity = _severity(
            severity_value.get("normalized") if isinstance(severity_value, dict) else None
        )
        candidate_set_id = candidates.get("candidate_set_id")
        candidate_values = candidates.get("candidates")
        if not isinstance(candidate_set_id, str) or not isinstance(candidate_values, list):
            raise IntegrityError("completed batch candidates are malformed")
        for candidate in candidate_values:
            if not isinstance(candidate, dict):
                raise IntegrityError("completed batch candidate is malformed")
            path = candidate.get("path")
            rank = candidate.get("rank")
            candidate_id = candidate.get("candidate_id")
            role = candidate.get("role")
            if (
                not isinstance(path, str)
                or not isinstance(rank, int)
                or not isinstance(candidate_id, str)
                or not isinstance(role, str)
            ):
                raise IntegrityError("completed batch candidate reference is invalid")
            by_path.setdefault(path, []).append(
                {
                    "finding_key": key,
                    "candidate_set_id": candidate_set_id,
                    "candidate_id": candidate_id,
                    "rank": rank,
                    "role": role,
                    "severity": severity,
                    "anchor": {
                        "start_line": candidate["region"]["start_line"],
                        "start_column": candidate["region"]["start_column"],
                        "end_line": candidate["region"]["end_line"],
                        "end_column": candidate["region"]["end_column"],
                    },
                }
            )
    if sum(len(value) for value in by_path.values()) > MAX_TRIAGE_CONTRIBUTIONS:
        raise InputError(
            f"batch candidates exceed contribution limit of {MAX_TRIAGE_CONTRIBUTIONS}"
        )

    queue: list[dict[str, object]] = []
    for path, contributions in by_path.items():
        ordered = sorted(
            contributions,
            key=lambda item: (
                int(item["rank"]),
                str(item["finding_key"]),
                str(item["candidate_id"]),
            ),
        )
        primary = ordered[0]
        severity = min(
            (str(item["severity"]) for item in contributions), key=_SEVERITY_ORDER.__getitem__
        )
        queue.append(
            {
                "path": path,
                "role": primary["role"],
                "highest_severity": severity.lower(),
                "finding_count": len({str(item["finding_key"]) for item in contributions}),
                "best_shortlist_rank": primary["rank"],
                "primary_anchor": {
                    "finding_key": primary["finding_key"],
                    "candidate_id": primary["candidate_id"],
                    "region": primary["anchor"],
                },
                "contributions": ordered,
                "queue_order_is_not_probability": True,
            }
        )
    queue.sort(
        key=lambda item: (
            _SEVERITY_ORDER[str(item["highest_severity"]).upper()],
            -int(item["finding_count"]),
            int(item["best_shortlist_rank"]),
            str(item["path"]),
        )
    )
    for rank, item in enumerate(queue, start=1):
        item["queue_rank"] = rank
    return queue


def _combined_sarif(
    completed: list[dict[str, object]], repository: dict[str, object]
) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for item in completed:
        bundle = item["bundle"]
        finding = item["finding"]
        if not isinstance(bundle, dict) or not isinstance(finding, dict):
            raise IntegrityError("completed batch evidence is malformed")
        projected = export_sarif(bundle)
        run = projected["runs"][0]
        result = run["results"][0]
        properties = result.setdefault("properties", {})
        if not isinstance(properties, dict):
            raise IntegrityError("projected SARIF result properties are invalid")
        properties["lumiTraceBatchResultKey"] = item["result_key"]
        results.append(result)
        rule = finding["rule"]
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise IntegrityError("completed batch finding rule is invalid")
        rules.setdefault(
            rule["id"],
            {
                "id": rule["id"],
                "name": rule["name"],
                "shortDescription": {"text": finding["message"]["title"]},
                "properties": {"tags": rule.get("tags", []) + rule.get("cwes", [])},
            },
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lumi Trace",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/noqt/Lumi-Trace",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
                "results": results,
                "properties": {
                    "repositoryManifestId": repository["manifest_id"],
                    "externalNetworkCalls": 0,
                    "queueOrderIsNotProbability": True,
                },
            }
        ],
    }


def triage_sarif(
    *,
    sarif_path: Path,
    repository_source: Path,
    output_directory: Path,
    top_k: int = 10,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    implementation_revision: str | None = None,
) -> dict[str, object]:
    """Create one verified multi-result evidence package from a local SARIF report."""

    if output_directory.exists():
        raise InputError("output directory already exists; choose a new evidence-package path")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 1_000:
        raise InputError("top_k must be between 1 and 1000")
    if (
        not isinstance(max_findings, int)
        or isinstance(max_findings, bool)
        or not 1 <= max_findings <= HARD_MAX_FINDINGS
    ):
        raise InputError("max_findings must be between 1 and 1000")
    if max_findings * top_k > MAX_TRIAGE_CONTRIBUTIONS:
        raise InputError(
            f"--max-findings times --top-k exceeds contribution limit of {MAX_TRIAGE_CONTRIBUTIONS}"
        )
    original_repository_root = repository_source if repository_source.is_dir() else None
    imported = import_sarif_batch(
        sarif_path, repository_root=original_repository_root, max_findings=max_findings
    )
    sarif_sha256 = sha256_file(sarif_path)
    for item in imported:
        item["result_key"] = _result_key(item, sarif_sha256)
    if len({str(item["result_key"]) for item in imported}) != len(imported):
        raise IntegrityError("batch result-key collision")

    completed: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    with RepositoryWorkspace(repository_source) as workspace:
        if workspace.root is None or workspace.identity is None:
            raise RuntimeError("repository workspace did not materialise")
        index = build_repository_index(workspace.root, workspace.identity)
        for item in imported:
            finding = item.get("finding")
            if not isinstance(finding, dict):
                errors.append(
                    {
                        "result_key": item["result_key"],
                        "source": item["source"],
                        "error_code": item["error_code"],
                        "detail": (
                            "The SARIF result could not be normalized under the local contract."
                        ),
                    }
                )
                continue
            try:
                _, candidate_set = _localize(finding, workspace, index, top_k=top_k)
                bundle = build_evidence_bundle(
                    finding=finding,
                    repository=workspace.identity,
                    index=index,
                    candidate_set=candidate_set,
                    reproduction_requested=False,
                    receipt=None,
                    source_revision=implementation_revision or source_revision(),
                )
            except (InputError, ValueError):
                errors.append(
                    {
                        "result_key": item["result_key"],
                        "source": item["source"],
                        "error_code": "LOCALIZATION_FAILED",
                        "detail": (
                            "The SARIF result could not be localized under the bounded "
                            "product contract."
                        ),
                    }
                )
                continue
            completed.append(
                {
                    "result_key": item["result_key"],
                    "source": item["source"],
                    "finding": finding,
                    "candidate_set": candidate_set,
                    "bundle": bundle,
                }
            )

    queue = _build_review_queue(completed)
    normalized_findings = {
        "schema_version": TRIAGE_PACKAGE_SCHEMA,
        "artifact_type": "normalized-findings",
        "sarif_input_sha256": sarif_sha256,
        "findings": [
            {"result_key": item["result_key"], "source": item["source"], "finding": item["finding"]}
            for item in completed
        ],
    }
    review_queue = {
        "schema_version": TRIAGE_PACKAGE_SCHEMA,
        "artifact_type": "review-queue",
        "queue_order_is_not_probability": True,
        "entries": queue,
    }
    triage_summary = {
        "schema_version": TRIAGE_PACKAGE_SCHEMA,
        "artifact_type": "summary",
        "selected_results": len(imported),
        "completed_localizations": len(completed),
        "localization_abstentions": sum(
            1
            for item in completed
            if isinstance(item["candidate_set"].get("abstention"), dict)
            and item["candidate_set"]["abstention"].get("abstained") is True
        ),
        "result_local_errors": len(errors),
        "unique_review_paths": len(queue),
        "exit_code": TRIAGE_PARTIAL_SUCCESS_EXIT_CODE if errors else 0,
        "exit_status": "partial-success" if errors else "complete",
        "queue_order_is_not_probability": True,
    }
    sarif = _combined_sarif(completed, index["repository"])
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=output_directory.parent, prefix=".lumi-trace-triage-"
    ) as temporary_root:
        staging = Path(temporary_root) / "package"
        staging.mkdir()
        artifacts: list[tuple[str, str]] = [
            ("normalized-findings.json", "normalized-findings"),
            ("repository-index.json", "repository-index"),
            ("review-queue.json", "review-queue"),
            ("triage-summary.json", "summary"),
            ("triage.sarif", "sarif"),
        ]
        dump_json(staging / "normalized-findings.json", normalized_findings)
        dump_json(staging / "repository-index.json", index)
        dump_json(staging / "review-queue.json", review_queue)
        dump_json(staging / "triage-summary.json", triage_summary)
        dump_json(staging / "triage.sarif", sarif)
        for item in completed:
            key = str(item["result_key"])
            candidates_path = f"findings/{key}/candidates.json"
            bundle_path = f"findings/{key}/evidence-bundle.json"
            dump_json(staging / PurePosixPath(candidates_path), item["candidate_set"])
            dump_json(staging / PurePosixPath(bundle_path), item["bundle"])
            artifacts.extend(((candidates_path, "candidates"), (bundle_path, "evidence-bundle")))
        for error in errors:
            key = str(error["result_key"])
            error_path = f"errors/{key}.json"
            document = {
                "schema_version": TRIAGE_PACKAGE_SCHEMA,
                "artifact_type": "result-error",
                **error,
            }
            dump_json(staging / PurePosixPath(error_path), document)
            artifacts.append((error_path, "result-error"))
        manifest = _artifact_manifest(staging, artifacts)
        dump_json(staging / "manifest.json", manifest)
        verify_triage_package(staging)
        staging.replace(output_directory)
    return {
        "summary": triage_summary,
        "review_queue": queue,
        "manifest": manifest,
        "output_directory": output_directory,
        "exit_code": triage_summary["exit_code"],
    }


def _require_exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IntegrityError(f"{label} structure is invalid")
    return value


def _verify_source_position(value: object) -> dict[str, object]:
    source = _require_exact_keys(value, {"sarif_run_index", "sarif_result_index"}, "batch source")
    if any(
        not isinstance(source[key], int) or isinstance(source[key], bool) or source[key] < 0
        for key in source
    ):
        raise IntegrityError("batch source position is invalid")
    return source


def verify_triage_package(path: Path) -> None:
    """Verify full batch membership, shared identities, references, and projections."""

    manifest_path = path / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise InputError("batch triage manifest is missing or unsafe")
    manifest = load_json(manifest_path)
    manifest = _require_exact_keys(
        manifest,
        {"schema_version", "artifact_type", "artifacts", "package_id"},
        "batch triage manifest",
    )
    if (
        manifest.get("schema_version") != TRIAGE_PACKAGE_SCHEMA
        or manifest.get("artifact_type") != "manifest"
    ):
        raise InputError("directory has no batch-triage-package-v1 manifest")
    expected_package_id = stable_id("triage-package", manifest, omit_keys=("package_id",))
    if manifest.get("package_id") != expected_package_id:
        raise IntegrityError("batch triage manifest identity mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 5:
        raise IntegrityError("batch triage manifest artifacts are invalid")
    expected_paths: set[str] = set()
    artifact_roles: dict[str, str] = {}
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "role", "sha256", "size_bytes"}
            or not isinstance(artifact.get("path"), str)
            or not isinstance(artifact.get("role"), str)
            or not isinstance(artifact.get("sha256"), str)
            or _SHA256.fullmatch(artifact["sha256"]) is None
            or not isinstance(artifact.get("size_bytes"), int)
            or isinstance(artifact.get("size_bytes"), bool)
            or artifact["size_bytes"] < 0
        ):
            raise IntegrityError("batch triage artifact entry is invalid")
        relative = PurePosixPath(artifact["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) != artifact["path"]:
            raise IntegrityError("batch triage artifact path is invalid")
        if artifact["path"] in expected_paths:
            raise IntegrityError("batch triage artifact path is duplicated")
        target = path / relative
        if target.is_symlink() or not target.is_file():
            raise IntegrityError("batch triage artifact is missing or unsafe")
        if (
            sha256_file(target) != artifact["sha256"]
            or target.stat().st_size != artifact["size_bytes"]
        ):
            raise IntegrityError("batch triage artifact hash or size mismatch")
        expected_paths.add(artifact["path"])
        artifact_roles[artifact["path"]] = artifact["role"]
    actual_paths = {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
        if item.is_file() or item.is_symlink()
    }
    if actual_paths != expected_paths | {"manifest.json"}:
        raise IntegrityError("batch triage package contains unmanifested or missing artifacts")
    expected_directories = {
        parent.as_posix()
        for artifact_path in expected_paths
        for parent in PurePosixPath(artifact_path).parents
        if parent.as_posix() != "."
    }
    actual_directories = {
        item.relative_to(path).as_posix() for item in path.rglob("*") if item.is_dir()
    }
    if actual_directories != expected_directories:
        raise IntegrityError("batch triage package contains an unexpected directory")
    required_roles = {"normalized-findings", "repository-index", "review-queue", "summary", "sarif"}
    if not required_roles.issubset(set(artifact_roles.values())):
        raise IntegrityError("batch triage package is missing required artifacts")
    root_roles = {
        "normalized-findings.json": "normalized-findings",
        "repository-index.json": "repository-index",
        "review-queue.json": "review-queue",
        "triage-summary.json": "summary",
        "triage.sarif": "sarif",
    }
    if any(artifact_roles.get(name) != role for name, role in root_roles.items()):
        raise IntegrityError("batch triage root artifact role is invalid")

    normalized = load_json(path / "normalized-findings.json")
    index = load_json(path / "repository-index.json")
    queue_document = load_json(path / "review-queue.json")
    summary = load_json(path / "triage-summary.json")
    sarif = load_json(path / "triage.sarif")
    normalized = _require_exact_keys(
        normalized,
        {"schema_version", "artifact_type", "sarif_input_sha256", "findings"},
        "batch findings",
    )
    queue_document = _require_exact_keys(
        queue_document,
        {"schema_version", "artifact_type", "queue_order_is_not_probability", "entries"},
        "batch queue",
    )
    summary = _require_exact_keys(
        summary,
        {
            "schema_version",
            "artifact_type",
            "selected_results",
            "completed_localizations",
            "localization_abstentions",
            "result_local_errors",
            "unique_review_paths",
            "exit_code",
            "exit_status",
            "queue_order_is_not_probability",
        },
        "batch summary",
    )
    if (
        normalized.get("schema_version") != TRIAGE_PACKAGE_SCHEMA
        or normalized.get("artifact_type") != "normalized-findings"
        or not isinstance(normalized.get("sarif_input_sha256"), str)
        or _SHA256.fullmatch(normalized["sarif_input_sha256"]) is None
        or queue_document.get("schema_version") != TRIAGE_PACKAGE_SCHEMA
        or queue_document.get("artifact_type") != "review-queue"
        or queue_document.get("queue_order_is_not_probability") is not True
        or summary.get("schema_version") != TRIAGE_PACKAGE_SCHEMA
        or summary.get("artifact_type") != "summary"
        or summary.get("queue_order_is_not_probability") is not True
    ):
        raise IntegrityError("batch triage root artifact contract is invalid")
    verify_repository_index(index)
    findings = normalized.get("findings")
    entries = queue_document.get("entries")
    if not isinstance(findings, list) or not isinstance(entries, list):
        raise IntegrityError("batch triage collection is invalid")
    completed: list[dict[str, object]] = []
    candidate_lookup: dict[tuple[str, str], dict[str, object]] = {}
    for record in findings:
        record = _require_exact_keys(
            record, {"result_key", "source", "finding"}, "batch finding record"
        )
        key = record.get("result_key")
        finding = record.get("finding")
        if (
            not isinstance(key, str)
            or _RESULT_KEY.fullmatch(key) is None
            or not isinstance(finding, dict)
        ):
            raise IntegrityError("batch finding identity is invalid")
        source = _verify_source_position(record["source"])
        validate_normalized_finding(finding)
        if key != _result_key(
            {"source": source, "finding": finding}, normalized["sarif_input_sha256"]
        ):
            raise IntegrityError("batch finding result key is inconsistent")
        candidates_path = path / "findings" / key / "candidates.json"
        bundle_path = path / "findings" / key / "evidence-bundle.json"
        if (
            candidates_path.relative_to(path).as_posix() not in artifact_roles
            or bundle_path.relative_to(path).as_posix() not in artifact_roles
        ):
            raise IntegrityError("batch finding artifact membership is invalid")
        candidates = load_json(candidates_path)
        bundle = load_json(bundle_path)
        if not isinstance(candidates, dict) or not isinstance(bundle, dict):
            raise IntegrityError("batch finding artifact type is invalid")
        verify_candidate_set(candidates)
        verify_evidence_bundle(bundle)
        if bundle.get("finding") != finding or candidates.get("finding_id") != finding.get(
            "finding_id"
        ):
            raise IntegrityError("batch finding cross-artifact identity mismatch")
        if candidates.get("index_id") != index.get("index_id") or bundle.get("index", {}).get(
            "index_id"
        ) != index.get("index_id"):
            raise IntegrityError("batch finding shared index mismatch")
        completed_item = {
            "result_key": key,
            "source": source,
            "finding": finding,
            "candidate_set": candidates,
            "bundle": bundle,
        }
        completed.append(completed_item)
        for candidate in candidates.get("candidates", []):
            if isinstance(candidate, dict) and isinstance(candidate.get("candidate_id"), str):
                candidate_lookup[(key, candidate["candidate_id"])] = candidate
    error_paths = sorted(key for key, role in artifact_roles.items() if role == "result-error")
    error_keys: set[str] = set()
    for error_path in error_paths:
        error = load_json(path / PurePosixPath(error_path))
        error = _require_exact_keys(
            error,
            {"schema_version", "artifact_type", "result_key", "source", "error_code", "detail"},
            "batch error",
        )
        if (
            error.get("schema_version") != TRIAGE_PACKAGE_SCHEMA
            or error.get("artifact_type") != "result-error"
            or not isinstance(error.get("result_key"), str)
            or _RESULT_KEY.fullmatch(error["result_key"]) is None
            or error.get("error_code") not in {"NORMALIZATION_FAILED", "LOCALIZATION_FAILED"}
            or not isinstance(error.get("detail"), str)
            or len(error["detail"]) > 256
        ):
            raise IntegrityError("batch result error is invalid")
        source = _verify_source_position(error["source"])
        if error["result_key"] != _result_key(
            {"source": source, "finding": None}, normalized["sarif_input_sha256"]
        ):
            raise IntegrityError("batch error result key is inconsistent")
        if error_path != f"errors/{error['result_key']}.json":
            raise IntegrityError("batch error artifact path is inconsistent")
        error_keys.add(error["result_key"])
    completed_keys = {str(item["result_key"]) for item in completed}
    if len(completed_keys) != len(completed):
        raise IntegrityError("batch finding result key is duplicated")
    expected_artifact_paths = set(root_roles)
    expected_artifact_paths.update(
        path_part
        for key in completed_keys
        for path_part in (f"findings/{key}/candidates.json", f"findings/{key}/evidence-bundle.json")
    )
    expected_artifact_paths.update(f"errors/{key}.json" for key in error_keys)
    if set(artifact_roles) != expected_artifact_paths:
        raise IntegrityError("batch triage artifact membership is inconsistent")
    if completed_keys & error_keys or len(completed_keys) + len(error_keys) != int(
        summary["selected_results"]
    ):
        raise IntegrityError("batch result accounting is inconsistent")
    expected_queue = _build_review_queue(completed)
    if entries != expected_queue:
        raise IntegrityError("batch review queue does not match completed candidate sets")
    if len(candidate_lookup) < sum(
        len(item["contributions"]) for item in entries if isinstance(item, dict)
    ):
        raise IntegrityError("batch queue has unknown candidate contributions")
    expected_sarif = _combined_sarif(completed, index["repository"])
    if sarif != expected_sarif:
        raise IntegrityError("batch SARIF does not match completed evidence bundles")
    abstentions = sum(
        1
        for item in completed
        if item["candidate_set"].get("abstention", {}).get("abstained") is True
    )
    expected_summary = {
        "selected_results": len(completed) + len(error_keys),
        "completed_localizations": len(completed),
        "localization_abstentions": abstentions,
        "result_local_errors": len(error_keys),
        "unique_review_paths": len(expected_queue),
        "exit_code": TRIAGE_PARTIAL_SUCCESS_EXIT_CODE if error_keys else 0,
        "exit_status": "partial-success" if error_keys else "complete",
    }
    if any(summary.get(key) != value for key, value in expected_summary.items()):
        raise IntegrityError("batch summary is inconsistent")
