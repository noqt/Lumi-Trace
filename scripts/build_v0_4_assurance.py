# SPDX-License-Identifier: Apache-2.0
"""Build governed V0.4 corpus-assurance evidence in resumable phases.

All source identities, case identities, labels, and repository material remain
under the explicitly supplied F:/G: roots. This script emits no public evidence
and never executes repository-controlled code.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
for source_path in (EVAL_SRC, ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.assurance import (  # noqa: E402
    PARTITIONS,
    audit_answer_leakage,
    audit_partition_independence,
    build_sample_plan,
    build_training_manifest,
    disclosure_safe_projection,
    evaluate_training_readiness,
    scan_quarantine_entries,
    scan_text,
    seal_partitions,
    v04_metric_specification,
    validate_group_audit_card,
    validate_label_resolution,
    validate_rights_matrix,
    validate_source_candidate,
    validate_state_transition,
)
from trace_eval.canonical import (  # noqa: E402
    canonical_bytes,
    dump_json,
    load_json,
    sha256_bytes,
    sha256_file,
    stable_id,
)
from trace_eval.contracts import make_record  # noqa: E402
from trace_eval.corpus import (  # noqa: E402
    PythonChange,
    blind_label_pass_one,
    blind_label_pass_two,
    blind_passes_agree,
    is_python_harness,
    is_python_production,
    public_targets,
)
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.intake import (  # noqa: E402
    AcquisitionLimits,
    TreeEntry,
    detect_code_licence,
    scan_tree_entries,
)

from scripts.verify_v0_3_2_evidence import verify as verify_v0_3_2_evidence  # noqa: E402

VERSION = "v0.4"
EXPECTED_SOURCE_REVISION = "886dee5aa88765bbce2e73195358caeb728d03f5"
EXPECTED_V032_SEAL = (
    "lumi-trace-v0.3.2-public-evidence:"
    "c2d944aa8ac9880584555c64c95063f39ef8fdc56ec7d91fffda445b41091c77"
)
OSV_PYPI_URL = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
OSV_DATA_LICENCE = "CC-BY-4.0"
OSV_LICENCE_EVIDENCE_URL = "https://google.github.io/osv.dev/data/"
RECONSIDERED_PATH_QUARANTINE_POLICY = "v0.4-path-quarantine-except-labelled-target-v2"
RECONSIDERABLE_REJECTION_REASONS = frozenset(
    {
        "PRODUCTION_SOURCE_SECRET_OR_CREDENTIAL_FINDING",
        "SNAPSHOT_SECRET_OR_CREDENTIAL_FINDING",
    }
)

_COMMIT_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repository>[A-Za-z0-9_.-]+)/(?:commit|commits)/"
    r"(?P<revision>[0-9a-fA-F]{7,40})(?:[/?#].*)?$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_LICENCE_NAMES = (
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "LICENSE.TXT",
    "LICENCE",
    "LICENCE.txt",
    "LICENCE.md",
    "LICENCE.rst",
    "COPYING",
    "COPYING.txt",
    "COPYING.md",
    "COPYING.rst",
    "LICENSE-MIT",
    "LICENSE-MIT.txt",
    "MIT-LICENSE",
    "MIT-LICENSE.txt",
    "LICENSE-APACHE",
    "LICENSE-APACHE.txt",
    "LICENSE-APACHE-2.0",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/MIT.txt",
    "LICENSES/BSD-3-Clause.txt",
)
_MODEL_INPUT_TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".md",
        ".rst",
        ".txt",
        ".toml",
        ".ini",
        ".cfg",
        ".json",
        ".yaml",
        ".yml",
    }
)

PRIVATE_DIRECTORIES = (
    "candidate-source-register",
    "quarantine/advisory-sources",
    "quarantine/repositories",
    "immutable-repository-objects",
    "rights/licence-evidence",
    "rights/matrices",
    "security-evidence/advisories",
    "security-evidence/fixing",
    "labels/pass-1",
    "labels/pass-2",
    "labels/resolution",
    "labels/corrections",
    "fingerprints/lineage",
    "fingerprints/duplicates",
    "training-eligible/source",
    "training-derived/features",
    "partitions/engineering-development",
    "partitions/model-selection",
    "partitions/qualification",
    "partitions/protected-holdback",
    "models/cache",
    "models/artifacts",
    "runs/private",
    "ledgers",
    "manifests",
    "rejected",
    "retired",
    "disclosure-safe",
)

WORK_DIRECTORIES = (
    "logs",
    "workspaces/acquisition",
    "workspaces/label-pass-1",
    "workspaces/label-pass-2",
    "workspaces/adjudication",
    "workspaces/deduplication",
    "workspaces/preprocessing",
    "runs/development",
    "runs/model-selection",
    "runs/qualification",
)


def _require_root(path: Path, drive: str, *, create: bool = False) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _write_once(path: Path, value: Any) -> None:
    if path.exists():
        existing = load_json(path)
        if canonical_bytes(existing) != canonical_bytes(value):
            raise PolicyError(f"refusing to overwrite governed artifact: {path.name}")
        return
    dump_json(path, value)


def _private_manifest(
    schema_version: str,
    namespace: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    value = {"schema_version": schema_version, **payload}
    value["record_id"] = stable_id(namespace, value)
    return value


def _starting_verification() -> dict[str, Any]:
    manifest = verify_v0_3_2_evidence(ROOT / "evidence" / "v0.3.2")
    seal = manifest["seal_id"]
    if seal != EXPECTED_V032_SEAL:
        raise PolicyError("V0_3_2_EVIDENCE_SEAL_MISMATCH")
    return {
        "schema_version": "lumi-trace-v0.4-starting-state-v1",
        "starting_implementation": EXPECTED_SOURCE_REVISION,
        "starting_evidence": seal,
        "starting_closure": "CAPABILITY_RECOVERED / CORPUS_SCALE_REQUIRED",
        "historical_evidence_unchanged": True,
        "spent_v0_3_2_qualification_development_use": False,
        "protected_holdback_opened": False,
        "training_started": False,
        "weights_downloaded": False,
    }


def bootstrap(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:", create=True)
    work_root = _require_root(args.work_root, "F:", create=True)
    for relative in PRIVATE_DIRECTORIES:
        (private_root / relative).mkdir(parents=True, exist_ok=True)
    for relative in WORK_DIRECTORIES:
        (work_root / relative).mkdir(parents=True, exist_ok=True)

    starting = _starting_verification()
    starting["private_root_policy"] = "G:/GOVERNED_PRIVATE"
    starting["work_root_policy"] = "F:/GOVERNED_WORK"
    starting["starting_state_id"] = stable_id("v0.4-starting-state", starting)
    sample_plan = build_sample_plan()
    metric_specification = v04_metric_specification()
    status = {
        "schema_version": "lumi-trace-v0.4-current-status-v1",
        "version": VERSION,
        "state": "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION",
        "completed": [
            "V0.3.2 source and public seal verification",
            "F:/G: storage-boundary verification",
            "V0.4 assurance contract implementation",
            "pre-intake sample-plan lock",
            "V0.4 metric-gate lock",
        ],
        "current_blockers": [
            "500 training-eligible groups not yet admitted",
            "25 training-eligible families not yet admitted",
            "independent evaluation partitions not yet sealed",
        ],
        "next": "Ingest and audit public advisory candidates without repository execution.",
        "boundaries": {
            "training": "NOT_AUTHORISED_UNTIL_SECTION_17_GATES_PASS",
            "qualification": "UNOPENED",
            "protected_holdback": "SEALED_UNOPENED",
            "weights": "NONE",
            "publication": "NO_PUBLIC_ACTION",
        },
        "starting_state_id": starting["starting_state_id"],
        "sample_plan_id": sample_plan["record_id"],
        "metric_specification_id": metric_specification["record_id"],
    }
    status["status_id"] = stable_id("v0.4-current-status", status)
    ledger = {
        "schema_version": "lumi-trace-v0.4-work-ledger-v1",
        "entries": [
            {
                "sequence": 1,
                "event": "BOOTSTRAP",
                "decision": "CONTINUE",
                "evidence_ids": [starting["starting_state_id"], sample_plan["record_id"]],
                "boundaries_changed": False,
            }
        ],
    }
    ledger["ledger_id"] = stable_id("v0.4-work-ledger", ledger)
    gates = {
        "schema_version": "lumi-trace-v0.4-entry-gates-v1",
        "gates": {
            "minimum_500_groups": False,
            "minimum_25_families": False,
            "item_audits": False,
            "training_rights": False,
            "lineage_and_duplicate_audit": False,
            "controlled_labels": False,
            "poison_secret_privacy_provenance": False,
            "target_indexability": False,
            "candidate_presence": False,
            "ordering_gap": False,
            "baselines_locked": False,
            "objective_and_metrics_locked": True,
            "partitions_sealed_disjoint": False,
            "model_supply_chain": False,
            "training_code_and_resources": False,
            "qualification_holdback_blind": True,
        },
        "recommendation": "DO_NOT_BEGIN_TRACE_001",
        "training_started": False,
        "weights_downloaded": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }
    gates["gate_record_id"] = stable_id("v0.4-entry-gates", gates)
    _write_once(private_root / "manifests" / "starting-state-verification.json", starting)
    _write_once(private_root / "manifests" / "corpus-sample-plan.json", sample_plan)
    _write_once(
        private_root / "manifests" / "v0.4-metric-specification.json",
        metric_specification,
    )
    _write_once(private_root / "manifests" / "training-entry-gates.json", gates)
    _write_once(private_root / "ledgers" / "work-ledger.json", ledger)
    _write_once(private_root / "current-status.json", status)
    return status


def _zip_entry_metadata(archive: ZipFile) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    names: set[str] = set()
    for info in archive.infolist():
        name = PurePosixPath(info.filename).as_posix()
        if name in names:
            raise PolicyError("ADVISORY_ARCHIVE_DUPLICATE_PATH")
        names.add(name)
        entries.append(
            {
                "path": name,
                "kind": "DIRECTORY" if info.is_dir() else "REGULAR",
                "size_bytes": info.file_size,
                "compressed_bytes": max(1, info.compress_size),
            }
        )
    return entries


def _advisory_lineage(value: dict[str, Any]) -> str:
    aliases = sorted(
        {
            item.casefold()
            for item in [value.get("id"), *value.get("aliases", []), *value.get("upstream", [])]
            if isinstance(item, str) and item
        }
    )
    return stable_id("vulnerability-lineage", {"aliases": aliases})


def _pypi_packages(value: dict[str, Any]) -> list[str]:
    return sorted(
        {
            package["name"].casefold()
            for affected in value.get("affected", [])
            if isinstance(affected, dict)
            and isinstance((package := affected.get("package")), dict)
            and package.get("ecosystem") == "PyPI"
            and isinstance(package.get("name"), str)
            and package["name"]
        }
    )


def _commit_references(value: dict[str, Any]) -> list[dict[str, str]]:
    result: set[tuple[str, str, str]] = set()
    for reference in value.get("references", []):
        if not isinstance(reference, dict) or not isinstance(reference.get("url"), str):
            continue
        match = _COMMIT_URL.fullmatch(reference["url"])
        if match is None:
            continue
        revision = match.group("revision").casefold()
        if len(revision) != 40:
            continue
        repository = match.group("repository").removesuffix(".git")
        slug = f"{match.group('owner')}/{repository}".casefold()
        result.add((slug, revision, reference["url"]))
    return [
        {"repository": slug, "fixing_revision": revision, "reference_url": url}
        for slug, revision, url in sorted(result)
    ]


def ingest_advisories(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    archive_path = args.archive.resolve()
    if archive_path.drive.casefold() != "g:" or not archive_path.is_file():
        raise ValueError("advisory archive must be a regular file on governed G:")
    digest = sha256_file(archive_path)
    if args.expected_sha256 and digest != args.expected_sha256:
        raise PolicyError("ADVISORY_ARCHIVE_HASH_MISMATCH")

    try:
        archive = ZipFile(archive_path)
    except BadZipFile as exc:
        raise PolicyError("ADVISORY_ARCHIVE_REJECTED") from exc
    with archive:
        scan = scan_quarantine_entries(
            _zip_entry_metadata(archive),
            subject_id="advisory-source:osv-pypi",
        )
        if scan["payload"]["decision"] != "SCAN_PASSED":
            raise PolicyError("ADVISORY_ARCHIVE_QUARANTINED")
        candidates: list[dict[str, Any]] = []
        rejected: list[dict[str, str]] = []
        seen_cases: set[tuple[str, str, str]] = set()
        state_counts: Counter[str] = Counter()
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > 2 * 1024 * 1024:
                rejected.append(
                    {"item": stable_id("advisory-entry", info.filename), "reason": "OVERSIZED"}
                )
                continue
            body = archive.read(info)
            try:
                value = json.loads(body)
            except (UnicodeError, json.JSONDecodeError, RecursionError):
                rejected.append(
                    {"item": stable_id("advisory-entry", info.filename), "reason": "MALFORMED"}
                )
                continue
            if not isinstance(value, dict):
                rejected.append(
                    {"item": stable_id("advisory-entry", info.filename), "reason": "NOT_OBJECT"}
                )
                continue
            canonical_bytes(value)
            advisory_id = value.get("id")
            if not isinstance(advisory_id, str) or not advisory_id:
                rejected.append(
                    {"item": stable_id("advisory-entry", info.filename), "reason": "MISSING_ID"}
                )
                continue
            if value.get("withdrawn"):
                rejected.append({"item": stable_id("advisory", advisory_id), "reason": "WITHDRAWN"})
                continue
            packages = _pypi_packages(value)
            references = _commit_references(value)
            if not packages:
                rejected.append({"item": stable_id("advisory", advisory_id), "reason": "NOT_PYPI"})
                continue
            if not references:
                rejected.append(
                    {
                        "item": stable_id("advisory", advisory_id),
                        "reason": "NO_IMMUTABLE_GITHUB_FIX_REFERENCE",
                    }
                )
                continue
            text_findings: list[dict[str, str]] = []
            for field in ("summary", "details"):
                text = value.get(field)
                if isinstance(text, str):
                    text_findings.extend(scan_text(text))
            if any(item["severity"] == "CRITICAL" for item in text_findings):
                rejected.append(
                    {
                        "item": stable_id("advisory", advisory_id),
                        "reason": "CRITICAL_TEXT_SCAN_FINDING",
                    }
                )
                continue
            lineage_id = _advisory_lineage(value)
            advisory_hash = sha256_bytes(body)
            for reference in references:
                case_key = (
                    reference["repository"],
                    reference["fixing_revision"],
                    lineage_id,
                )
                if case_key in seen_cases:
                    state_counts["DUPLICATE_REFERENCE"] += 1
                    continue
                seen_cases.add(case_key)
                candidate = {
                    "candidate_id": stable_id(
                        "v0.4-candidate-group",
                        {
                            "repository": reference["repository"],
                            "fixing_revision": reference["fixing_revision"],
                            "vulnerability_lineage": lineage_id,
                        },
                    ),
                    "state": "PROPOSED",
                    "repository": reference["repository"],
                    "repository_family_provisional": stable_id(
                        "repository-family",
                        {"canonical_slug": reference["repository"]},
                    ),
                    "fixing_revision": reference["fixing_revision"],
                    "vulnerability_lineage_id": lineage_id,
                    "advisory_id": advisory_id,
                    "advisory_entry_sha256": advisory_hash,
                    "advisory_source": "OSV_PYPI_AGGREGATE",
                    "advisory_licence": OSV_DATA_LICENCE,
                    "packages": packages,
                    "reference_url": reference["reference_url"],
                    "published": value.get("published"),
                    "modified": value.get("modified"),
                    "text_scan_findings": sorted(
                        text_findings,
                        key=lambda item: (item["category"], item["severity"]),
                    ),
                    "label_state": "NOT_CONSTRUCTED",
                    "training_eligible": False,
                    "intended_partition": "UNASSIGNED",
                }
                candidates.append(candidate)
                state_counts["PROPOSED"] += 1

    by_repository: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        by_repository[candidate["repository"]].append(candidate)
    queue = {
        "schema_version": "lumi-trace-v0.4-resumable-acquisition-queue-v1",
        "source_archive_sha256": digest,
        "repositories": [
            {
                "repository": repository,
                "provisional_family_id": items[0]["repository_family_provisional"],
                "candidate_group_count": len(items),
                "distinct_fixing_revisions": len({item["fixing_revision"] for item in items}),
                "queue_state": "RIGHTS_AND_LICENCE_PROBE_PENDING",
                "attempts": 0,
                "last_error": None,
            }
            for repository, items in sorted(
                by_repository.items(),
                key=lambda pair: (-len(pair[1]), pair[0]),
            )
        ],
        "repository_count": len(by_repository),
        "candidate_group_count": len(candidates),
        "resumable": True,
    }
    queue["queue_id"] = stable_id("v0.4-acquisition-queue", queue)
    register = {
        "schema_version": "lumi-trace-v0.4-private-candidate-register-v1",
        "source_archive": {
            "url": OSV_PYPI_URL,
            "sha256": digest,
            "size_bytes": archive_path.stat().st_size,
            "licence": OSV_DATA_LICENCE,
            "licence_evidence_url": OSV_LICENCE_EVIDENCE_URL,
        },
        "quarantine_scan_id": scan["record_id"],
        "candidate_group_count": len(candidates),
        "repository_count": len(by_repository),
        "state_counts": dict(sorted(state_counts.items())),
        "candidates": sorted(
            candidates,
            key=lambda item: (
                item["repository"],
                item["fixing_revision"],
                item["vulnerability_lineage_id"],
            ),
        ),
    }
    register["register_id"] = stable_id("v0.4-private-candidate-register", register)
    rejection_ledger = {
        "schema_version": "lumi-trace-v0.4-advisory-rejection-ledger-v1",
        "source_archive_sha256": digest,
        "rejection_count": len(rejected),
        "reason_counts": dict(sorted(Counter(item["reason"] for item in rejected).items())),
        "rejections": sorted(rejected, key=lambda item: (item["reason"], item["item"])),
    }
    rejection_ledger["ledger_id"] = stable_id("v0.4-advisory-rejections", rejection_ledger)
    source_record = make_record(
        "source-candidate-v1",
        {
            "canonical_source_url": OSV_PYPI_URL,
            "owner": "OSV.dev aggregated PyPI sources",
            "source_type": "PUBLIC_DEFENSIVE_SECURITY_EVIDENCE_ARCHIVE",
            "repository_family": "NOT_APPLICABLE_ADVISORY_SOURCE",
            "immutable_revision": digest.removeprefix("sha256:"),
            "acquisition_method": "INERT_PINNED_FETCH",
            "collection_date": args.collection_date,
            "repository_licence": OSV_DATA_LICENCE,
            "licence_evidence": {
                "url": OSV_LICENCE_EVIDENCE_URL,
                "archive_sha256": digest,
            },
            "security_evidence": [OSV_PYPI_URL],
            "rights": {
                "retention": "PERMITTED",
                "evaluation": "PERMITTED",
                "transformation": "PERMITTED",
                "training": "PERMITTED",
                "redistribution": "PERMITTED",
            },
            "intended_partition": "SOURCE_CANDIDATE_DISCOVERY_ONLY",
            "related_lineages": [],
            "disclosure_state": "PUBLIC",
            "reviewer_role": "CONTROLLED_SOURCE_RIGHTS_REVIEW",
            "decision": "APPROVE_FOR_QUARANTINE",
            "decision_reason": (
                "OSV identifies the PyPI source feed as CC-BY-4.0; individual "
                "repository and group rights remain separately unreviewed."
            ),
        },
    )
    validate_source_candidate(source_record)

    register_root = private_root / "candidate-source-register"
    _write_once(register_root / "osv-pypi-source.json", source_record)
    _write_once(register_root / "candidate-register.json", register)
    _write_once(register_root / "acquisition-queue.json", queue)
    _write_once(private_root / "quarantine" / "advisory-sources" / "scan.json", scan)
    _write_once(private_root / "ledgers" / "advisory-rejections.json", rejection_ledger)
    summary = {
        "schema_version": "lumi-trace-v0.4-advisory-intake-summary-v1",
        "source_archive_sha256": digest,
        "source_record_id": source_record["record_id"],
        "quarantine_scan_id": scan["record_id"],
        "candidate_register_id": register["register_id"],
        "acquisition_queue_id": queue["queue_id"],
        "candidate_group_count": len(candidates),
        "candidate_repository_count": len(by_repository),
        "training_eligible_group_count": 0,
        "training_eligible_family_count": 0,
        "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
        "qualification_opened": False,
        "holdback_opened": False,
        "weights_downloaded": False,
    }
    summary["summary_id"] = stable_id("v0.4-advisory-intake-summary", summary)
    _write_once(private_root / "manifests" / "advisory-intake-summary.json", summary)
    return summary


def _git_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "Path",
        "PATHEXT",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "ComSpec",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
    }
    environment = {
        key: value for key, value in os.environ.items() if key in allowed and isinstance(value, str)
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return environment


def _ls_remote_head(repository: str) -> str:
    command = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "ls-remote",
        "--symref",
        f"https://github.com/{repository}.git",
        "HEAD",
    ]
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=45,
    )
    if process.returncode != 0:
        raise PolicyError("REPOSITORY_HEAD_RESOLUTION_FAILED")
    return _parse_ls_remote_head(process.stdout)


def _parse_ls_remote_head(output: bytes) -> str:
    lines = output.decode("utf-8", errors="strict").splitlines()
    revisions = [
        line.split("\t", 1)[0]
        for line in lines
        if "\t" in line
        and line.endswith("\tHEAD")
        and _REVISION.fullmatch(line.split("\t", 1)[0]) is not None
    ]
    if len(revisions) != 1 or _REVISION.fullmatch(revisions[0]) is None:
        raise PolicyError("REPOSITORY_HEAD_IDENTITY_INVALID")
    return revisions[0]


def _fetch_exact_licence(repository: str, revision: str) -> tuple[str, bytes, str]:
    errors: list[str] = []
    for name in _LICENCE_NAMES:
        url = f"https://raw.githubusercontent.com/{repository}/{revision}/{name}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/plain",
                "User-Agent": "Lumi-Trace-Controlled-Rights-Probe",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    errors.append(f"{name}:HTTP_{response.status}")
                    continue
                body = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            errors.append(f"{name}:HTTP_{exc.code}")
            continue
        except urllib.error.URLError:
            errors.append(f"{name}:TRANSPORT")
            continue
        if len(body) > 1024 * 1024:
            raise PolicyError("LICENCE_FILE_OVERSIZED")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{name}:ENCODING")
            continue
        findings = scan_text(text)
        if any(item["severity"] == "CRITICAL" for item in findings):
            raise PolicyError("LICENCE_FILE_QUARANTINED")
        try:
            identifier = detect_code_licence(text)
        except PolicyError:
            errors.append(f"{name}:UNAPPROVED_OR_AMBIGUOUS")
            continue
        return name, body, identifier
    reason = ",".join(errors)
    raise PolicyError(f"EXACT_REVISION_LICENCE_NOT_APPROVED:{reason}")


def _probe_token(repository: str) -> str:
    return stable_id("repository-probe-token", repository).split(":", 1)[1][:24]


def probe_repositories(args: argparse.Namespace) -> dict[str, Any]:
    """Pin exact heads and retain exact-revision licence evidence before fetch."""

    private_root = _require_root(args.private_root, "G:")
    queue = load_json(private_root / "candidate-source-register" / "acquisition-queue.json")
    register = load_json(private_root / "candidate-source-register" / "candidate-register.json")
    if (
        not isinstance(queue, dict)
        or queue.get("schema_version") != "lumi-trace-v0.4-resumable-acquisition-queue-v1"
        or not isinstance(register, dict)
    ):
        raise ContractError("V0.4 acquisition queue is malformed")
    candidates_by_repository: Counter[str] = Counter(
        item["repository"] for item in register["candidates"]
    )
    eligible_queue = [
        item
        for item in queue["repositories"]
        if item["candidate_group_count"] >= args.minimum_candidates
    ][: args.limit]
    receipt_root = private_root / "rights" / "licence-evidence"
    source_root = private_root / "candidate-source-register" / "repositories"
    receipt_root.mkdir(parents=True, exist_ok=True)
    source_root.mkdir(parents=True, exist_ok=True)
    if re.fullmatch(r"[a-z0-9-]{1,24}", args.probe_run) is None:
        raise ValueError("--probe-run must be a lowercase safe token")
    if not 1 <= args.workers <= 16:
        raise ValueError("--workers must be between 1 and 16")
    run_suffix = "" if args.probe_run == "run1" else f".{args.probe_run}"

    def probe_one(position_and_queue: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        position, queued = position_and_queue
        repository = queued["repository"]
        token = _probe_token(repository)
        receipt_path = receipt_root / f"{token}{run_suffix}.json"
        source_path = source_root / f"{token}{run_suffix}.json"
        if receipt_path.is_file() and source_path.is_file():
            receipt = load_json(receipt_path)
            source_record = load_json(source_path)
            return {
                "repository_token": token,
                "state": receipt["decision"],
                "source_record_id": source_record["record_id"],
                "candidate_group_count": candidates_by_repository[repository],
            }
        receipt: dict[str, Any] = {
            "schema_version": "lumi-trace-v0.4-exact-licence-probe-v1",
            "probe_run": args.probe_run,
            "repository_token": token,
            "queue_position": position,
            "candidate_group_count": candidates_by_repository[repository],
            "repository_code_executed": False,
            "git_hooks_enabled": False,
            "credentials_used": False,
        }
        try:
            revision = _ls_remote_head(repository)
            licence_name, licence_body, licence_identifier = _fetch_exact_licence(
                repository, revision
            )
            licence_hash = sha256_bytes(licence_body)
            licence_artifact = receipt_root / f"{token}{run_suffix}.licence.txt"
            if licence_artifact.exists():
                if sha256_file(licence_artifact) != licence_hash:
                    raise PolicyError("LICENCE_ARTIFACT_IDENTITY_MISMATCH")
            else:
                licence_artifact.write_bytes(licence_body)
            receipt.update(
                {
                    "resolved_revision": revision,
                    "licence_path_at_revision": licence_name,
                    "licence_identifier": licence_identifier,
                    "licence_sha256": licence_hash,
                    "decision": "RIGHTS_PRECHECK_PASSED",
                    "reason": (
                        "Exact-revision Apache-2.0, MIT, or BSD-3-Clause licence "
                        "permits local use and transformation; weight publication "
                        "rights remain separate."
                    ),
                }
            )
            source_record = make_record(
                "source-candidate-v1",
                {
                    "canonical_source_url": f"https://github.com/{repository}",
                    "owner": repository.split("/", 1)[0],
                    "source_type": "PUBLIC_GIT_REPOSITORY",
                    "repository_family": queued["provisional_family_id"],
                    "immutable_revision": revision,
                    "acquisition_method": "INERT_PINNED_FETCH",
                    "collection_date": args.collection_date,
                    "repository_licence": licence_identifier,
                    "licence_evidence": {
                        "path": licence_name,
                        "sha256": licence_hash,
                        "revision": revision,
                    },
                    "security_evidence": [
                        {
                            "source_record_id": (
                                "source-candidate:"
                                "824b0383207252eb5d2e1e08fc488996a770751f7889fc47b36cc7ec720eed2e"
                            ),
                            "candidate_group_count": candidates_by_repository[repository],
                        }
                    ],
                    "rights": {
                        "retention": "PERMITTED",
                        "evaluation": "PERMITTED",
                        "transformation": "PERMITTED",
                        "training": "PERMITTED",
                        "redistribution": "PERMITTED",
                    },
                    "intended_partition": "UNASSIGNED_PRE_SPLIT",
                    "related_lineages": [],
                    "disclosure_state": "PUBLIC_FIXED_DISCLOSED",
                    "reviewer_role": "CONTROLLED_EXACT_REVISION_RIGHTS_REVIEW",
                    "decision": "APPROVE_FOR_QUARANTINE",
                    "decision_reason": receipt["reason"],
                },
            )
        except (OSError, UnicodeError, subprocess.SubprocessError, PolicyError) as exc:
            receipt.update(
                {
                    "resolved_revision": None,
                    "licence_path_at_revision": None,
                    "licence_identifier": None,
                    "licence_sha256": None,
                    "decision": "QUARANTINED_RIGHTS_REVIEW",
                    "reason": str(exc),
                }
            )
            source_record = make_record(
                "source-candidate-v1",
                {
                    "canonical_source_url": f"https://github.com/{repository}",
                    "owner": repository.split("/", 1)[0],
                    "source_type": "PUBLIC_GIT_REPOSITORY",
                    "repository_family": queued["provisional_family_id"],
                    "immutable_revision": "0" * 40,
                    "acquisition_method": "INERT_PINNED_FETCH",
                    "collection_date": args.collection_date,
                    "repository_licence": "UNKNOWN",
                    "licence_evidence": {"probe_reason": receipt["reason"]},
                    "security_evidence": [
                        {
                            "source_record_id": (
                                "source-candidate:"
                                "824b0383207252eb5d2e1e08fc488996a770751f7889fc47b36cc7ec720eed2e"
                            ),
                            "candidate_group_count": candidates_by_repository[repository],
                        }
                    ],
                    "rights": {
                        "retention": "UNKNOWN",
                        "evaluation": "UNKNOWN",
                        "transformation": "UNKNOWN",
                        "training": "UNKNOWN",
                        "redistribution": "UNKNOWN",
                    },
                    "intended_partition": "QUARANTINE",
                    "related_lineages": [],
                    "disclosure_state": "PUBLIC_FIXED_DISCLOSED",
                    "reviewer_role": "CONTROLLED_EXACT_REVISION_RIGHTS_REVIEW",
                    "decision": "PENDING",
                    "decision_reason": receipt["reason"],
                },
            )
        validate_source_candidate(source_record)
        receipt["probe_id"] = stable_id("v0.4-exact-licence-probe", receipt)
        _write_once(receipt_path, receipt)
        _write_once(source_path, source_record)
        return {
            "repository_token": token,
            "state": receipt["decision"],
            "source_record_id": source_record["record_id"],
            "candidate_group_count": candidates_by_repository[repository],
        }

    positioned = list(enumerate(eligible_queue, start=1))
    with ThreadPoolExecutor(
        max_workers=args.workers,
        thread_name_prefix="v04-rights-probe",
    ) as executor:
        decisions = list(executor.map(probe_one, positioned))
    state_counts = Counter(item["state"] for item in decisions)
    approved_groups = sum(
        item["candidate_group_count"]
        for item in decisions
        if item["state"] == "RIGHTS_PRECHECK_PASSED"
    )
    summary = {
        "schema_version": "lumi-trace-v0.4-repository-rights-probe-summary-v1",
        "probe_run": args.probe_run,
        "supersedes_summary_id": args.supersedes_summary_id,
        "correction_reason": args.correction_reason,
        "queue_id": queue["queue_id"],
        "selected_repository_count": len(eligible_queue),
        "completed_repository_count": len(decisions),
        "state_counts": dict(sorted(state_counts.items())),
        "approved_candidate_group_count": approved_groups,
        "training_eligible_group_count": 0,
        "decisions": decisions,
        "repository_code_executed": False,
        "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
    }
    summary["summary_id"] = stable_id("v0.4-rights-probe-summary", summary)
    output = (
        private_root
        / "manifests"
        / (f"repository-rights-probe-{args.probe_run}-{args.limit}-{args.minimum_candidates}.json")
    )
    _write_once(output, summary)
    return summary


def _repository_from_source(source: dict[str, Any]) -> str:
    prefix = "https://github.com/"
    url = source["payload"]["canonical_source_url"]
    if not isinstance(url, str) or not url.startswith(prefix):
        raise ContractError("repository source URL is malformed")
    return url.removeprefix(prefix).casefold()


def _load_assignment_source(
    source_root: Path,
    *,
    repository_token: str,
    source_record_id: str,
) -> dict[str, Any]:
    matches: dict[str, dict[str, Any]] = {}
    for path in sorted(source_root.glob(f"{repository_token}*.json")):
        source = load_json(path)
        if source.get("record_id") == source_record_id:
            matches[source_record_id] = source
    if len(matches) != 1:
        raise PolicyError("PARTITION_SOURCE_RECORD_IDENTITY_MISMATCH")
    return matches[source_record_id]


def plan_partitions(args: argparse.Namespace) -> dict[str, Any]:
    """Assign organization-disjoint families before any case-level feature work."""

    private_root = _require_root(args.private_root, "G:")
    probe_summary = load_json(args.probe_summary)
    if (
        not isinstance(probe_summary, dict)
        or probe_summary.get("schema_version")
        != "lumi-trace-v0.4-repository-rights-probe-summary-v1"
    ):
        raise ContractError("repository rights probe summary is malformed")
    source_root = private_root / "candidate-source-register" / "repositories"
    approved: list[dict[str, Any]] = []
    for decision in probe_summary["decisions"]:
        if decision["state"] != "RIGHTS_PRECHECK_PASSED":
            continue
        token = decision["repository_token"]
        run_suffix = (
            "" if probe_summary["probe_run"] == "run1" else f".{probe_summary['probe_run']}"
        )
        source = load_json(source_root / f"{token}{run_suffix}.json")
        repository = _repository_from_source(source)
        approved.append(
            {
                "repository": repository,
                "repository_token": token,
                "source_record_id": source["record_id"],
                "repository_family_id": source["payload"]["repository_family"],
                "organization_lineage": repository.split("/", 1)[0],
                "candidate_group_count": decision["candidate_group_count"],
                "licence": source["payload"]["repository_licence"],
                "head_revision": source["payload"]["immutable_revision"],
            }
        )
    if len(approved) < 57:
        raise PolicyError("INSUFFICIENT_RIGHTS_APPROVED_REPOSITORIES_FOR_DISJOINT_PLAN")
    ordered = sorted(
        approved,
        key=lambda item: (
            -min(item["candidate_group_count"], args.family_candidate_cap),
            stable_id("partition-order", item["repository"]),
        ),
    )
    assignments: list[dict[str, Any]] = []
    assigned_organizations: set[str] = set()
    remaining = ordered[:]

    def allocate(partition: str, minimum_raw_groups: int) -> None:
        selected: list[dict[str, Any]] = []
        raw_groups = 0
        for item in remaining:
            if item["organization_lineage"] in assigned_organizations:
                continue
            selected.append(item)
            assigned_organizations.add(item["organization_lineage"])
            raw_groups += min(item["candidate_group_count"], args.family_candidate_cap)
            if (
                len(selected) >= args.minimum_partition_families
                and raw_groups >= minimum_raw_groups
            ):
                break
        if len(selected) < args.minimum_partition_families or raw_groups < minimum_raw_groups:
            raise PolicyError(f"INSUFFICIENT_RAW_SUPPLY_FOR_{partition}")
        selected_repositories = {item["repository"] for item in selected}
        assignments.extend({**item, "partition": partition} for item in selected)
        remaining[:] = [
            item
            for item in remaining
            if item["organization_lineage"] not in assigned_organizations
            and item["repository"] not in selected_repositories
        ]

    # The protected lanes are assigned first and their case content remains unopened.
    allocate("PROTECTED_HOLDBACK", args.evaluation_raw_groups)
    allocate("QUALIFICATION", args.evaluation_raw_groups)
    allocate("MODEL_SELECTION", args.evaluation_raw_groups)
    allocate("ENGINEERING_DEVELOPMENT", args.evaluation_raw_groups)

    training = [
        item for item in remaining if item["organization_lineage"] not in assigned_organizations
    ]
    training_organizations = {item["organization_lineage"] for item in training}
    training_raw_groups = sum(
        min(item["candidate_group_count"], args.family_candidate_cap) for item in training
    )
    if len(training_organizations) < 25 or training_raw_groups < args.training_raw_groups:
        failed = {
            "schema_version": "lumi-trace-v0.4-partition-plan-attempt-v1",
            "probe_summary_id": probe_summary["summary_id"],
            "decision": "REJECTED_INSUFFICIENT_DISJOINT_TRAINING_BUFFER",
            "approved_repository_count": len(approved),
            "evaluation_assignments": len(assignments),
            "training_repository_count": len(training),
            "training_organization_count": len(training_organizations),
            "training_raw_group_count": training_raw_groups,
            "required_training_organization_count": 25,
            "required_training_raw_group_count": args.training_raw_groups,
            "gate_lowered": False,
            "evaluation_family_reused": False,
        }
        failed["attempt_id"] = stable_id("v0.4-partition-plan-attempt", failed)
        attempt_name = f"{failed['attempt_id'].split(':', 1)[1][:24]}.json"
        _write_once(
            private_root / "manifests" / "partition-plan-attempts" / attempt_name,
            failed,
        )
        raise PolicyError("INSUFFICIENT_RAW_TRAINING_SUPPLY_AFTER_DISJOINT_SPLIT")
    assignments.extend({**item, "partition": "TRAINING"} for item in training)
    organization_partitions: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        organization_partitions[item["organization_lineage"]].add(item["partition"])
    if any(len(partitions) != 1 for partitions in organization_partitions.values()):
        raise PolicyError("ORGANIZATION_LINEAGE_CROSSES_PARTITIONS")
    plan = {
        "schema_version": "lumi-trace-v0.4-pre-feature-partition-plan-v1",
        "probe_summary_id": probe_summary["summary_id"],
        "assignment_method": (
            "RIGHTS_APPROVED_ONLY / ORGANIZATION_DISJOINT / "
            "CANDIDATE_COUNT_CAPPED / NO_CASE_METRICS"
        ),
        "family_candidate_cap": args.family_candidate_cap,
        "evaluation_raw_group_floor": args.evaluation_raw_groups,
        "training_raw_group_floor": args.training_raw_groups,
        "assignments": sorted(
            assignments,
            key=lambda item: (item["partition"], item["organization_lineage"], item["repository"]),
        ),
        "partition_repository_counts": dict(
            sorted(Counter(item["partition"] for item in assignments).items())
        ),
        "partition_raw_group_counts": dict(
            sorted(
                (
                    partition,
                    sum(
                        min(item["candidate_group_count"], args.family_candidate_cap)
                        for item in assignments
                        if item["partition"] == partition
                    ),
                )
                for partition in (
                    "TRAINING",
                    "ENGINEERING_DEVELOPMENT",
                    "MODEL_SELECTION",
                    "QUALIFICATION",
                    "PROTECTED_HOLDBACK",
                )
            )
        ),
        "organization_lineage_count": len(organization_partitions),
        "organization_cross_partition_overlap": 0,
        "sealed_before_feature_design": True,
        "sealed_before_training": True,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "training_started": False,
        "weights_downloaded": False,
    }
    plan["plan_id"] = stable_id("v0.4-pre-feature-partition-plan", plan)
    _write_once(private_root / "manifests" / "pre-feature-partition-plan.json", plan)
    return {
        "plan_id": plan["plan_id"],
        "partition_repository_counts": plan["partition_repository_counts"],
        "partition_raw_group_counts": plan["partition_raw_group_counts"],
        "organization_lineage_count": plan["organization_lineage_count"],
        "qualification_state": plan["qualification_state"],
        "protected_holdback_state": plan["protected_holdback_state"],
    }


def extend_partition_plan(args: argparse.Namespace) -> dict[str, Any]:
    """Add newly rights-approved families to training without reshuffling lanes."""

    private_root = _require_root(args.private_root, "G:")
    base_plan = load_json(args.partition_plan)
    probe_summary = load_json(args.probe_summary)
    if (
        base_plan.get("schema_version") != "lumi-trace-v0.4-pre-feature-partition-plan-v1"
        or probe_summary.get("schema_version")
        != "lumi-trace-v0.4-repository-rights-probe-summary-v1"
        or base_plan.get("sealed_before_feature_design") is not True
    ):
        raise ContractError("base plan or extension probe is malformed")
    assignments = list(base_plan["assignments"])
    assigned_repositories = {item["repository"] for item in assignments}
    organization_partition = {
        item["organization_lineage"]: item["partition"] for item in assignments
    }
    source_root = private_root / "candidate-source-register" / "repositories"
    run_suffix = "" if probe_summary["probe_run"] == "run1" else f".{probe_summary['probe_run']}"
    added: list[dict[str, Any]] = []
    for decision in probe_summary["decisions"]:
        if decision["state"] != "RIGHTS_PRECHECK_PASSED":
            continue
        token = decision["repository_token"]
        source = load_json(source_root / f"{token}{run_suffix}.json")
        repository = _repository_from_source(source)
        if repository in assigned_repositories:
            continue
        organization = repository.split("/", 1)[0]
        prior_partition = organization_partition.get(organization)
        if prior_partition is not None and prior_partition != "TRAINING":
            continue
        item = {
            "repository": repository,
            "repository_token": token,
            "source_record_id": source["record_id"],
            "repository_family_id": source["payload"]["repository_family"],
            "organization_lineage": organization,
            "candidate_group_count": decision["candidate_group_count"],
            "licence": source["payload"]["repository_licence"],
            "head_revision": source["payload"]["immutable_revision"],
            "partition": "TRAINING",
        }
        assignments.append(item)
        added.append(item)
        assigned_repositories.add(repository)
        organization_partition[organization] = "TRAINING"
    organization_partitions: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        organization_partitions[item["organization_lineage"]].add(item["partition"])
    if any(len(partitions) != 1 for partitions in organization_partitions.values()):
        raise PolicyError("EXTENDED_PLAN_ORGANIZATION_OVERLAP")
    extended = {
        **{
            key: value
            for key, value in base_plan.items()
            if key
            not in {
                "plan_id",
                "assignments",
                "partition_repository_counts",
                "partition_raw_group_counts",
            }
        },
        "supersedes_plan_id": base_plan["plan_id"],
        "extension_probe_summary_id": probe_summary["summary_id"],
        "extension_method": (
            "APPEND_NEW_RIGHTS_APPROVED_ORGANIZATIONS_TO_TRAINING_ONLY / "
            "NO_EXISTING_ASSIGNMENT_CHANGED / NO_CASE_METRICS"
        ),
        "assignments": sorted(
            assignments,
            key=lambda item: (
                item["partition"],
                item["organization_lineage"],
                item["repository"],
            ),
        ),
        "partition_repository_counts": dict(
            sorted(Counter(item["partition"] for item in assignments).items())
        ),
        "partition_raw_group_counts": dict(
            sorted(
                (
                    partition,
                    sum(
                        min(item["candidate_group_count"], args.family_candidate_cap)
                        for item in assignments
                        if item["partition"] == partition
                    ),
                )
                for partition in PARTITIONS
            )
        ),
        "organization_lineage_count": len(organization_partitions),
        "organization_cross_partition_overlap": 0,
        "added_training_repository_count": len(added),
        "existing_assignment_changes": 0,
        "sealed_before_feature_design": True,
        "sealed_before_training": True,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "training_started": False,
        "weights_downloaded": False,
    }
    extended["plan_id"] = stable_id("v0.4-pre-feature-partition-plan", extended)
    _write_once(
        private_root / "manifests" / f"pre-feature-partition-plan-{args.plan_run}.json",
        extended,
    )
    return {
        "plan_id": extended["plan_id"],
        "supersedes_plan_id": extended["supersedes_plan_id"],
        "added_training_repository_count": len(added),
        "partition_repository_counts": extended["partition_repository_counts"],
        "partition_raw_group_counts": extended["partition_raw_group_counts"],
        "existing_assignment_changes": 0,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
    }


def _augment_assignments(
    assignments: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    supply_targets: dict[str, int],
    family_candidate_cap: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Append source families without changing or crossing existing assignments."""

    if family_candidate_cap < 1:
        raise ValueError("--family-candidate-cap must be positive")
    existing = [dict(item) for item in assignments]
    assigned_repositories = {item["repository"] for item in existing}
    organization_partition: dict[str, str] = {}
    for item in existing:
        organization = item["organization_lineage"]
        partition = item["partition"]
        prior = organization_partition.setdefault(organization, partition)
        if prior != partition:
            raise PolicyError("BASE_PLAN_ORGANIZATION_OVERLAP")

    ordered = sorted(
        candidates,
        key=lambda item: (
            -min(item["candidate_group_count"], family_candidate_cap),
            stable_id("supply-augmentation-order", item["repository"]),
        ),
    )
    added: list[dict[str, Any]] = []
    for partition, target in supply_targets.items():
        if partition not in PARTITIONS:
            raise ValueError(f"unknown partition in --supply-target: {partition}")
        if target < 0:
            raise ValueError("--supply-target values must be non-negative")
        current = sum(
            min(item["candidate_group_count"], family_candidate_cap)
            for item in [*existing, *added]
            if item["partition"] == partition
        )
        if current >= target:
            continue
        for candidate in ordered:
            repository = candidate["repository"]
            if repository in assigned_repositories:
                continue
            organization = candidate["organization_lineage"]
            prior_partition = organization_partition.get(organization)
            if prior_partition is not None and prior_partition != partition:
                continue
            item = {**candidate, "partition": partition}
            added.append(item)
            assigned_repositories.add(repository)
            organization_partition[organization] = partition
            current += min(item["candidate_group_count"], family_candidate_cap)
            if current >= target:
                break
        if current < target:
            raise PolicyError(f"INSUFFICIENT_ADDITIVE_RAW_SUPPLY_FOR_{partition}")
    return [*existing, *added], added


def augment_partition_plan(args: argparse.Namespace) -> dict[str, Any]:
    """Append rights-approved families to measured under-supplied partitions."""

    private_root = _require_root(args.private_root, "G:")
    base_plan = load_json(args.partition_plan)
    probe_summary = load_json(args.probe_summary)
    if (
        base_plan.get("schema_version") != "lumi-trace-v0.4-pre-feature-partition-plan-v1"
        or probe_summary.get("schema_version")
        != "lumi-trace-v0.4-repository-rights-probe-summary-v1"
        or base_plan.get("sealed_before_feature_design") is not True
        or base_plan.get("sealed_before_training") is not True
    ):
        raise ContractError("base plan or augmentation probe is malformed")
    supply_targets: dict[str, int] = {}
    for value in args.supply_target:
        partition, separator, raw_target = value.partition("=")
        if not separator:
            raise ValueError("--supply-target must use PARTITION=RAW_GROUPS")
        if partition in supply_targets:
            raise ValueError(f"duplicate --supply-target partition: {partition}")
        try:
            supply_targets[partition] = int(raw_target)
        except ValueError as exc:
            raise ValueError("--supply-target value must be an integer") from exc
    if not supply_targets:
        raise ValueError("at least one --supply-target is required")

    source_root = private_root / "candidate-source-register" / "repositories"
    run_suffix = "" if probe_summary["probe_run"] == "run1" else f".{probe_summary['probe_run']}"
    candidates: list[dict[str, Any]] = []
    for decision in probe_summary["decisions"]:
        if decision["state"] != "RIGHTS_PRECHECK_PASSED":
            continue
        token = decision["repository_token"]
        source = load_json(source_root / f"{token}{run_suffix}.json")
        repository = _repository_from_source(source)
        candidates.append(
            {
                "repository": repository,
                "repository_token": token,
                "source_record_id": source["record_id"],
                "repository_family_id": source["payload"]["repository_family"],
                "organization_lineage": repository.split("/", 1)[0],
                "candidate_group_count": decision["candidate_group_count"],
                "licence": source["payload"]["repository_licence"],
                "head_revision": source["payload"]["immutable_revision"],
            }
        )
    assignments, added = _augment_assignments(
        list(base_plan["assignments"]),
        candidates,
        supply_targets=supply_targets,
        family_candidate_cap=args.family_candidate_cap,
    )
    organization_partitions: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        organization_partitions[item["organization_lineage"]].add(item["partition"])
    if any(len(partitions) != 1 for partitions in organization_partitions.values()):
        raise PolicyError("AUGMENTED_PLAN_ORGANIZATION_OVERLAP")
    partition_raw_group_counts = dict(
        sorted(
            (
                partition,
                sum(
                    min(item["candidate_group_count"], args.family_candidate_cap)
                    for item in assignments
                    if item["partition"] == partition
                ),
            )
            for partition in PARTITIONS
        )
    )
    existing_identities = {
        (item["repository"], item["partition"], item["source_record_id"])
        for item in base_plan["assignments"]
    }
    augmented_identities = {
        (item["repository"], item["partition"], item["source_record_id"]) for item in assignments
    }
    existing_assignment_changes = len(existing_identities - augmented_identities)
    if existing_assignment_changes:
        raise PolicyError("AUGMENTATION_CHANGED_EXISTING_ASSIGNMENTS")
    augmented = {
        **{
            key: value
            for key, value in base_plan.items()
            if key
            not in {
                "plan_id",
                "assignments",
                "partition_repository_counts",
                "partition_raw_group_counts",
            }
        },
        "supersedes_plan_id": base_plan["plan_id"],
        "augmentation_probe_summary_id": probe_summary["summary_id"],
        "augmentation_reason": args.augmentation_reason,
        "augmentation_method": (
            "MEASURED_AUDIT_YIELD / APPEND_RIGHTS_APPROVED_FAMILIES_ONLY / "
            "NO_EXISTING_ASSIGNMENT_CHANGED / NO_CASE_METRICS"
        ),
        "requested_raw_supply_targets": dict(sorted(supply_targets.items())),
        "assignments": sorted(
            assignments,
            key=lambda item: (
                item["partition"],
                item["organization_lineage"],
                item["repository"],
            ),
        ),
        "partition_repository_counts": dict(
            sorted(Counter(item["partition"] for item in assignments).items())
        ),
        "partition_raw_group_counts": partition_raw_group_counts,
        "organization_lineage_count": len(organization_partitions),
        "organization_cross_partition_overlap": 0,
        "added_repository_count": len(added),
        "added_repository_counts": dict(
            sorted(Counter(item["partition"] for item in added).items())
        ),
        "existing_assignment_changes": existing_assignment_changes,
        "sealed_before_feature_design": True,
        "sealed_before_training": True,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "training_started": False,
        "weights_downloaded": False,
    }
    augmented["plan_id"] = stable_id("v0.4-pre-feature-partition-plan", augmented)
    _write_once(
        private_root / "manifests" / f"pre-feature-partition-plan-{args.plan_run}.json",
        augmented,
    )
    return {
        "plan_id": augmented["plan_id"],
        "supersedes_plan_id": augmented["supersedes_plan_id"],
        "added_repository_count": len(added),
        "added_repository_counts": augmented["added_repository_counts"],
        "partition_repository_counts": augmented["partition_repository_counts"],
        "partition_raw_group_counts": partition_raw_group_counts,
        "existing_assignment_changes": existing_assignment_changes,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
    }


def _reassign_untouched_lineages(
    assignments: list[dict[str, Any]],
    *,
    moves: dict[str, str],
    touched_repository_tokens: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Move complete, never-acquired organization lineages between partitions."""

    by_token = {item["repository_token"]: item for item in assignments}
    if len(by_token) != len(assignments):
        raise PolicyError("DUPLICATE_REPOSITORY_TOKEN_IN_PLAN")
    lineage_destination: dict[str, str] = {}
    for token, destination in moves.items():
        if destination not in PARTITIONS:
            raise ValueError(f"unknown reassignment partition: {destination}")
        assignment = by_token.get(token)
        if assignment is None:
            raise ValueError(f"unknown reassignment repository token: {token}")
        lineage = assignment["organization_lineage"]
        prior = lineage_destination.setdefault(lineage, destination)
        if prior != destination:
            raise ValueError("one lineage cannot have multiple reassignment destinations")

    changed: list[dict[str, Any]] = []
    result: list[dict[str, Any]] = []
    for item in assignments:
        destination = lineage_destination.get(item["organization_lineage"])
        if destination is None or destination == item["partition"]:
            result.append(dict(item))
            continue
        if item["repository_token"] in touched_repository_tokens:
            raise PolicyError("TOUCHED_REPOSITORY_REASSIGNMENT_FORBIDDEN")
        replacement = {**item, "partition": destination}
        changed.append(
            {
                "repository_token": item["repository_token"],
                "organization_lineage": item["organization_lineage"],
                "from_partition": item["partition"],
                "to_partition": destination,
                "candidate_group_count": item["candidate_group_count"],
                "source_record_id": item["source_record_id"],
            }
        )
        result.append(replacement)
    return result, changed


def rebalance_partition_plan(args: argparse.Namespace) -> dict[str, Any]:
    """Reassign only untouched lineages, then append new rights-approved supply."""

    private_root = _require_root(args.private_root, "G:")
    base_plan = load_json(args.partition_plan)
    probe_summary = load_json(args.probe_summary)
    if (
        base_plan.get("schema_version") != "lumi-trace-v0.4-pre-feature-partition-plan-v1"
        or probe_summary.get("schema_version")
        != "lumi-trace-v0.4-repository-rights-probe-summary-v1"
        or base_plan.get("sealed_before_feature_design") is not True
        or base_plan.get("sealed_before_training") is not True
        or base_plan.get("qualification_state") != "SEALED_UNOPENED"
        or base_plan.get("protected_holdback_state") != "SEALED_UNOPENED"
    ):
        raise ContractError("base plan or rebalance probe is malformed")

    moves: dict[str, str] = {}
    for value in args.move_repository:
        token, separator, destination = value.partition("=")
        if not separator or re.fullmatch(r"[0-9a-f]{24}", token) is None or token in moves:
            raise ValueError("--move-repository must use one unique 24-hex-token=PARTITION")
        moves[token] = destination
    if not moves:
        raise ValueError("at least one --move-repository is required")
    touched_tokens = {
        path.name
        for path in (private_root / "immutable-repository-objects").iterdir()
        if path.is_dir()
    }
    reassigned, changed = _reassign_untouched_lineages(
        list(base_plan["assignments"]),
        moves=moves,
        touched_repository_tokens=touched_tokens,
    )

    supply_targets: dict[str, int] = {}
    for value in args.supply_target:
        partition, separator, raw_target = value.partition("=")
        if not separator or partition in supply_targets:
            raise ValueError("--supply-target must use unique PARTITION=RAW_GROUPS")
        try:
            supply_targets[partition] = int(raw_target)
        except ValueError as exc:
            raise ValueError("--supply-target value must be an integer") from exc
    if not supply_targets:
        raise ValueError("at least one --supply-target is required")

    source_root = private_root / "candidate-source-register" / "repositories"
    run_suffix = "" if probe_summary["probe_run"] == "run1" else f".{probe_summary['probe_run']}"
    candidates: list[dict[str, Any]] = []
    for decision in probe_summary["decisions"]:
        if decision["state"] != "RIGHTS_PRECHECK_PASSED":
            continue
        token = decision["repository_token"]
        source = load_json(source_root / f"{token}{run_suffix}.json")
        repository = _repository_from_source(source)
        candidates.append(
            {
                "repository": repository,
                "repository_token": token,
                "source_record_id": source["record_id"],
                "repository_family_id": source["payload"]["repository_family"],
                "organization_lineage": repository.split("/", 1)[0],
                "candidate_group_count": decision["candidate_group_count"],
                "licence": source["payload"]["repository_licence"],
                "head_revision": source["payload"]["immutable_revision"],
            }
        )
    assignments, added = _augment_assignments(
        reassigned,
        candidates,
        supply_targets=supply_targets,
        family_candidate_cap=args.family_candidate_cap,
    )
    organization_partitions: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        organization_partitions[item["organization_lineage"]].add(item["partition"])
    if any(len(partitions) != 1 for partitions in organization_partitions.values()):
        raise PolicyError("REBALANCED_PLAN_ORGANIZATION_OVERLAP")
    raw_counts = dict(
        sorted(
            (
                partition,
                sum(
                    min(item["candidate_group_count"], args.family_candidate_cap)
                    for item in assignments
                    if item["partition"] == partition
                ),
            )
            for partition in PARTITIONS
        )
    )
    rebalanced = {
        **{
            key: value
            for key, value in base_plan.items()
            if key
            not in {
                "plan_id",
                "assignments",
                "partition_repository_counts",
                "partition_raw_group_counts",
            }
        },
        "supersedes_plan_id": base_plan["plan_id"],
        "rebalance_probe_summary_id": probe_summary["summary_id"],
        "rebalance_reason": args.augmentation_reason,
        "rebalance_method": (
            "MEASURED_AGGREGATE_AUDIT_YIELD / COMPLETE_UNTOUCHED_LINEAGES_ONLY / "
            "APPEND_NEW_RIGHTS_APPROVED_SUPPLY / NO_CASE_LEVEL_SELECTION"
        ),
        "requested_raw_supply_targets": dict(sorted(supply_targets.items())),
        "assignments": sorted(
            assignments,
            key=lambda item: (
                item["partition"],
                item["organization_lineage"],
                item["repository"],
            ),
        ),
        "partition_repository_counts": dict(
            sorted(Counter(item["partition"] for item in assignments).items())
        ),
        "partition_raw_group_counts": raw_counts,
        "organization_lineage_count": len(organization_partitions),
        "organization_cross_partition_overlap": 0,
        "touched_repository_count_at_rebalance": len(touched_tokens),
        "touched_assignment_changes": 0,
        "reassigned_repository_count": len(changed),
        "reassignment_records": changed,
        "added_repository_count": len(added),
        "added_repository_counts": dict(
            sorted(Counter(item["partition"] for item in added).items())
        ),
        "sealed_before_feature_design": True,
        "sealed_before_training": True,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
        "training_started": False,
        "weights_downloaded": False,
    }
    rebalanced["plan_id"] = stable_id("v0.4-pre-feature-partition-plan", rebalanced)
    _write_once(
        private_root / "manifests" / f"pre-feature-partition-plan-{args.plan_run}.json",
        rebalanced,
    )
    return {
        "plan_id": rebalanced["plan_id"],
        "supersedes_plan_id": rebalanced["supersedes_plan_id"],
        "reassigned_repository_count": len(changed),
        "touched_assignment_changes": 0,
        "added_repository_count": len(added),
        "added_repository_counts": rebalanced["added_repository_counts"],
        "partition_repository_counts": rebalanced["partition_repository_counts"],
        "partition_raw_group_counts": raw_counts,
        "qualification_state": "SEALED_UNOPENED",
        "protected_holdback_state": "SEALED_UNOPENED",
    }


def _run_inert_git(command: list[str], *, timeout: int = 300) -> bytes:
    process = subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=_git_environment(),
        timeout=timeout,
    )
    if process.returncode != 0:
        error = process.stderr.decode("utf-8", errors="replace")[-2000:]
        raise ContractError(f"inert Git command failed ({process.returncode}): {error}")
    return process.stdout


def _git(
    bare_repository: Path,
    arguments: list[str],
    *,
    hooks_directory: Path,
    timeout: int = 300,
) -> bytes:
    return _run_inert_git(
        [
            "git",
            "-c",
            f"core.hooksPath={hooks_directory}",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "submodule.recurse=false",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            f"--git-dir={bare_repository}",
            *arguments,
        ],
        timeout=timeout,
    )


def _initialise_bare_repository(bare_repository: Path, *, hooks_directory: Path) -> None:
    hooks_directory.mkdir(parents=True, exist_ok=True)
    if bare_repository.exists():
        if not (bare_repository / "HEAD").is_file() or not (bare_repository / "objects").is_dir():
            raise PolicyError("BARE_REPOSITORY_IDENTITY_INVALID")
        return
    bare_repository.parent.mkdir(parents=True, exist_ok=True)
    _run_inert_git(
        [
            "git",
            "-c",
            f"core.hooksPath={hooks_directory}",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "init",
            "--bare",
            str(bare_repository),
        ]
    )


def _fetch_fixes(
    bare_repository: Path,
    *,
    hooks_directory: Path,
    repository: str,
    revisions: list[str],
) -> tuple[list[str], dict[str, str]]:
    url = f"https://github.com/{repository}.git"
    accepted: list[str] = []
    rejected: dict[str, str] = {}
    valid: list[str] = []
    for revision in revisions:
        if _REVISION.fullmatch(revision) is None:
            rejected[revision] = "FIXING_REVISION_INVALID"
        else:
            valid.append(revision)
    for offset in range(0, len(valid), 16):
        batch = valid[offset : offset + 16]
        refspecs = [f"+{revision}:refs/lumi-trace/v0.4/fixes/{revision}" for revision in batch]
        batch_succeeded = True
        try:
            _git(
                bare_repository,
                [
                    "fetch",
                    "--force",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--depth=2",
                    url,
                    *refspecs,
                ],
                hooks_directory=hooks_directory,
                timeout=300,
            )
        except (ContractError, OSError, subprocess.SubprocessError):
            batch_succeeded = False
        for revision in batch:
            try:
                if not batch_succeeded:
                    _git(
                        bare_repository,
                        [
                            "fetch",
                            "--force",
                            "--no-tags",
                            "--no-recurse-submodules",
                            "--depth=2",
                            url,
                            f"+{revision}:refs/lumi-trace/v0.4/fixes/{revision}",
                        ],
                        hooks_directory=hooks_directory,
                        timeout=180,
                    )
                resolved = (
                    _git(
                        bare_repository,
                        ["rev-parse", "--verify", f"{revision}^{{commit}}"],
                        hooks_directory=hooks_directory,
                    )
                    .decode("ascii")
                    .strip()
                )
                if resolved != revision:
                    raise PolicyError("FIXING_REVISION_IDENTITY_MISMATCH")
                accepted.append(revision)
            except (
                ContractError,
                OSError,
                PolicyError,
                subprocess.SubprocessError,
                UnicodeError,
            ) as exc:
                rejected[revision] = f"INERT_FETCH_FAILED:{str(exc)[-500:]}"
    return accepted, rejected


def _commit_pair(
    bare_repository: Path,
    revision: str,
    *,
    hooks_directory: Path,
) -> tuple[str, str, str]:
    lines = (
        _git(
            bare_repository,
            ["show", "-s", "--format=%T%n%P", revision],
            hooks_directory=hooks_directory,
        )
        .decode("ascii")
        .splitlines()
    )
    if len(lines) != 2:
        raise PolicyError("FIXING_COMMIT_METADATA_INVALID")
    parents = lines[1].split()
    if len(parents) != 1 or _REVISION.fullmatch(parents[0]) is None:
        raise PolicyError("FIXING_COMMIT_NOT_SINGLE_PARENT")
    parent = parents[0]
    parent_tree = (
        _git(
            bare_repository,
            ["show", "-s", "--format=%T", parent],
            hooks_directory=hooks_directory,
        )
        .decode("ascii")
        .strip()
    )
    if _REVISION.fullmatch(lines[0]) is None or _REVISION.fullmatch(parent_tree) is None:
        raise PolicyError("COMMIT_TREE_IDENTITY_INVALID")
    return parent, parent_tree, lines[0]


def _tree_entries(
    bare_repository: Path,
    revision: str,
    *,
    hooks_directory: Path,
) -> list[TreeEntry]:
    raw = _git(
        bare_repository,
        ["-c", "core.quotepath=false", "ls-tree", "-rlz", "--full-tree", revision],
        hooks_directory=hooks_directory,
    )
    entries: list[TreeEntry] = []
    for row in raw.split(b"\x00"):
        if not row:
            continue
        metadata, separator, raw_path = row.partition(b"\t")
        fields = metadata.decode("ascii").split()
        if not separator or len(fields) != 4:
            raise ContractError("Git tree entry is malformed")
        mode, object_type, object_id, size = fields
        entries.append(
            TreeEntry(
                mode=mode,
                object_type=object_type,
                object_id=object_id,
                path=raw_path.decode("utf-8", errors="strict"),
                size_bytes=None if size == "-" else int(size),
            )
        )
    return entries


def _read_blob_at(
    bare_repository: Path,
    revision: str,
    path: str,
    *,
    hooks_directory: Path,
    maximum_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    object_expression = f"{revision}:{path}"
    size_text = (
        _git(
            bare_repository,
            ["cat-file", "-s", object_expression],
            hooks_directory=hooks_directory,
        )
        .decode("ascii")
        .strip()
    )
    size = int(size_text)
    if size < 0 or size > maximum_bytes:
        raise PolicyError("GIT_BLOB_SIZE_LIMIT")
    body = _git(
        bare_repository,
        ["cat-file", "blob", object_expression],
        hooks_directory=hooks_directory,
    )
    if len(body) != size:
        raise ContractError("Git blob size identity mismatch")
    return body


def _read_object_blob(
    bare_repository: Path,
    object_id: str,
    *,
    hooks_directory: Path,
    maximum_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    size = int(
        _git(
            bare_repository,
            ["cat-file", "-s", object_id],
            hooks_directory=hooks_directory,
        )
        .decode("ascii")
        .strip()
    )
    if size < 0 or size > maximum_bytes:
        raise PolicyError("GIT_BLOB_SIZE_LIMIT")
    body = _git(
        bare_repository,
        ["cat-file", "blob", object_id],
        hooks_directory=hooks_directory,
    )
    if len(body) != size:
        raise ContractError("Git object blob size identity mismatch")
    return body


def _batch_scan_text_objects(
    bare_repository: Path,
    object_ids: list[str],
    *,
    hooks_directory: Path,
    blob_cache: dict[str, list[dict[str, str]]],
) -> None:
    pending = sorted({object_id for object_id in object_ids if object_id not in blob_cache})
    if not pending:
        return
    command = [
        "git",
        "-c",
        f"core.hooksPath={hooks_directory}",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        f"--git-dir={bare_repository}",
        "cat-file",
        "--batch",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
    )
    assert process.stdin is not None and process.stdout is not None
    for object_id in pending:
        process.stdin.write(f"{object_id}\n".encode("ascii"))
        process.stdin.flush()
        header = process.stdout.readline().decode("ascii").rstrip("\n")
        fields = header.split()
        if len(fields) != 3 or fields[0] != object_id or fields[1] != "blob":
            process.kill()
            raise ContractError("Git batch blob identity mismatch")
        size = int(fields[2])
        if size < 0 or size > 2 * 1024 * 1024:
            process.kill()
            raise PolicyError("GIT_BATCH_BLOB_SIZE_LIMIT")
        body = process.stdout.read(size)
        if len(body) != size or process.stdout.read(1) != b"\n":
            process.kill()
            raise ContractError("Git batch blob framing mismatch")
        try:
            blob_cache[object_id] = scan_text(body.decode("utf-8"))
        except UnicodeError:
            blob_cache[object_id] = [{"category": "INVALID_TEXT_ENCODING", "severity": "REVIEW"}]
    process.stdin.close()
    process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    return_code = process.wait(timeout=300)
    if return_code != 0:
        raise ContractError(f"Git batch scan failed: {stderr.decode(errors='replace')[-1000:]}")


def _changed_paths(
    bare_repository: Path,
    parent: str,
    fix: str,
    *,
    hooks_directory: Path,
) -> list[str]:
    raw = _git(
        bare_repository,
        [
            "-c",
            "diff.external=",
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            parent,
            fix,
        ],
        hooks_directory=hooks_directory,
    )
    paths = [item.decode("utf-8", errors="strict") for item in raw.split(b"\x00") if item]
    if not paths or len(paths) > 200:
        raise PolicyError("FIXING_CHANGE_PATH_COUNT_REJECTED")
    scan_tree_entries(
        [
            TreeEntry("100644", "blob", f"{index + 1:040x}", path, 0)
            for index, path in enumerate(paths)
        ],
        limits=AcquisitionLimits(maximum_files=200, maximum_total_bytes=1),
    )
    return paths


def _patch_for_path(
    bare_repository: Path,
    parent: str,
    fix: str,
    path: str,
    *,
    hooks_directory: Path,
) -> bytes:
    patch = _git(
        bare_repository,
        [
            "-c",
            "diff.external=",
            "diff",
            "--unified=0",
            "--no-ext-diff",
            "--no-textconv",
            parent,
            fix,
            "--",
            path,
        ],
        hooks_directory=hooks_directory,
    )
    if len(patch) > 4 * 1024 * 1024:
        raise PolicyError("FIXING_DIFF_SIZE_LIMIT")
    changed_lines = sum(
        line.startswith((b"+", b"-")) and not line.startswith((b"+++", b"---"))
        for line in patch.splitlines()
    )
    if changed_lines == 0 or changed_lines > 400:
        raise PolicyError("FIXING_DIFF_CHANGE_COUNT_REJECTED")
    return patch


def _historical_licence(
    bare_repository: Path,
    revision: str,
    *,
    hooks_directory: Path,
    expected_identifier: str,
) -> dict[str, str]:
    for name in _LICENCE_NAMES:
        try:
            body = _read_blob_at(
                bare_repository,
                revision,
                name,
                hooks_directory=hooks_directory,
                maximum_bytes=1024 * 1024,
            )
            text = body.decode("utf-8")
            identifier = detect_code_licence(text)
        except (ContractError, PolicyError, UnicodeError, ValueError):
            continue
        if identifier != expected_identifier:
            raise PolicyError("HISTORICAL_LICENCE_IDENTIFIER_MISMATCH")
        if any(item["severity"] == "CRITICAL" for item in scan_text(text)):
            raise PolicyError("HISTORICAL_LICENCE_SCAN_FAILED")
        return {"path": name, "sha256": sha256_bytes(body), "identifier": identifier}
    raise PolicyError("HISTORICAL_LICENCE_NOT_VERIFIED")


def _scan_snapshot(
    bare_repository: Path,
    revision: str,
    *,
    hooks_directory: Path,
    blob_cache: dict[str, list[dict[str, str]]],
) -> tuple[dict[str, Any], list[TreeEntry]]:
    scan = scan_tree_entries(
        _tree_entries(bare_repository, revision, hooks_directory=hooks_directory),
        limits=AcquisitionLimits(),
    )
    findings: list[dict[str, Any]] = []
    scanned_text_blobs = 0
    text_entries = [
        entry
        for entry in scan["regular_entries"]
        if PurePosixPath(entry.path).suffix.casefold() in _MODEL_INPUT_TEXT_SUFFIXES
        and entry.size_bytes is not None
        and entry.size_bytes <= 2 * 1024 * 1024
    ]
    _batch_scan_text_objects(
        bare_repository,
        [entry.object_id for entry in text_entries],
        hooks_directory=hooks_directory,
        blob_cache=blob_cache,
    )
    for entry in text_entries:
        scanned_text_blobs += 1
        findings.extend(
            {
                "path_identity": stable_id("repository-path", entry.path),
                "category": finding["category"],
                "severity": finding["severity"],
                "production_python": is_python_production(entry.path),
            }
            for finding in blob_cache[entry.object_id]
        )
    critical = sum(item["severity"] == "CRITICAL" for item in findings)
    quarantined_paths = sorted(
        {item["path_identity"] for item in findings if item["severity"] in {"CRITICAL", "REVIEW"}}
    )
    summary = {
        "regular_file_count": scan["regular_file_count"],
        "total_bytes": scan["total_bytes"],
        "inert_gitlink_count": scan["inert_gitlink_count"],
        "inert_symlink_count": scan["inert_symlink_count"],
        "scanned_text_blob_count": scanned_text_blobs,
        "finding_counts": dict(sorted(Counter(item["category"] for item in findings).items())),
        "critical_finding_count": critical,
        "critical_production_python_finding_count": sum(
            item["severity"] == "CRITICAL" and item["production_python"] for item in findings
        ),
        "quarantined_path_identities": quarantined_paths,
        "decision": ("PASSED_WITH_PATH_EXCLUSIONS" if quarantined_paths else "PASSED"),
        "repository_code_executed": False,
    }
    return summary, scan["regular_entries"]


def _rights_material(
    *,
    basis: str,
    evidence_ids: list[str],
    included: bool,
    training: str = "PERMITTED",
    redistribution: str = "PROHIBITED",
) -> dict[str, Any]:
    return {
        "retention": "PERMITTED",
        "evaluation": "PERMITTED",
        "transformation": "PERMITTED",
        "training": training,
        "redistribution": redistribution,
        "evidence_ids": evidence_ids,
        "basis": basis,
        "included_in_model_input": included,
    }


def _group_rights_matrix(
    candidate: dict[str, Any],
    *,
    source_record: dict[str, Any],
    vulnerable_revision: str,
    licence_receipts: list[dict[str, str]],
) -> dict[str, Any]:
    source_id = source_record["record_id"]
    advisory_id = stable_id(
        "advisory-evidence",
        {
            "id": candidate["advisory_id"],
            "sha256": candidate["advisory_entry_sha256"],
        },
    )
    licence_ids = [stable_id("licence-evidence", receipt) for receipt in licence_receipts]
    record = make_record(
        "rights-matrix-v1",
        {
            "subject_id": candidate["candidate_id"],
            "exact_revision": vulnerable_revision,
            "materials": {
                "repository_code": _rights_material(
                    basis="Exact-revision permissive code licence.",
                    evidence_ids=[source_id, *licence_ids],
                    included=True,
                    redistribution="PERMITTED",
                ),
                "advisory_prose": _rights_material(
                    basis="CC-BY-4.0 advisory source; prose excluded from learned input.",
                    evidence_ids=[advisory_id],
                    included=False,
                    redistribution="PERMITTED",
                ),
                "vulnerability_metadata": _rights_material(
                    basis="CC-BY-4.0 advisory metadata with attribution.",
                    evidence_ids=[advisory_id],
                    included=True,
                    redistribution="PERMITTED",
                ),
                "fixing_diff": _rights_material(
                    basis="Exact-revision code licence; diff used only for labels.",
                    evidence_ids=[source_id, *licence_ids],
                    included=False,
                    redistribution="PERMITTED",
                ),
                "labels": _rights_material(
                    basis="Skylark-owned controlled-review labels.",
                    evidence_ids=["lumi-trace-v0.4-label-policy:1"],
                    included=True,
                    redistribution="PROHIBITED",
                ),
                "derived_features": _rights_material(
                    basis="Skylark-owned deterministic derived features.",
                    evidence_ids=["lumi-trace-v0.4-preprocessing-policy:1"],
                    included=True,
                    redistribution="PROHIBITED",
                ),
                "trained_weights": _rights_material(
                    basis="No trained weights exist.",
                    evidence_ids=["lumi-trace-v0.4-no-weights:1"],
                    included=False,
                    training="NOT_APPLICABLE",
                    redistribution="NOT_APPLICABLE",
                ),
            },
            "reviewer_role": "CONTROLLED_ITEM_RIGHTS_REVIEWER",
            "review_status": "APPROVED",
            "reviewed_at": "2026-07-26T00:00:00Z",
        },
    )
    validate_rights_matrix(record)
    return record


def _transition_records(
    candidate: dict[str, Any],
    *,
    final_state: str,
    evidence_ids: list[str],
) -> list[dict[str, Any]]:
    states = [
        ("PROPOSED", "QUARANTINED_ACQUIRED"),
        ("QUARANTINED_ACQUIRED", "RIGHTS_REVIEWED"),
        ("RIGHTS_REVIEWED", "PROVENANCE_VERIFIED"),
        ("PROVENANCE_VERIFIED", "SECURITY_SCANNED"),
        ("SECURITY_SCANNED", "LABELLED_UNREVIEWED"),
        ("LABELLED_UNREVIEWED", "CONTROLLED_REVIEWED"),
        ("CONTROLLED_REVIEWED", "INDEPENDENCE_VERIFIED"),
        ("INDEPENDENCE_VERIFIED", final_state),
    ]
    records: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    for sequence, (source, target) in enumerate(states, start=1):
        record = make_record(
            "data-state-transition-v1",
            {
                "item_id": candidate["candidate_id"],
                "from_state": source,
                "to_state": target,
                "sequence": sequence,
                "previous_transition_id": previous["record_id"] if previous else None,
                "decision_receipt_id": evidence_ids[min(sequence - 1, len(evidence_ids) - 1)],
                "supporting_receipt_ids": evidence_ids,
                "actor_role": "CONTROLLED_V0_4_ASSURANCE_WORKFLOW",
                "reason": f"Required audit stage completed: {target}.",
                "occurred_at": "2026-07-26T00:00:00Z",
            },
        )
        validate_state_transition(record, previous=previous)
        records.append(record)
        previous = record
    return records


def _load_advisory_inputs(archive_path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with ZipFile(archive_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.endswith(".json") or info.file_size > 2_000_000:
                continue
            value = json.loads(archive.read(info))
            if not isinstance(value, dict) or not isinstance(value.get("id"), str):
                continue
            result[value["id"]] = {
                "summary": str(value.get("summary", ""))[:2000],
                "details": str(value.get("details", ""))[:4000],
                "aliases": sorted(
                    item for item in value.get("aliases", []) if isinstance(item, str)
                )[:20],
            }
    return result


def _candidate_token(candidate: dict[str, Any]) -> str:
    return candidate["candidate_id"].split(":", 1)[1][:24]


def _reconsidered_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    replacement = {
        **candidate,
        "supersedes_candidate_id": candidate["candidate_id"],
        "assurance_policy_id": RECONSIDERED_PATH_QUARANTINE_POLICY,
    }
    replacement["candidate_id"] = stable_id(
        "v0.4-candidate-group",
        {
            "supersedes_candidate_id": candidate["candidate_id"],
            "assurance_policy_id": RECONSIDERED_PATH_QUARANTINE_POLICY,
        },
    )
    return replacement


def _record_reconsideration_success(
    private_root: Path,
    candidate: dict[str, Any],
    *,
    replacement_card_id: str,
) -> None:
    superseded = candidate.get("supersedes_candidate_id")
    if not isinstance(superseded, str):
        return
    value = {
        "schema_version": "lumi-trace-v0.4-private-policy-reconsideration-v1",
        "superseded_candidate_id": superseded,
        "replacement_candidate_id": candidate["candidate_id"],
        "replacement_card_id": replacement_card_id,
        "from_state": "REJECTED",
        "to_state": "RETIRED",
        "reason": (
            "Whole-snapshot rejection superseded by path-level quarantine; "
            "the labelled target remains subject to fail-closed scanning."
        ),
        "assurance_policy_id": RECONSIDERED_PATH_QUARANTINE_POLICY,
        "append_only": True,
        "training_started": False,
    }
    value["correction_id"] = stable_id(
        "v0.4-policy-reconsideration",
        value,
    )
    token = superseded.split(":", 1)[1][:24]
    _write_once(
        private_root / "retired" / "policy-reconsiderations" / f"{token}.json",
        value,
    )


def _backfill_supporting_evidence(
    private_root: Path,
    *,
    cards: list[dict[str, Any]],
    plan: dict[str, Any],
) -> int:
    """Materialize supporting records already preserved in admission receipts."""

    register = load_json(private_root / "candidate-source-register" / "candidate-register.json")
    candidates = {item["candidate_id"]: item for item in register["candidates"]}
    for path in sorted(
        (private_root / "candidate-source-register" / "reconsidered").glob("*.json")
    ):
        item = load_json(path)["candidate"]
        candidates[item["candidate_id"]] = item
    assignments = {item["repository_token"]: item for item in plan["assignments"]}
    created = 0
    for card in cards:
        group_id = card["payload"]["group_id"]
        token = group_id.split(":", 1)[1][:24]
        receipts = sorted((private_root / "runs" / "private" / "intake").rglob(f"{token}.json"))
        if len(receipts) != 1:
            raise PolicyError("GROUP_ADMISSION_RECEIPT_MISSING_OR_AMBIGUOUS")
        receipt = load_json(receipts[0])
        candidate = candidates.get(group_id)
        assignment = assignments.get(receipt["repository_token"])
        if candidate is None or assignment is None:
            raise PolicyError("SUPPORTING_EVIDENCE_SOURCE_MISSING")
        advisory_evidence_id = stable_id(
            "advisory-evidence",
            {
                "id": candidate["advisory_id"],
                "sha256": candidate["advisory_entry_sha256"],
            },
        )
        advisory = {
            "schema_version": "lumi-trace-v0.4-private-advisory-evidence-v1",
            "evidence_id": advisory_evidence_id,
            "group_id": group_id,
            "advisory_identity": candidate["advisory_entry_sha256"],
            "source_record_id": card["payload"]["source_identities"][0],
            "licence": OSV_DATA_LICENCE,
            "licence_evidence_url": OSV_LICENCE_EVIDENCE_URL,
            "prose_included_in_model_input": False,
        }
        fixing = {
            "schema_version": "lumi-trace-v0.4-private-fixing-evidence-v1",
            "group_id": group_id,
            "family_id": card["payload"]["family_id"],
            "vulnerable_revision": stable_id("revision", receipt["vulnerable_revision"]),
            "fixed_revision": stable_id("revision", receipt["fixed_revision"]),
            "vulnerable_tree": stable_id("tree", receipt["vulnerable_tree"]),
            "fixed_tree": stable_id("tree", receipt["fixed_tree"]),
            "single_parent": True,
            "changed_path_identities": [
                stable_id("repository-path", path) for path in receipt["changed_paths"]
            ],
            "target_set_identity": card["payload"]["fingerprints"]["target"],
            "fixing_diff_sha256": card["payload"]["fingerprints"]["fixing_diff"],
            "repository_code_executed": False,
        }
        fixing["evidence_id"] = stable_id("v0.4-fixing-evidence", fixing)
        security_scan = {
            "schema_version": "lumi-trace-v0.4-private-security-scan-v1",
            "group_id": group_id,
            "vulnerable_snapshot": receipt["snapshot_scans"]["vulnerable"],
            "fixed_snapshot": receipt["snapshot_scans"]["fixed"],
            "target_source_scan": "PASSED",
            "poisoning": "PASSED_WITH_INERT_TEXT_EXCLUSIONS",
            "secrets": "PASSED",
            "privacy": "PASSED",
            "repository_code_executed": False,
        }
        security_scan["scan_id"] = stable_id("v0.4-security-scan", security_scan)
        lineage = {
            "schema_version": "lumi-trace-v0.4-private-lineage-record-v1",
            "group_id": group_id,
            "family_id": card["payload"]["family_id"],
            "organization_lineage": assignment["organization_lineage"],
            "vulnerability_lineage": candidate["vulnerability_lineage_id"],
            "fingerprints": card["payload"]["fingerprints"],
            "partition": card["payload"]["partition"],
            "cross_partition_relationship": False,
        }
        lineage["lineage_id"] = stable_id("v0.4-lineage-record", lineage)
        leakage = audit_answer_leakage(
            receipt["finding_input"],
            group_id=group_id,
            target_paths=[target["path"] for target in receipt["private_targets"]],
            target_symbols=[target["symbol"] for target in receipt["private_targets"]],
            target_lines=[target["region"]["start_line"] for target in receipt["private_targets"]],
        )
        if leakage["record_id"] != card["payload"]["cue_and_leakage"]["leakage_audit_id"]:
            raise PolicyError("BACKFILLED_LEAKAGE_IDENTITY_MISMATCH")
        outputs = (
            (
                private_root / "security-evidence" / "advisories" / f"{token}.json",
                advisory,
            ),
            (
                private_root / "security-evidence" / "fixing" / f"{token}.json",
                fixing,
            ),
            (
                private_root / "quarantine" / "repositories" / f"{token}.json",
                security_scan,
            ),
            (
                private_root / "fingerprints" / "lineage" / f"{token}.json",
                lineage,
            ),
            (
                private_root / "manifests" / "answer-leakage" / f"{token}.json",
                leakage,
            ),
        )
        for path, value in outputs:
            if not path.exists():
                created += 1
            _write_once(path, value)
    return created


def _rejection_record(
    candidate: dict[str, Any],
    *,
    partition: str,
    stage: str,
    reason: str,
) -> dict[str, Any]:
    record = {
        "schema_version": "lumi-trace-v0.4-private-group-rejection-v1",
        "candidate_id": candidate["candidate_id"],
        "repository_family_id": candidate["repository_family_provisional"],
        "partition": partition,
        "state": "REJECTED",
        "stage": stage,
        "reason": reason[:1000],
        "training_eligible": False,
        "qualification_consumed": False,
        "holdback_opened": False,
    }
    record["rejection_id"] = stable_id("v0.4-group-rejection", record)
    return record


def _process_candidate(
    candidate: dict[str, Any],
    *,
    assignment: dict[str, Any],
    source_record: dict[str, Any],
    advisory_input: dict[str, Any],
    bare_repository: Path,
    hooks_directory: Path,
    private_root: Path,
    blob_cache: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    partition = assignment["partition"]
    token = _candidate_token(candidate)
    fixed = candidate["fixing_revision"]
    parent, parent_tree, fixed_tree = _commit_pair(
        bare_repository,
        fixed,
        hooks_directory=hooks_directory,
    )
    expected_licence = source_record["payload"]["repository_licence"]
    parent_licence = _historical_licence(
        bare_repository,
        parent,
        hooks_directory=hooks_directory,
        expected_identifier=expected_licence,
    )
    fixed_licence = _historical_licence(
        bare_repository,
        fixed,
        hooks_directory=hooks_directory,
        expected_identifier=expected_licence,
    )
    parent_scan, _ = _scan_snapshot(
        bare_repository,
        parent,
        hooks_directory=hooks_directory,
        blob_cache=blob_cache,
    )
    fixed_scan, _ = _scan_snapshot(
        bare_repository,
        fixed,
        hooks_directory=hooks_directory,
        blob_cache=blob_cache,
    )
    changed_paths = _changed_paths(
        bare_repository,
        parent,
        fixed,
        hooks_directory=hooks_directory,
    )
    production_paths = [path for path in changed_paths if is_python_production(path)]
    harness_paths = [path for path in changed_paths if is_python_harness(path)]
    if not 1 <= len(production_paths) <= 5:
        raise PolicyError("PYTHON_PRODUCTION_TARGET_COUNT_REJECTED")
    changes: list[PythonChange] = []
    patch_bodies: list[bytes] = []
    for path in production_paths:
        parent_body = _read_blob_at(
            bare_repository,
            parent,
            path,
            hooks_directory=hooks_directory,
        )
        fixed_body = _read_blob_at(
            bare_repository,
            fixed,
            path,
            hooks_directory=hooks_directory,
        )
        try:
            parent_text = parent_body.decode("utf-8")
            fixed_text = fixed_body.decode("utf-8")
        except UnicodeError as exc:
            raise PolicyError("TARGET_SOURCE_ENCODING_REJECTED") from exc
        target_findings = [*scan_text(parent_text), *scan_text(fixed_text)]
        if any(
            finding["severity"] == "CRITICAL"
            or finding["category"] in {"PROMPT_INJECTION_TEXT", "HIDDEN_UNICODE"}
            for finding in target_findings
        ):
            raise PolicyError("TARGET_SOURCE_POISON_OR_SECRET_FINDING")
        patch = _patch_for_path(
            bare_repository,
            parent,
            fixed,
            path,
            hooks_directory=hooks_directory,
        )
        patch_bodies.append(patch)
        changes.append(
            PythonChange(
                path=path,
                parent_source=parent_text,
                fixed_source=fixed_text,
                patch=patch.decode("utf-8", errors="replace"),
            )
        )

    pass_one_targets = blind_label_pass_one(changes)
    if not 1 <= len(pass_one_targets) <= 5:
        raise PolicyError("BLIND_PASS_ONE_TARGET_COUNT_REJECTED")
    pass_one = make_record(
        "label-review-pass-v1",
        {
            "group_id": candidate["candidate_id"],
            "pass_number": 1,
            "workspace_id": f"workspace:v0.4:pass-1:{token}",
            "reviewer_role": "CODEX_CONTROLLED_BLIND_LABEL_PASS_1",
            "input_hashes": [
                stable_id("tree", parent_tree),
                sha256_bytes(b"\n".join(patch_bodies)),
                candidate["advisory_entry_sha256"],
            ],
            "other_pass_visible": False,
            "candidate_output_visible": False,
            "model_output_visible": False,
            "conclusion": "ACCEPT",
            "targets": public_targets(pass_one_targets),
            "created_at": "2026-07-26T00:00:00Z",
        },
    )
    _write_once(private_root / "labels" / "pass-1" / f"{token}.json", pass_one)

    # This pass receives only source/diff inputs, never the first-pass record.
    pass_two_targets = blind_label_pass_two(changes)
    if not 1 <= len(pass_two_targets) <= 5:
        raise PolicyError("BLIND_PASS_TWO_TARGET_COUNT_REJECTED")
    pass_two = make_record(
        "label-review-pass-v1",
        {
            "group_id": candidate["candidate_id"],
            "pass_number": 2,
            "workspace_id": f"workspace:v0.4:pass-2:{token}",
            "reviewer_role": "CODEX_CONTROLLED_BLIND_LABEL_PASS_2",
            "input_hashes": [
                stable_id("tree", parent_tree),
                sha256_bytes(b"\n".join(patch_bodies)),
                candidate["advisory_entry_sha256"],
            ],
            "other_pass_visible": False,
            "candidate_output_visible": False,
            "model_output_visible": False,
            "conclusion": "ACCEPT",
            "targets": public_targets(pass_two_targets),
            "created_at": "2026-07-26T00:00:00Z",
        },
    )
    _write_once(private_root / "labels" / "pass-2" / f"{token}.json", pass_two)
    if not blind_passes_agree(pass_one_targets, pass_two_targets):
        raise PolicyError("CONTROLLED_BLIND_LABEL_DISAGREEMENT")
    resolution = make_record(
        "label-review-resolution-v1",
        {
            "group_id": candidate["candidate_id"],
            "pass_record_ids": [pass_one["record_id"], pass_two["record_id"]],
            "comparison": {
                "target_agreement": True,
                "conclusion_agreement": True,
            },
            "disagreements": [],
            "resolution": "ACCEPT",
            "adjudicator_role": "CONTROLLED_LABEL_COMPARISON",
            "candidate_output_visible": False,
            "correction_ids": [],
            "resolved_at": "2026-07-26T00:00:00Z",
        },
    )
    validate_label_resolution(resolution, first=pass_one, second=pass_two)

    private_targets = [target["private_mapping"] for target in pass_one_targets]
    finding_input = {
        "advisory_identifier": candidate["advisory_id"],
        "aliases": advisory_input["aliases"],
        "packages": candidate["packages"],
        "summary": advisory_input["summary"],
        "description": advisory_input["details"],
    }
    leakage = audit_answer_leakage(
        finding_input,
        group_id=candidate["candidate_id"],
        target_paths=[target["path"] for target in private_targets],
        target_symbols=[target["symbol"] for target in private_targets],
        target_lines=[target["region"]["start_line"] for target in private_targets],
    )
    if leakage["payload"]["decision"] == "QUARANTINE":
        raise PolicyError("ANSWER_LEAKAGE_AUDIT_FAILED")
    rights = _group_rights_matrix(
        candidate,
        source_record=source_record,
        vulnerable_revision=parent,
        licence_receipts=[parent_licence, fixed_licence],
    )
    final_state = "TRAINING_ELIGIBLE" if partition == "TRAINING" else "EVALUATION_ONLY"
    hard_negatives = [
        {
            "path_identity": stable_id("hard-negative-path", path),
            "role": "HARNESS",
            "family": "NATURAL_SECURITY_TEST_OR_REPRODUCTION_HARNESS",
        }
        for path in harness_paths[:5]
    ]
    target_fingerprint = stable_id("target-set", public_targets(pass_one_targets))
    normalized_source = "\n".join(" ".join(change.parent_source.split()) for change in changes)
    fingerprints = {
        "source_exact": stable_id("source-exact", parent_tree),
        "source_near": sha256_bytes(normalized_source.encode("utf-8")),
        "fixing_diff": sha256_bytes(b"\n".join(patch_bodies)),
        "advisory": candidate["advisory_entry_sha256"],
        "target": target_fingerprint,
        "vulnerability_lineage": candidate["vulnerability_lineage_id"],
    }
    advisory_evidence_id = stable_id(
        "advisory-evidence",
        {
            "id": candidate["advisory_id"],
            "sha256": candidate["advisory_entry_sha256"],
        },
    )
    fixing_evidence = {
        "schema_version": "lumi-trace-v0.4-private-fixing-evidence-v1",
        "group_id": candidate["candidate_id"],
        "family_id": assignment["repository_family_id"],
        "vulnerable_revision": stable_id("revision", parent),
        "fixed_revision": stable_id("revision", fixed),
        "vulnerable_tree": stable_id("tree", parent_tree),
        "fixed_tree": stable_id("tree", fixed_tree),
        "single_parent": True,
        "changed_path_identities": [stable_id("repository-path", path) for path in changed_paths],
        "target_set_identity": target_fingerprint,
        "fixing_diff_sha256": fingerprints["fixing_diff"],
        "repository_code_executed": False,
    }
    fixing_evidence["evidence_id"] = stable_id(
        "v0.4-fixing-evidence",
        fixing_evidence,
    )
    advisory_evidence = {
        "schema_version": "lumi-trace-v0.4-private-advisory-evidence-v1",
        "evidence_id": advisory_evidence_id,
        "group_id": candidate["candidate_id"],
        "advisory_identity": fingerprints["advisory"],
        "source_record_id": source_record["record_id"],
        "licence": OSV_DATA_LICENCE,
        "licence_evidence_url": OSV_LICENCE_EVIDENCE_URL,
        "prose_included_in_model_input": False,
    }
    security_scan = {
        "schema_version": "lumi-trace-v0.4-private-security-scan-v1",
        "group_id": candidate["candidate_id"],
        "vulnerable_snapshot": parent_scan,
        "fixed_snapshot": fixed_scan,
        "target_source_scan": "PASSED",
        "poisoning": "PASSED_WITH_INERT_TEXT_EXCLUSIONS",
        "secrets": "PASSED",
        "privacy": "PASSED",
        "repository_code_executed": False,
    }
    security_scan["scan_id"] = stable_id("v0.4-security-scan", security_scan)
    lineage_record = {
        "schema_version": "lumi-trace-v0.4-private-lineage-record-v1",
        "group_id": candidate["candidate_id"],
        "family_id": assignment["repository_family_id"],
        "organization_lineage": assignment["organization_lineage"],
        "vulnerability_lineage": candidate["vulnerability_lineage_id"],
        "fingerprints": fingerprints,
        "partition": partition,
        "cross_partition_relationship": False,
    }
    lineage_record["lineage_id"] = stable_id("v0.4-lineage-record", lineage_record)
    card = make_record(
        "group-audit-card-v1",
        {
            "group_id": candidate["candidate_id"],
            "family_id": assignment["repository_family_id"],
            "source_identities": [source_record["record_id"]],
            "revision_identities": [
                stable_id("revision", parent),
                stable_id("revision", fixed),
            ],
            "rights_matrix_id": rights["record_id"],
            "vulnerable_fixed_relationship": {
                "single_parent": True,
                "vulnerable_revision": stable_id("revision", parent),
                "fixed_revision": stable_id("revision", fixed),
                "vulnerable_tree": stable_id("tree", parent_tree),
                "fixed_tree": stable_id("tree", fixed_tree),
                "scope": "TARGET_ISSUE_ONLY",
            },
            "security_evidence_ids": [
                advisory_evidence_id,
                fixing_evidence["evidence_id"],
            ],
            "label": {
                "primary_role": "VULNERABLE_IMPLEMENTATION",
                "target_exists": True,
                "symbols_and_regions_resolve": True,
                "constructed_without_runner_or_model_output": True,
                "target_set_identity": target_fingerprint,
            },
            "hard_negatives": hard_negatives,
            "controls": [
                {
                    "kind": "MATCHED_FIXED_CONTROL_TARGET_ISSUE_ONLY",
                    "tree_identity": stable_id("tree", fixed_tree),
                }
            ],
            "cue_and_leakage": {
                "leakage_audit_id": leakage["record_id"],
                "natural_cue_count": len(leakage["payload"]["natural_cues"]),
                "required_views": leakage["payload"]["required_views"],
                "quarantined_nonproduction_path_count": len(
                    {
                        *parent_scan["quarantined_path_identities"],
                        *fixed_scan["quarantined_path_identities"],
                    }
                ),
                "quarantined_path_count": len(
                    {
                        *parent_scan["quarantined_path_identities"],
                        *fixed_scan["quarantined_path_identities"],
                    }
                ),
            },
            "fingerprints": fingerprints,
            "audits": {
                "provenance": "PASSED",
                "target_resolution": "PASSED",
                "lineage": "PASSED",
                "duplicates": "PASSED",
                "answer_leakage": "PASSED",
                "poisoning": "PASSED",
                "secrets": "PASSED",
                "privacy": "PASSED",
                "controlled_review": "PASSED",
            },
            "review_receipt_ids": [
                pass_one["record_id"],
                pass_two["record_id"],
                resolution["record_id"],
            ],
            "permitted_uses": (
                ["TRAINING", "PRIVATE_EVALUATION"]
                if final_state == "TRAINING_ELIGIBLE"
                else ["PRIVATE_EVALUATION"]
            ),
            "partition": partition,
            "correction_history": [],
            "final_state": final_state,
            "admission_reasons": [
                "Exact vulnerable/fixed ancestry and historical licences verify.",
                "Two controlled blind label passes agree before runtime output.",
                "Snapshot, leakage, poison, secret, and privacy controls pass.",
                "Every flagged repository path is excluded from derived model inputs.",
            ],
        },
    )
    validate_group_audit_card(
        card,
        rights_matrix=rights if final_state == "TRAINING_ELIGIBLE" else None,
    )
    evidence_ids = [
        source_record["record_id"],
        rights["record_id"],
        leakage["record_id"],
        pass_one["record_id"],
        pass_two["record_id"],
        resolution["record_id"],
    ]
    transitions = _transition_records(
        candidate,
        final_state=final_state,
        evidence_ids=evidence_ids,
    )
    receipt = {
        "schema_version": "lumi-trace-v0.4-private-group-admission-v1",
        "candidate_id": candidate["candidate_id"],
        "group_audit_card_id": card["record_id"],
        "partition": partition,
        "repository_token": assignment["repository_token"],
        "vulnerable_revision": parent,
        "fixed_revision": fixed,
        "vulnerable_tree": parent_tree,
        "fixed_tree": fixed_tree,
        "historical_licences": [parent_licence, fixed_licence],
        "snapshot_scans": {
            "vulnerable": parent_scan,
            "fixed": fixed_scan,
        },
        "changed_paths": changed_paths,
        "private_targets": private_targets,
        "hard_negative_paths": harness_paths[:5],
        "finding_input_identity": stable_id("finding-input", finding_input),
        "finding_input": finding_input,
        "repository_code_executed": False,
        "network_after_acquisition": "DENIED_BY_WORKFLOW",
        "state": final_state,
    }
    receipt["admission_id"] = stable_id("v0.4-group-admission", receipt)
    _write_once(private_root / "rights" / "matrices" / f"{token}.json", rights)
    _write_once(
        private_root / "security-evidence" / "advisories" / f"{token}.json",
        advisory_evidence,
    )
    _write_once(
        private_root / "security-evidence" / "fixing" / f"{token}.json",
        fixing_evidence,
    )
    _write_once(
        private_root / "quarantine" / "repositories" / f"{token}.json",
        security_scan,
    )
    _write_once(
        private_root / "fingerprints" / "lineage" / f"{token}.json",
        lineage_record,
    )
    _write_once(
        private_root / "manifests" / "answer-leakage" / f"{token}.json",
        leakage,
    )
    _write_once(private_root / "labels" / "resolution" / f"{token}.json", resolution)
    _write_once(
        private_root / "fingerprints" / "duplicates" / f"{token}.json",
        {"group_id": candidate["candidate_id"], **fingerprints},
    )
    _write_once(
        private_root
        / "manifests"
        / "audit-cards"
        / partition.casefold().replace("_", "-")
        / f"{token}.json",
        card,
    )
    _write_once(
        private_root / "ledgers" / "transitions" / f"{token}.json",
        transitions,
    )
    _write_once(
        private_root
        / "runs"
        / "private"
        / "intake"
        / partition.casefold().replace("_", "-")
        / f"{token}.json",
        receipt,
    )
    return {
        "candidate_id": candidate["candidate_id"],
        "card_id": card["record_id"],
        "state": final_state,
        "partition": partition,
        "hard_negative": bool(hard_negatives),
    }


def acquire_groups(args: argparse.Namespace) -> dict[str, Any]:
    """Fetch pinned fixes and construct audited groups without executing source."""

    private_root = _require_root(args.private_root, "G:")
    work_root = _require_root(args.work_root, "F:")
    plan = load_json(args.partition_plan)
    register = load_json(private_root / "candidate-source-register" / "candidate-register.json")
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != "lumi-trace-v0.4-pre-feature-partition-plan-v1"
        or plan.get("sealed_before_feature_design") is not True
        or plan.get("protected_holdback_state") != "SEALED_UNOPENED"
        or not isinstance(register, dict)
    ):
        raise ContractError("sealed partition plan or candidate register is invalid")
    if re.fullmatch(r"[a-z0-9-]{1,24}", args.acquisition_run) is None:
        raise ValueError("--acquisition-run must be a lowercase safe token")
    archive_path = args.advisory_archive.resolve()
    if archive_path.drive.casefold() != "g:" or not archive_path.is_file():
        raise ValueError("advisory archive must remain on governed G:")
    if sha256_file(archive_path) != register["source_archive"]["sha256"]:
        raise PolicyError("ADVISORY_ARCHIVE_IDENTITY_MISMATCH")
    advisory_inputs = _load_advisory_inputs(archive_path)
    selected_partitions = set(args.partition)
    if not selected_partitions or not selected_partitions <= set(PARTITIONS):
        raise ValueError("--partition contains an unsupported partition")
    assignments = [item for item in plan["assignments"] if item["partition"] in selected_partitions]
    if args.skip_existing_acquisition_receipts:
        assignments = [
            assignment
            for assignment in assignments
            if not (
                private_root
                / "immutable-repository-objects"
                / assignment["repository_token"]
                / f"acquisition-receipt.{args.acquisition_run}.json"
            ).is_file()
        ]
    if args.maximum_repositories:
        assignments = assignments[: args.maximum_repositories]
    reconsidered_by_id: dict[str, dict[str, Any]] = {}
    if args.reconsider_policy_rejections:
        selected_repositories = {assignment["repository"] for assignment in assignments}
        originals = {item["candidate_id"]: item for item in register["candidates"]}
        for path in sorted((private_root / "rejected" / "groups").glob("*.json")):
            rejection = load_json(path)
            if rejection["reason"].split(":", 1)[0] not in (RECONSIDERABLE_REJECTION_REASONS):
                continue
            original = originals.get(rejection["candidate_id"])
            if original is None or original["repository"] not in selected_repositories:
                continue
            replacement = _reconsidered_candidate(original)
            reconsidered_by_id[original["candidate_id"]] = replacement
            token = _candidate_token(replacement)
            proposal = {
                "schema_version": ("lumi-trace-v0.4-private-reconsidered-candidate-v1"),
                "candidate": replacement,
                "superseded_rejection_id": rejection["rejection_id"],
                "assurance_policy_id": RECONSIDERED_PATH_QUARANTINE_POLICY,
                "state": "PROPOSED",
                "append_only": True,
            }
            proposal["proposal_id"] = stable_id(
                "v0.4-reconsidered-candidate",
                proposal,
            )
            _write_once(
                private_root / "candidate-source-register" / "reconsidered" / f"{token}.json",
                proposal,
            )
    candidates_by_repository: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in register["candidates"]:
        selected = reconsidered_by_id.get(candidate["candidate_id"], candidate)
        candidates_by_repository[selected["repository"]].append(selected)
    if not 1 <= args.workers <= 16:
        raise ValueError("--workers must be between 1 and 16")

    def process_assignment(
        assignment: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assignment_admitted: list[dict[str, Any]] = []
        assignment_rejected: list[dict[str, Any]] = []
        repository = assignment["repository"]
        token = assignment["repository_token"]
        source_record = _load_assignment_source(
            private_root / "candidate-source-register" / "repositories",
            repository_token=token,
            source_record_id=assignment["source_record_id"],
        )
        candidates = sorted(
            candidates_by_repository[repository],
            key=lambda item: (
                stable_id("case-order", item["candidate_id"]),
                item["candidate_id"],
            ),
        )
        all_unique_fixes: list[dict[str, Any]] = []
        seen_fixes: set[str] = set()
        for candidate in candidates:
            if candidate["fixing_revision"] in seen_fixes:
                continue
            seen_fixes.add(candidate["fixing_revision"])
            all_unique_fixes.append(candidate)
        unique_fixes = all_unique_fixes[: args.maximum_cases_per_repository]
        deferred_fixes = all_unique_fixes[args.maximum_cases_per_repository :]
        for candidate in deferred_fixes:
            candidate_token = _candidate_token(candidate)
            card_path = (
                private_root
                / "manifests"
                / "audit-cards"
                / assignment["partition"].casefold().replace("_", "-")
                / f"{candidate_token}.json"
            )
            rejection_path = private_root / "rejected" / "groups" / f"{candidate_token}.json"
            if card_path.is_file():
                card = load_json(card_path)
                assignment_admitted.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "card_id": card["record_id"],
                        "state": card["payload"]["final_state"],
                        "partition": assignment["partition"],
                        "hard_negative": bool(card["payload"]["hard_negatives"]),
                    }
                )
                continue
            if rejection_path.is_file():
                assignment_rejected.append(load_json(rejection_path))
                continue
            rejection = _rejection_record(
                candidate,
                partition=assignment["partition"],
                stage="CORPUS_DIVERSITY_CAP",
                reason="FAMILY_CASE_CAP_DEFERRED",
            )
            _write_once(rejection_path, rejection)
            assignment_rejected.append(rejection)
        repository_root = private_root / "immutable-repository-objects" / token
        bare_repository = repository_root / "objects.git"
        hooks_directory = repository_root / "empty-hooks"
        _initialise_bare_repository(
            bare_repository,
            hooks_directory=hooks_directory,
        )
        accepted_fixes, fetch_rejections = _fetch_fixes(
            bare_repository,
            hooks_directory=hooks_directory,
            repository=repository,
            revisions=[candidate["fixing_revision"] for candidate in unique_fixes],
        )
        accepted_set = set(accepted_fixes)
        blob_cache: dict[str, list[dict[str, str]]] = {}
        for candidate in unique_fixes:
            candidate_token = _candidate_token(candidate)
            partition_slug = assignment["partition"].casefold().replace("_", "-")
            card_path = (
                private_root
                / "manifests"
                / "audit-cards"
                / partition_slug
                / f"{candidate_token}.json"
            )
            rejection_path = private_root / "rejected" / "groups" / f"{candidate_token}.json"
            if card_path.is_file():
                card = load_json(card_path)
                result = {
                    "candidate_id": candidate["candidate_id"],
                    "card_id": card["record_id"],
                    "state": card["payload"]["final_state"],
                    "partition": assignment["partition"],
                    "hard_negative": bool(card["payload"]["hard_negatives"]),
                }
                assignment_admitted.append(result)
                _record_reconsideration_success(
                    private_root,
                    candidate,
                    replacement_card_id=card["record_id"],
                )
                continue
            if rejection_path.is_file():
                assignment_rejected.append(load_json(rejection_path))
                continue
            if candidate["fixing_revision"] not in accepted_set:
                rejection = _rejection_record(
                    candidate,
                    partition=assignment["partition"],
                    stage="INERT_ACQUISITION",
                    reason=fetch_rejections.get(
                        candidate["fixing_revision"], "FIXING_REVISION_NOT_FETCHED"
                    ),
                )
                _write_once(rejection_path, rejection)
                assignment_rejected.append(rejection)
                continue
            advisory_input = advisory_inputs.get(candidate["advisory_id"])
            if advisory_input is None:
                rejection = _rejection_record(
                    candidate,
                    partition=assignment["partition"],
                    stage="SECURITY_EVIDENCE",
                    reason="ADVISORY_INPUT_IDENTITY_MISSING",
                )
                _write_once(rejection_path, rejection)
                assignment_rejected.append(rejection)
                continue
            try:
                result = _process_candidate(
                    candidate,
                    assignment=assignment,
                    source_record=source_record,
                    advisory_input=advisory_input,
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
                rejection = _rejection_record(
                    candidate,
                    partition=assignment["partition"],
                    stage="ITEM_AUDIT_AND_LABEL",
                    reason=str(exc),
                )
                _write_once(rejection_path, rejection)
                assignment_rejected.append(rejection)
                continue
            assignment_admitted.append(result)
            _record_reconsideration_success(
                private_root,
                candidate,
                replacement_card_id=result["card_id"],
            )
        repository_receipt = {
            "schema_version": "lumi-trace-v0.4-private-repository-acquisition-v1",
            "acquisition_run": args.acquisition_run,
            "repository_token": token,
            "source_record_id": source_record["record_id"],
            "partition": assignment["partition"],
            "requested_fix_count": len(unique_fixes),
            "deferred_fix_count": len(deferred_fixes),
            "fetched_fix_count": len(accepted_fixes),
            "fetch_rejection_count": len(fetch_rejections),
            "bare_repository": "GOVERNED_PRIVATE_OBJECT_STORE",
            "hooks_disabled": True,
            "submodules_acquired": False,
            "lfs_objects_acquired": False,
            "checkout_performed": False,
            "repository_code_executed": False,
        }
        repository_receipt["receipt_id"] = stable_id(
            "v0.4-repository-acquisition", repository_receipt
        )
        _write_once(
            private_root
            / "immutable-repository-objects"
            / token
            / f"acquisition-receipt.{args.acquisition_run}.json",
            repository_receipt,
        )
        return assignment_admitted, assignment_rejected

    with ThreadPoolExecutor(
        max_workers=args.workers,
        thread_name_prefix="v04-group-acquisition",
    ) as executor:
        assignment_results = list(executor.map(process_assignment, assignments))
    admitted = [item for admitted_items, _ in assignment_results for item in admitted_items]
    rejected = [item for _, rejected_items in assignment_results for item in rejected_items]
    state_counts = Counter(item["state"] for item in admitted)
    rejection_counts = Counter(item["reason"].split(":", 1)[0] for item in rejected)
    summary = {
        "schema_version": "lumi-trace-v0.4-private-group-acquisition-summary-v1",
        "acquisition_run": args.acquisition_run,
        "partition_plan_id": plan["plan_id"],
        "partitions": sorted(selected_partitions),
        "repository_count": len(assignments),
        "admitted_group_count": len(admitted),
        "admitted_family_count": len(
            {
                item["repository_family_id"]
                for item in assignments
                if any(
                    result["partition"] == item["partition"]
                    and result["candidate_id"]
                    in {
                        candidate["candidate_id"]
                        for candidate in candidates_by_repository[item["repository"]]
                    }
                    for result in admitted
                )
            }
        ),
        "state_counts": dict(sorted(state_counts.items())),
        "hard_negative_group_count": sum(item["hard_negative"] for item in admitted),
        "rejected_group_count": len(rejected),
        "rejection_reason_counts": dict(sorted(rejection_counts.items())),
        "repository_code_executed": False,
        "training_started": False,
        "weights_downloaded": False,
        "qualification_consumed": False,
        "holdback_opened": False,
    }
    summary["summary_id"] = stable_id("v0.4-group-acquisition-summary", summary)
    summary_name = f"{args.acquisition_run}-" + "-".join(
        sorted(partition.casefold() for partition in selected_partitions)
    )
    _write_once(
        private_root / "manifests" / f"group-acquisition-{summary_name}.json",
        summary,
    )
    # The work root receives logs only; governed identities remain private on G:.
    work_status = {
        "schema_version": "lumi-trace-v0.4-work-status-v1",
        "private_summary_id": summary["summary_id"],
        "partitions": summary["partitions"],
        "completed": True,
        "repository_code_executed": False,
    }
    work_status["status_id"] = stable_id("v0.4-work-status", work_status)
    _write_once(work_root / "logs" / f"group-acquisition-{summary_name}.json", work_status)
    return summary


def _family_cap_exclusions(
    cards: list[dict[str, Any]],
    *,
    partition: str,
    maximum_groups_per_family: int,
    already_excluded: set[str],
) -> set[str]:
    if partition not in PARTITIONS or maximum_groups_per_family < 1:
        raise ValueError("family cap configuration is invalid")
    by_family: dict[str, list[str]] = defaultdict(list)
    for card in cards:
        if card["record_id"] not in already_excluded and card["payload"]["partition"] == partition:
            by_family[card["payload"]["family_id"]].append(card["record_id"])
    return {
        card_id
        for member_ids in by_family.values()
        for card_id in sorted(member_ids)[maximum_groups_per_family:]
    }


def finalize_corpus(args: argparse.Namespace) -> dict[str, Any]:
    """Deduplicate admitted cards and issue the strongest honest readiness state."""

    private_root = _require_root(args.private_root, "G:")
    if re.fullmatch(r"[a-z0-9-]{1,24}", args.finalize_run) is None:
        raise ValueError("--finalize-run must be a lowercase safe token")
    plan = load_json(args.partition_plan)
    sample_plan = load_json(private_root / "manifests" / "corpus-sample-plan.json")
    if (
        plan.get("schema_version") != "lumi-trace-v0.4-pre-feature-partition-plan-v1"
        or sample_plan.get("schema_version") != "corpus-sample-plan-v1"
    ):
        raise ContractError("V0.4 plan identities are invalid")
    cards = [
        load_json(path)
        for path in sorted((private_root / "manifests" / "audit-cards").rglob("*.json"))
    ]
    for card in cards:
        validate_group_audit_card(card)
    if not cards:
        raise PolicyError("NO_AUDITED_GROUPS_TO_FINALIZE")
    supporting_evidence_backfill_count = _backfill_supporting_evidence(
        private_root,
        cards=cards,
        plan=plan,
    )

    cards_by_id = {card["record_id"]: card for card in cards}
    excluded_ids: set[str] = set()
    duplicate_clusters: list[dict[str, Any]] = []
    by_fingerprint: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        for kind, value in card["payload"]["fingerprints"].items():
            by_fingerprint[(kind, value)].append(card)
    for (kind, value), members in sorted(by_fingerprint.items()):
        unique_members = {member["record_id"]: member for member in members}
        if len(unique_members) < 2:
            continue
        partitions = {member["payload"]["partition"] for member in unique_members.values()}
        if len(partitions) > 1:
            cluster_excluded = sorted(unique_members)
            decision = "QUARANTINE_ALL_CROSS_PARTITION_DUPLICATES"
        else:
            cluster_excluded = []
            decision = "OBSERVED_WITHIN_PARTITION_FINGERPRINT_OVERLAP"
        excluded_ids.update(cluster_excluded)
        duplicate_clusters.append(
            {
                "fingerprint_kind": kind,
                "fingerprint_identity": stable_id("duplicate-fingerprint", value),
                "member_card_ids": sorted(unique_members),
                "partitions": sorted(partitions),
                "decision": decision,
                "excluded_card_ids": cluster_excluded,
            }
        )
    by_group_signature: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for card in cards:
        fingerprints = card["payload"]["fingerprints"]
        by_group_signature[
            (
                card["payload"]["partition"],
                fingerprints["source_exact"],
                fingerprints["fixing_diff"],
                fingerprints["advisory"],
                fingerprints["target"],
                fingerprints["vulnerability_lineage"],
            )
        ].append(card)
    for signature, members in sorted(by_group_signature.items()):
        if len(members) < 2:
            continue
        ordered = sorted(member["record_id"] for member in members)
        cluster_excluded = ordered[1:]
        excluded_ids.update(cluster_excluded)
        duplicate_clusters.append(
            {
                "fingerprint_kind": "composite_group_identity",
                "fingerprint_identity": stable_id(
                    "duplicate-group-signature",
                    list(signature),
                ),
                "member_card_ids": ordered,
                "partitions": [signature[0]],
                "decision": "KEEP_STABLE_MINIMUM_ID_SUPERSEDE_EXACT_GROUP_DUPLICATES",
                "excluded_card_ids": cluster_excluded,
            }
        )

    family_partitions: dict[str, set[str]] = defaultdict(set)
    for card in cards:
        family_partitions[card["payload"]["family_id"]].add(card["payload"]["partition"])
    cross_partition_families = {
        family: sorted(partitions)
        for family, partitions in family_partitions.items()
        if len(partitions) > 1
    }
    if cross_partition_families:
        excluded_ids.update(
            card["record_id"]
            for card in cards
            if card["payload"]["family_id"] in cross_partition_families
        )
    training_family_cap = 25
    training_cap_excluded_ids = _family_cap_exclusions(
        cards,
        partition="TRAINING",
        maximum_groups_per_family=training_family_cap,
        already_excluded=excluded_ids,
    )
    excluded_ids.update(training_cap_excluded_ids)

    accepted = [card for card in cards if card["record_id"] not in excluded_ids]
    correction_records = [
        {
            "schema_version": "lumi-trace-v0.4-deduplication-correction-v1",
            "card_id": card_id,
            "group_id": cards_by_id[card_id]["payload"]["group_id"],
            "from_state": cards_by_id[card_id]["payload"]["final_state"],
            "to_state": "SUPERSEDED",
            "reason": "CORPUS_WIDE_DUPLICATE_OR_FAMILY_INDEPENDENCE_CONFLICT",
            "append_only": True,
        }
        for card_id in sorted(excluded_ids)
    ]
    for correction in correction_records:
        if correction["card_id"] in training_cap_excluded_ids:
            correction["reason"] = "PREDECLARED_TRAINING_FAMILY_GROUP_CAP_25"
    for correction in correction_records:
        correction["correction_id"] = stable_id("v0.4-deduplication-correction", correction)
        token = correction["correction_id"].split(":", 1)[1][:24]
        _write_once(
            private_root / "labels" / "corrections" / f"{token}.json",
            correction,
        )

    duplicate_audit = {
        "schema_version": "lumi-trace-v0.4-duplicate-audit-v1",
        "input_card_count": len(cards),
        "accepted_card_count": len(accepted),
        "excluded_card_count": len(excluded_ids),
        "duplicate_cluster_count": len(duplicate_clusters),
        "cross_partition_family_count": len(cross_partition_families),
        "training_family_group_cap": training_family_cap,
        "training_family_cap_excluded_count": len(training_cap_excluded_ids),
        "clusters": duplicate_clusters,
        "methods": [
            "source_exact",
            "source_near",
            "fixing_diff",
            "advisory",
            "target",
            "vulnerability_lineage",
        ],
    }
    duplicate_audit["audit_id"] = stable_id("v0.4-duplicate-audit", duplicate_audit)
    _write_once(
        private_root / "fingerprints" / "duplicates" / "corpus-wide-audit.json",
        duplicate_audit,
    )

    counts: dict[str, dict[str, int]] = {}
    for partition in PARTITIONS:
        partition_cards = [card for card in accepted if card["payload"]["partition"] == partition]
        counts[partition] = {
            "groups": len(partition_cards),
            "families": len({card["payload"]["family_id"] for card in partition_cards}),
            "matched_controls": sum(bool(card["payload"]["controls"]) for card in partition_cards),
            "hard_negative_groups": sum(
                bool(card["payload"]["hard_negatives"]) for card in partition_cards
            ),
        }
    independence = audit_partition_independence(accepted)
    independence_record = _private_manifest(
        "lumi-trace-v0.4-private-independence-audit-v1",
        "v0.4-independence-audit",
        {
            **independence,
            "duplicate_audit_id": duplicate_audit["audit_id"],
            "sealed_before_training": True,
            "qualification_consumed": False,
            "holdback_opened": False,
        },
    )
    _write_once(
        private_root / "manifests" / f"cross-partition-independence-{args.finalize_run}.json",
        independence_record,
    )

    partition_manifest_ids: dict[str, str] = {}
    for partition in PARTITIONS:
        partition_cards = [card for card in accepted if card["payload"]["partition"] == partition]
        family_ids = sorted({card["payload"]["family_id"] for card in partition_cards})
        manifest = _private_manifest(
            "lumi-trace-v0.4-private-partition-manifest-v1",
            "v0.4-partition-manifest",
            {
                "partition": partition,
                "audit_card_ids": sorted(card["record_id"] for card in partition_cards),
                "group_ids": sorted(card["payload"]["group_id"] for card in partition_cards),
                "family_ids": family_ids,
                "group_count": len(partition_cards),
                "family_count": len(family_ids),
                "single_use": partition == "QUALIFICATION",
                "opened": False,
                "consumed": False,
                "sealed_before_training": True,
            },
        )
        slug = partition.casefold().replace("_", "-")
        _write_once(
            private_root / "partitions" / slug / f"manifest-{args.finalize_run}.json",
            manifest,
        )
        partition_manifest_ids[partition] = manifest["record_id"]

    evaluation_cards = [
        card for card in accepted if card["payload"]["final_state"] == "EVALUATION_ONLY"
    ]
    evaluation_manifest = _private_manifest(
        "lumi-trace-v0.4-private-evaluation-only-manifest-v1",
        "v0.4-evaluation-only-manifest",
        {
            "audit_card_ids": sorted(card["record_id"] for card in evaluation_cards),
            "group_count": len(evaluation_cards),
            "family_count": len({card["payload"]["family_id"] for card in evaluation_cards}),
            "permitted_use": "PRIVATE_EVALUATION_ONLY",
            "training_admission": "PROHIBITED",
            "qualification_consumed": False,
            "holdback_opened": False,
        },
    )
    _write_once(
        private_root / "manifests" / f"evaluation-only-manifest-{args.finalize_run}.json",
        evaluation_manifest,
    )

    assignment_partition = {item["repository"]: item["partition"] for item in plan["assignments"]}
    candidate_register = load_json(
        private_root / "candidate-source-register" / "candidate-register.json"
    )
    terminalized_unselected_count = 0
    quarantined_unassigned_ids: list[str] = []
    for candidate in candidate_register["candidates"]:
        partition = assignment_partition.get(candidate["repository"])
        if partition is None:
            quarantined_unassigned_ids.append(candidate["candidate_id"])
            continue
        token = _candidate_token(candidate)
        card_path = (
            private_root
            / "manifests"
            / "audit-cards"
            / partition.casefold().replace("_", "-")
            / f"{token}.json"
        )
        rejection_path = private_root / "rejected" / "groups" / f"{token}.json"
        if card_path.is_file() or rejection_path.is_file():
            continue
        rejection = _rejection_record(
            candidate,
            partition=partition,
            stage="FINAL_PROPOSAL_TERMINALIZATION",
            reason="DUPLICATE_FIXING_REVISION_NOT_SELECTED",
        )
        _write_once(rejection_path, rejection)
        terminalized_unselected_count += 1
    unassigned_manifest = _private_manifest(
        "lumi-trace-v0.4-private-unassigned-quarantine-manifest-v1",
        "v0.4-unassigned-quarantine-manifest",
        {
            "candidate_ids": sorted(quarantined_unassigned_ids),
            "candidate_count": len(quarantined_unassigned_ids),
            "state": "QUARANTINED_NOT_IN_FINAL_PARTITION_PLAN",
            "training_admission": "PROHIBITED",
            "qualification_admission": "PROHIBITED",
        },
    )
    _write_once(
        private_root / "manifests" / f"unassigned-quarantine-manifest-{args.finalize_run}.json",
        unassigned_manifest,
    )
    reconsideration_terminal_counts: Counter[str] = Counter()
    reconsideration_quarantined_ids: list[str] = []
    reconsideration_proposals = [
        load_json(path)
        for path in sorted(
            (private_root / "candidate-source-register" / "reconsidered").glob("*.json")
        )
    ]
    for proposal in reconsideration_proposals:
        candidate = proposal["candidate"]
        token = _candidate_token(candidate)
        partition = assignment_partition.get(candidate["repository"])
        card_paths = (
            sorted((private_root / "manifests" / "audit-cards").rglob(f"{token}.json"))
            if partition is not None
            else []
        )
        rejection_path = private_root / "rejected" / "groups" / f"{token}.json"
        if len(card_paths) == 1:
            reconsideration_terminal_counts["ADMITTED"] += 1
        elif rejection_path.is_file():
            reconsideration_terminal_counts["REJECTED"] += 1
        else:
            reconsideration_terminal_counts["QUARANTINED"] += 1
            reconsideration_quarantined_ids.append(proposal["proposal_id"])
    reconsideration_terminal_manifest = _private_manifest(
        "lumi-trace-v0.4-private-reconsideration-terminal-manifest-v1",
        "v0.4-reconsideration-terminal-manifest",
        {
            "proposal_count": len(reconsideration_proposals),
            "terminal_counts": dict(sorted(reconsideration_terminal_counts.items())),
            "quarantined_proposal_ids": sorted(reconsideration_quarantined_ids),
            "quarantined_state": "QUARANTINED_RECONSIDERATION_INCOMPLETE",
            "append_only": True,
        },
    )
    _write_once(
        private_root / "manifests" / f"reconsideration-terminal-manifest-{args.finalize_run}.json",
        reconsideration_terminal_manifest,
    )

    rejections = [
        load_json(path) for path in sorted((private_root / "rejected" / "groups").glob("*.json"))
    ]
    rejected_manifest = _private_manifest(
        "lumi-trace-v0.4-private-rejected-item-manifest-v1",
        "v0.4-rejected-item-manifest",
        {
            "rejection_ids": sorted(item["rejection_id"] for item in rejections),
            "rejected_count": len(rejections),
            "reason_counts": dict(
                sorted(Counter(item["reason"].split(":", 1)[0] for item in rejections).items())
            ),
            "training_eligible_count": 0,
            "terminalized_unselected_proposal_count": terminalized_unselected_count,
            "quarantined_unassigned_candidate_count": len(quarantined_unassigned_ids),
            "quarantined_reconsideration_count": len(reconsideration_quarantined_ids),
        },
    )
    _write_once(
        private_root / "manifests" / f"rejected-item-manifest-{args.finalize_run}.json",
        rejected_manifest,
    )
    policy_reconsiderations = [
        load_json(path)
        for path in sorted((private_root / "retired" / "policy-reconsiderations").glob("*.json"))
    ]
    all_correction_ids = [
        *(item["correction_id"] for item in correction_records),
        *(item["correction_id"] for item in policy_reconsiderations),
    ]
    retired_manifest = _private_manifest(
        "lumi-trace-v0.4-private-retired-item-manifest-v1",
        "v0.4-retired-item-manifest",
        {
            "correction_ids": sorted(all_correction_ids),
            "retired_or_superseded_count": len(all_correction_ids),
            "policy_reconsideration_count": len(policy_reconsiderations),
            "terminalized_unselected_proposal_count": (terminalized_unselected_count),
            "quarantined_unassigned_candidate_count": len(quarantined_unassigned_ids),
            "quarantined_reconsideration_count": len(reconsideration_quarantined_ids),
            "duplicate_supersession_count": len(correction_records),
            "active_training_admission": False,
        },
    )
    _write_once(
        private_root / "manifests" / f"retired-item-manifest-{args.finalize_run}.json",
        retired_manifest,
    )

    lineage_graph = _private_manifest(
        "lumi-trace-v0.4-private-lineage-graph-v1",
        "v0.4-lineage-graph",
        {
            "families": sorted(
                (
                    {
                        "family_id": family_id,
                        "partition": next(iter(partitions)),
                        "group_count": sum(
                            card["payload"]["family_id"] == family_id for card in accepted
                        ),
                    }
                    for family_id, partitions in family_partitions.items()
                    if len(partitions) == 1
                ),
                key=lambda item: item["family_id"],
            ),
            "cross_partition_family_count": 0,
            "organization_split_unit": True,
            "fork_mirror_vendor_upstream_review": "ENFORCED_AT_SOURCE_PLAN",
        },
    )
    _write_once(
        private_root / "fingerprints" / "lineage" / f"corpus-graph-{args.finalize_run}.json",
        lineage_graph,
    )

    security_scans = [
        load_json(path)
        for path in sorted((private_root / "quarantine" / "repositories").glob("*.json"))
    ]
    security_summary = _private_manifest(
        "lumi-trace-v0.4-private-poison-secret-privacy-summary-v1",
        "v0.4-security-assurance-summary",
        {
            "audited_group_count": len(security_scans),
            "poisoning_passed_count": sum(
                item["poisoning"].startswith("PASSED") for item in security_scans
            ),
            "secret_scan_passed_count": sum(item["secrets"] == "PASSED" for item in security_scans),
            "privacy_scan_passed_count": sum(
                item["privacy"] == "PASSED" for item in security_scans
            ),
            "repository_code_executed": False,
            "quarantined_matches_published": False,
        },
    )
    _write_once(
        private_root / "manifests" / f"poison-secret-privacy-summary-{args.finalize_run}.json",
        security_summary,
    )
    cue_summary = _private_manifest(
        "lumi-trace-v0.4-private-cue-availability-summary-v1",
        "v0.4-cue-availability-summary",
        {
            "group_count": len(accepted),
            "groups_with_natural_cues": sum(
                card["payload"]["cue_and_leakage"]["natural_cue_count"] > 0 for card in accepted
            ),
            "required_views": [
                "NATURAL_CUE_MARKED",
                "NO_PATH",
                "NO_SYMBOL",
                "REDUCED_DESCRIPTION",
                "IDENTIFIER_ABLATION",
            ],
            "prohibited_answer_leakage_count": 0,
        },
    )
    _write_once(
        private_root / "manifests" / f"cue-availability-{args.finalize_run}.json",
        cue_summary,
    )
    dataset_card = _private_manifest(
        "lumi-trace-v0.4-private-dataset-card-v1",
        "v0.4-dataset-card",
        {
            "name": "Lumi Trace V0.4 governed natural ranking corpus",
            "product_envelope": "PYTHON_FINDING_GUIDED_CANDIDATE_RANKING",
            "source_policy": "PUBLIC_FIXED_DISCLOSED_PERMISSIVE_REPOSITORIES",
            "advisory_policy": "OSV_PYPI_CC_BY_4_0",
            "partition_manifest_ids": dict(sorted(partition_manifest_ids.items())),
            "group_count": len(accepted),
            "family_count": len({card["payload"]["family_id"] for card in accepted}),
            "limitations": [
                "Python-only primary targets.",
                "Finding-guided candidate ranking, not vulnerability discovery.",
                "No customer or private repository data.",
                "No disposition or repair-generation claim.",
            ],
            "redistribution": "PRIVATE_UNLESS_SEPARATELY_APPROVED",
            "weights_licensed": False,
        },
    )
    data_statement = _private_manifest(
        "lumi-trace-v0.4-private-data-statement-v1",
        "v0.4-data-statement",
        {
            "collection_method": "INERT_EXACT_REVISION_ACQUISITION",
            "label_method": "TWO_CONTROLLED_BLIND_PASSES",
            "rights_review": "ITEM_LEVEL_MATRIX",
            "deduplication": duplicate_audit["methods"],
            "security_review": [
                "POISONING",
                "SECRETS",
                "PRIVACY",
                "ANSWER_LEAKAGE",
            ],
            "repository_code_executed": False,
            "customer_data_used": False,
            "hosted_inference_used": False,
            "case_level_publication": False,
        },
    )
    _write_once(
        private_root / "manifests" / f"dataset-card-{args.finalize_run}.json",
        dataset_card,
    )
    _write_once(
        private_root / "manifests" / f"data-statement-{args.finalize_run}.json",
        data_statement,
    )
    planned = sample_plan["payload"]
    corpus_floors = {
        "training_groups": counts["TRAINING"]["groups"] >= 500,
        "training_families": counts["TRAINING"]["families"] >= 25,
        "engineering_groups": counts["ENGINEERING_DEVELOPMENT"]["groups"]
        >= planned["engineering_development"]["minimum_primary_targets"],
        "engineering_families": counts["ENGINEERING_DEVELOPMENT"]["families"]
        >= planned["engineering_development"]["minimum_families"],
        "model_selection_groups": counts["MODEL_SELECTION"]["groups"]
        >= planned["model_selection"]["minimum_primary_targets"],
        "model_selection_families": counts["MODEL_SELECTION"]["families"]
        >= planned["model_selection"]["minimum_families"],
        "qualification_groups": counts["QUALIFICATION"]["groups"]
        >= planned["qualification"]["minimum_primary_targets"],
        "qualification_controls": counts["QUALIFICATION"]["matched_controls"]
        >= planned["qualification"]["minimum_matched_safe_controls"],
        "qualification_families": counts["QUALIFICATION"]["families"]
        >= planned["qualification"]["minimum_families"],
        "holdback_groups": counts["PROTECTED_HOLDBACK"]["groups"]
        >= planned["protected_holdback"]["minimum_primary_targets"],
        "holdback_families": counts["PROTECTED_HOLDBACK"]["families"]
        >= planned["protected_holdback"]["minimum_families"],
    }
    floors_passed = all(corpus_floors.values()) and not cross_partition_families
    partition_seal: dict[str, Any] | None = None
    training_manifest: dict[str, Any] | None = None
    readiness: dict[str, Any] | None = None
    if floors_passed:
        partition_seal = seal_partitions(
            accepted,
            independence_audit_id=independence_record["record_id"],
            duplicate_audit_id=duplicate_audit["audit_id"],
        )
        rights_records = [
            load_json(path)
            for path in sorted((private_root / "rights" / "matrices").glob("*.json"))
        ]
        rights_by_id = {record["record_id"]: record for record in rights_records}
        training_cards = [
            card for card in accepted if card["payload"]["final_state"] == "TRAINING_ELIGIBLE"
        ]
        training_manifest = build_training_manifest(
            training_cards,
            rights_by_id,
            partition_seal=partition_seal,
            created_at="2026-07-26T00:00:00Z",
        )
        entry_gate_record = load_json(private_root / "manifests" / "training-entry-gates.json")
        gate_values = {
            key: value
            for key, value in entry_gate_record["gates"].items()
            if key
            not in {
                "minimum_500_groups",
                "minimum_25_families",
            }
        }
        readiness = evaluate_training_readiness(
            training_manifest,
            gates=gate_values,
            qualification_opened=False,
            holdback_opened=False,
        )
        _write_once(
            private_root / "manifests" / "final-partition-seal.json",
            partition_seal,
        )
        _write_once(
            private_root / "manifests" / "training-eligibility-manifest.json",
            training_manifest,
        )
        _write_once(
            private_root / "manifests" / "training-readiness.json",
            readiness,
        )

    aggregate = disclosure_safe_projection(accepted)
    aggregate.update(
        {
            "partition_counts": counts,
            "corpus_floors": corpus_floors,
            "all_corpus_floors_passed": floors_passed,
            "duplicate_cluster_count": len(duplicate_clusters),
            "cross_partition_family_count": len(cross_partition_families),
            "training_family_group_cap": training_family_cap,
            "training_family_cap_excluded_count": len(training_cap_excluded_ids),
            "policy_reconsideration_count": len(policy_reconsiderations),
            "terminalized_unselected_proposal_count": (terminalized_unselected_count),
            "quarantined_unassigned_candidate_count": len(quarantined_unassigned_ids),
            "quarantined_reconsideration_count": len(reconsideration_quarantined_ids),
            "training_manifest_id": (training_manifest["record_id"] if training_manifest else None),
            "partition_seal_id": partition_seal["record_id"] if partition_seal else None,
            "training_recommendation": (
                readiness["payload"]["recommendation"] if readiness else "DO_NOT_BEGIN_TRACE_001"
            ),
            "training_started": False,
            "weights_downloaded": False,
            "qualification_consumed": False,
            "holdback_opened": False,
            "supporting_evidence_backfill_count": supporting_evidence_backfill_count,
            "independence_audit_id": independence_record["record_id"],
            "evaluation_only_manifest_id": evaluation_manifest["record_id"],
            "dataset_card_id": dataset_card["record_id"],
            "data_statement_id": data_statement["record_id"],
        }
    )
    aggregate["aggregate_id"] = stable_id("v0.4-corpus-assurance-aggregate", aggregate)
    _write_once(
        private_root / "disclosure-safe" / f"corpus-aggregate-{args.finalize_run}.json",
        aggregate,
    )
    return aggregate


def status(args: argparse.Namespace) -> dict[str, Any]:
    private_root = _require_root(args.private_root, "G:")
    result: dict[str, Any] = {
        "version": VERSION,
        "bootstrap": (private_root / "current-status.json").is_file(),
        "advisory_intake": (private_root / "manifests" / "advisory-intake-summary.json").is_file(),
        "training_started": False,
        "weights_downloaded": False,
        "qualification_opened": False,
        "holdback_opened": False,
    }
    if result["advisory_intake"]:
        summary = load_json(private_root / "manifests" / "advisory-intake-summary.json")
        result["candidate_group_count"] = summary["candidate_group_count"]
        result["candidate_repository_count"] = summary["candidate_repository_count"]
    return result


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
            "bootstrap",
            "ingest-advisories",
            "probe-repositories",
            "plan-partitions",
            "extend-partition-plan",
            "augment-partition-plan",
            "rebalance-partition-plan",
            "acquire-groups",
            "finalize-corpus",
            "status",
        ),
    )
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--collection-date", default="2026-07-26")
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--minimum-candidates", type=int, default=5)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--probe-run", default="run1")
    parser.add_argument("--supersedes-summary-id")
    parser.add_argument("--correction-reason")
    parser.add_argument("--probe-summary", type=Path)
    parser.add_argument("--family-candidate-cap", type=int, default=25)
    parser.add_argument("--minimum-partition-families", type=int, default=8)
    parser.add_argument("--evaluation-raw-groups", type=int, default=160)
    parser.add_argument("--training-raw-groups", type=int, default=800)
    parser.add_argument("--partition-plan", type=Path)
    parser.add_argument("--advisory-archive", type=Path)
    parser.add_argument("--partition", action="append", default=[])
    parser.add_argument("--maximum-repositories", type=int, default=0)
    parser.add_argument("--maximum-cases-per-repository", type=int, default=25)
    parser.add_argument("--skip-existing-acquisition-receipts", action="store_true")
    parser.add_argument("--reconsider-policy-rejections", action="store_true")
    parser.add_argument("--acquisition-run", default="run1")
    parser.add_argument("--finalize-run", default="provisional")
    parser.add_argument("--plan-run", default="extended")
    parser.add_argument("--supply-target", action="append", default=[])
    parser.add_argument("--augmentation-reason")
    parser.add_argument("--move-repository", action="append", default=[])
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.phase == "ingest-advisories" and args.archive is None:
            raise ValueError("--archive is required for ingest-advisories")
        if args.phase == "plan-partitions" and args.probe_summary is None:
            raise ValueError("--probe-summary is required for plan-partitions")
        if args.phase == "extend-partition-plan" and (
            args.probe_summary is None or args.partition_plan is None
        ):
            raise ValueError(
                "--probe-summary and --partition-plan are required for extend-partition-plan"
            )
        if args.phase == "augment-partition-plan" and (
            args.probe_summary is None
            or args.partition_plan is None
            or not args.augmentation_reason
        ):
            raise ValueError(
                "--probe-summary, --partition-plan, and --augmentation-reason "
                "are required for augment-partition-plan"
            )
        if args.phase == "rebalance-partition-plan" and (
            args.probe_summary is None
            or args.partition_plan is None
            or not args.augmentation_reason
        ):
            raise ValueError(
                "--probe-summary, --partition-plan, and --augmentation-reason "
                "are required for rebalance-partition-plan"
            )
        if args.phase == "acquire-groups" and (
            args.partition_plan is None or args.advisory_archive is None
        ):
            raise ValueError(
                "--partition-plan and --advisory-archive are required for acquire-groups"
            )
        if args.phase == "finalize-corpus" and args.partition_plan is None:
            raise ValueError("--partition-plan is required for finalize-corpus")
        result = {
            "bootstrap": bootstrap,
            "ingest-advisories": ingest_advisories,
            "probe-repositories": probe_repositories,
            "plan-partitions": plan_partitions,
            "extend-partition-plan": extend_partition_plan,
            "augment-partition-plan": augment_partition_plan,
            "rebalance-partition-plan": rebalance_partition_plan,
            "acquire-groups": acquire_groups,
            "finalize-corpus": finalize_corpus,
            "status": status,
        }[args.phase](args)
    except (ContractError, PolicyError, OSError, ValueError) as exc:
        print(f"build-v0.4-assurance: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
