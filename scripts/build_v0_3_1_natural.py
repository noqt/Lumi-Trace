# SPDX-License-Identifier: Apache-2.0
"""Build governed private V0.3.1 natural-corpus evidence in explicit phases.

Repository-specific inputs and every derived artifact remain on the governed
private evaluation volumes.  The public repository receives only this generic
builder, contracts, tests, documentation, and a disclosure-safe projection.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
for source_path in (EVAL_SRC, ROOT / "src", ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.canonical import (  # noqa: E402
    dump_json,
    load_json,
    sha256_bytes,
    sha256_file,
    stable_id,
)
from trace_eval.code_metrics import (  # noqa: E402
    aggregate_trace_code_metrics,
    default_metric_specification,
    score_trace_code_case,
)
from trace_eval.contracts import make_record  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.intake import (  # noqa: E402
    AcquisitionLimits,
    TreeEntry,
    acquisition_plan,
    audit_revision_pairs,
    canonical_upstream_url,
    detect_code_licence,
    enforce_publication_decision,
    scan_tree_entries,
    validate_finding_cue_profile,
    validate_group_review,
    validate_intake_proposal,
    validate_rights_dimensions,
    validate_threshold_decision,
    verify_acquisition_receipt,
    verify_licence_evidence,
    verify_pre_run_seal,
)
from trace_eval.metrics import score_run  # noqa: E402
from trace_eval.package import seal_package, verify_package  # noqa: E402
from trace_eval.policy import audit_repository_independence  # noqa: E402
from trace_eval.programme import assess_natural_corpus  # noqa: E402
from trace_eval.registry import load_registry, records_by_schema, write_registry  # noqa: E402
from trace_eval.replay import replay_run  # noqa: E402
from trace_eval.runner import load_run_package, run_registry  # noqa: E402

from lumi_trace.repository import compute_repository_identity  # noqa: E402
from scripts.verify_v0_3_evidence import verify as verify_v03  # noqa: E402

VERSION = "v0.3.1"
EXPECTED_V03_SEAL = (
    "lumi-trace-v0.3-public-evidence:"
    "a56044b38ff78687739a9d01ea32697c57f5b45d67063e8babf9931cc2da7b70"
)
EXPECTED_V01_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GHSA = re.compile(
    r"^GHSA-[23456789cfghjmpqrvwx]{4}-"
    r"[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$"
)
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIFF_HUNK = re.compile(r"^@@ -(?P<start>[0-9]+)(?:,(?P<count>[0-9]+))? ")
_NON_PRODUCTION_PARTS = frozenset(
    {
        ".github",
        "benchmark",
        "benchmarks",
        "ci",
        "doc",
        "docs",
        "example",
        "examples",
        "script",
        "scripts",
        "test",
        "testing",
        "tests",
    }
)


def _require_governed_root(path: Path, drive: str) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"required governed {drive} root is unavailable")
    return resolved


def _safe_token(prefix: str, value: str) -> str:
    return stable_id(prefix, {"value": value}).split(":", 1)[1][:20]


def _load_catalog(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "lumi-trace-v0.3.1-private-intake-catalog-v1"
        or not isinstance(value.get("repositories"), list)
    ):
        raise ContractError("private intake catalog is malformed")
    repositories = value["repositories"]
    if not 8 <= len(repositories) <= 12:
        raise ContractError("pilot catalog must propose 8 to 12 repositories")
    slugs: set[str] = set()
    fixes: set[str] = set()
    advisories: set[str] = set()
    for repository in repositories:
        if not isinstance(repository, dict) or _SLUG.fullmatch(repository.get("slug", "")) is None:
            raise ContractError("catalog repository slug is invalid")
        if repository["slug"].casefold() in slugs:
            raise ContractError("catalog contains a duplicate repository")
        slugs.add(repository["slug"].casefold())
        if repository.get("split") not in {"development", "qualification"}:
            raise ContractError("catalog split is invalid")
        cases = repository.get("cases")
        if not isinstance(cases, list) or not cases:
            raise ContractError("catalog repository has no security cases")
        for case in cases:
            if (
                not isinstance(case, dict)
                or _GHSA.fullmatch(case.get("ghsa", "")) is None
                or _REVISION.fullmatch(case.get("fix", "")) is None
                or not isinstance(case.get("cve"), str)
            ):
                raise ContractError("catalog security case is malformed")
            if case["ghsa"] in advisories or case["fix"] in fixes:
                raise ContractError("catalog duplicates a security lineage or fix revision")
            advisories.add(case["ghsa"])
            fixes.add(case["fix"])
    return value


def _fetch_osv(ghsa: str) -> tuple[dict[str, Any], bytes]:
    request = urllib.request.Request(
        f"https://api.osv.dev/v1/vulns/{ghsa}",
        headers={"Accept": "application/json", "User-Agent": "Lumi-Trace-Controlled-Intake"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ContractError(f"security advisory fetch failed for {ghsa}")
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024:
        raise ContractError(f"security advisory is oversized for {ghsa}")
    try:
        value = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"security advisory is malformed for {ghsa}") from exc
    if not isinstance(value, dict) or value.get("id") != ghsa:
        raise ContractError(f"security advisory identity mismatch for {ghsa}")
    return value, body


def _advisory_precheck(
    advisory: dict[str, Any],
    *,
    slug: str,
    ghsa: str,
    cve: str,
    fix: str,
) -> dict[str, Any]:
    aliases = advisory.get("aliases", [])
    references = [
        item.get("url")
        for item in advisory.get("references", [])
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ]
    exact_fix = f"https://github.com/{slug}/commit/{fix}"
    weakness = [
        item
        for item in advisory.get("database_specific", {}).get("cwe_ids", [])
        if isinstance(item, str) and item.startswith("CWE-")
    ]
    if cve not in aliases or exact_fix not in references:
        raise PolicyError(f"SECURITY_EVIDENCE_PRECHECK_REJECTED: {ghsa}")
    return {
        "ghsa": ghsa,
        "cve": cve,
        "fix_revision": fix,
        "authoritative_fix_reference": exact_fix,
        "weakness_classes": sorted(set(weakness)) or ["CWE-UNKNOWN"],
        "summary": advisory.get("summary", ""),
        "aliases": sorted(item for item in aliases if isinstance(item, str)),
        "references": sorted(references),
    }


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_governed_root(args.active_root, "F:")
    private_root = _require_governed_root(args.private_root, "G:")
    previous_evidence = verify_v03(ROOT / "evidence" / "v0.3.0")
    if previous_evidence["seal_id"] != EXPECTED_V03_SEAL:
        raise PolicyError("SEALED_V0_3_BASELINE_MISMATCH")
    catalog = _load_catalog(args.catalog)
    prepared = active_root / "intake" / VERSION / "prepared"
    if prepared.exists():
        raise ValueError("refusing to overwrite prepared V0.3.1 intake")
    prepared.mkdir(parents=True)
    repository_index: list[dict[str, Any]] = []
    for repository in catalog["repositories"]:
        slug = repository["slug"]
        token = _safe_token("natural-repository", slug)
        records = prepared / "repositories" / token
        records.mkdir(parents=True)
        evidence_references: list[dict[str, str]] = []
        weakness_classes: set[str] = set()
        cases: list[dict[str, str]] = []
        for case in repository["cases"]:
            advisory, body = _fetch_osv(case["ghsa"])
            precheck = _advisory_precheck(advisory, slug=slug, **case)
            weakness_classes.update(precheck["weakness_classes"])
            evidence_name = f"{_safe_token('security-evidence', case['ghsa'])}.json"
            evidence_path = records / "security-evidence" / evidence_name
            dump_json(evidence_path, advisory)
            evidence_references.append(
                {
                    "advisory_id": case["ghsa"],
                    "canonical_url": f"https://osv.dev/vulnerability/{case['ghsa']}",
                    "retrieval_url": f"https://api.osv.dev/v1/vulns/{case['ghsa']}",
                    "sha256": sha256_bytes(body),
                }
            )
            cases.append(
                {
                    "advisory_id": case["ghsa"],
                    "fix_revision": case["fix"],
                    "evidence_sha256": sha256_bytes(body),
                }
            )
        proposal = make_record(
            "intake-proposal-v1",
            {
                "proposed_repository_id": f"proposed-repository:{token}",
                "canonical_upstream_url": canonical_upstream_url(f"https://github.com/{slug}"),
                "hosting_provider": "GITHUB_PUBLIC",
                "requested_revisions": sorted(case["fix"] for case in repository["cases"]),
                "licence_evidence_location": "ROOT_LICENCE_FILE_AT_EACH_EXACT_REVISION",
                "security_evidence_references": evidence_references,
                "expected_language": repository["language"],
                "expected_weakness_classes": sorted(weakness_classes),
                "project_family": f"family:{token}",
                "known_fork_lineage": f"lineage:{token}",
                "proposed_use": "PRIVATE_EVALUATION_ONLY",
                "expected_retention": "GOVERNED_G_DRIVE_PRIVATE_STORE",
                "operator_id": catalog["operator_id"],
                "decision_identity": f"controlled-intake-decision:{token}",
                "acquisition_state": "PROPOSED",
            },
        )
        validate_intake_proposal(proposal)
        rights_precheck = {
            "schema_version": "lumi-trace-rights-precheck-v1",
            "proposal_id": proposal["record_id"],
            "claimed_code_licence": repository["licence"],
            "code_licence_allowlist_match": repository["licence"]
            in {"Apache-2.0", "MIT", "BSD-3-Clause"},
            "private_evaluation_basis": "PUBLIC_PERMISSIVE_SOURCE_AND_PUBLIC_SECURITY_EVIDENCE",
            "source_redistribution_decision": "PRIVATE_ONLY_BY_PROJECT_POLICY",
            "future_training_use_reviewed": False,
            "future_training_use_permitted": False,
            "weight_licence": "NONE",
            "security_evidence_precheck": "PASSED",
            "exact_revision_licence_verification": "REQUIRED_AFTER_INERT_ACQUISITION",
        }
        rights_precheck["precheck_id"] = stable_id("rights-precheck", rights_precheck)
        if rights_precheck["code_licence_allowlist_match"] is not True:
            raise PolicyError("RIGHTS_PRECHECK_REJECTED")
        decision = make_record(
            "acquisition-decision-v1",
            {
                "proposal_id": proposal["record_id"],
                "decision": "APPROVE",
                "from_state": "RIGHTS_PRECHECK_PASSED",
                "to_state": "ACQUISITION_APPROVED",
                "reviewer_role": catalog["reviewer_role"],
                "rights_precheck": "PASSED",
                "decided_before_fetch": True,
                "rationale": (
                    "Conditional approval for inert private evaluation acquisition only; "
                    "exact-revision licence and content admission remain fail-closed."
                ),
            },
        )
        dump_json(records / "proposal.json", proposal)
        dump_json(records / "rights-precheck.json", rights_precheck)
        dump_json(records / "acquisition-decision.json", decision)
        repository_index.append(
            {
                "private_token": token,
                "proposal_id": proposal["record_id"],
                "decision_id": decision["record_id"],
                "case_count": len(cases),
                "cases": cases,
                "proposed_split": repository["split"],
            }
        )
    preparation = {
        "schema_version": "lumi-trace-v0.3.1-intake-preparation-v1",
        "version": VERSION,
        "authority": "USER_APPROVED_V0_3_1_BUILD_BRIEF",
        "previous_public_evidence_seal": EXPECTED_V03_SEAL,
        "catalog_sha256": sha256_file(args.catalog),
        "repository_count": len(repository_index),
        "proposed_case_count": sum(item["case_count"] for item in repository_index),
        "proposals_and_decisions_precede_fetch": True,
        "training_authorised": False,
        "weights_acquired": False,
        "holdback_state": "FROZEN_UNOPENED",
        "repositories": repository_index,
        "private_retention_root": "GOVERNED_G_DRIVE_PRIVATE_STORE",
    }
    preparation["preparation_id"] = stable_id("v0.3.1-intake-preparation", preparation)
    dump_json(prepared / "preparation.json", preparation)
    manifest = seal_package(prepared)
    summary = {
        "prepared_package_id": manifest["package_id"],
        "repository_count": preparation["repository_count"],
        "proposed_case_count": preparation["proposed_case_count"],
        "private_repository_root_ready": (private_root / "repositories" / VERSION).parent.is_dir(),
    }
    return summary


def _git_environment(plan: dict[str, Any]) -> dict[str, str]:
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
    environment.update(plan["environment"])
    return environment


def _run(command: list[str], *, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        timeout=300,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise ContractError(f"inert Git command failed ({completed.returncode}): {error}")
    return completed.stdout


def _git(
    bare_repository: Path,
    arguments: list[str],
    *,
    environment: dict[str, str],
) -> bytes:
    return _run(
        ["git", f"--git-dir={bare_repository}", *arguments],
        environment=environment,
    )


def _commit_identity(
    bare_repository: Path, revision: str, *, environment: dict[str, str]
) -> tuple[str, str, str]:
    resolved = (
        _git(
            bare_repository,
            ["rev-parse", "--verify", f"{revision}^{{commit}}"],
            environment=environment,
        )
        .decode()
        .strip()
    )
    if resolved != revision:
        raise PolicyError("IMMUTABLE_REVISION_MISMATCH")
    lines = (
        _git(
            bare_repository,
            ["show", "-s", "--format=%T%n%P", revision],
            environment=environment,
        )
        .decode()
        .splitlines()
    )
    if len(lines) < 2 or not lines[1].split():
        raise PolicyError("SECURITY_FIX_HAS_NO_VULNERABLE_PARENT")
    return resolved, lines[0], lines[1].split()[0]


def _tree_entries(
    bare_repository: Path, revision: str, *, environment: dict[str, str]
) -> list[TreeEntry]:
    raw = _git(
        bare_repository,
        ["-c", "core.quotepath=false", "ls-tree", "-rlz", "--full-tree", revision],
        environment=environment,
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


def _materialise(
    bare_repository: Path,
    revision: str,
    destination: Path,
    *,
    environment: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if destination.exists():
        raise ValueError(f"refusing to overwrite snapshot: {destination.name}")
    scan = scan_tree_entries(
        _tree_entries(bare_repository, revision, environment=environment),
        limits=AcquisitionLimits(),
    )
    destination.mkdir(parents=True)
    entries: list[TreeEntry] = scan["regular_entries"]
    process = subprocess.Popen(
        ["git", f"--git-dir={bare_repository}", "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdin is not None and process.stdout is not None
    for entry in entries:
        process.stdin.write(f"{entry.object_id}\n".encode("ascii"))
        process.stdin.flush()
        header = process.stdout.readline().decode("ascii").rstrip("\n")
        fields = header.split()
        if (
            len(fields) != 3
            or fields[0] != entry.object_id
            or fields[1] != "blob"
            or int(fields[2]) != entry.size_bytes
        ):
            raise ContractError("Git batch blob identity mismatch")
        target = destination.joinpath(*entry.path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        remaining = int(entry.size_bytes or 0)
        with target.open("wb") as output:
            while remaining:
                block = process.stdout.read(min(1024 * 1024, remaining))
                if not block:
                    raise ContractError("Git blob ended before its declared size")
                output.write(block)
                remaining -= len(block)
        if process.stdout.read(1) != b"\n":
            raise ContractError("Git batch blob framing mismatch")
        target.chmod(0o644)
    process.stdin.close()
    process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    return_code = process.wait(timeout=300)
    if return_code != 0:
        raise ContractError(
            f"Git batch materialisation failed: {stderr.decode(errors='replace')[-1000:]}"
        )
    identity = compute_repository_identity(destination)
    public_scan = {
        "regular_file_count": scan["regular_file_count"],
        "total_bytes": scan["total_bytes"],
        "inert_gitlinks": scan["inert_gitlinks"],
        "inert_symlinks": scan["inert_symlinks"],
        "special_files": 0,
    }
    return identity, public_scan


def _licence_file(snapshot: Path) -> tuple[Path, str, str]:
    candidates = [
        path
        for path in snapshot.iterdir()
        if path.is_file()
        and path.name.casefold().split(".", 1)[0] in {"license", "licence", "copying"}
        and path.stat().st_size <= 256 * 1024
    ]
    detected: list[tuple[Path, str, str]] = []
    for path in sorted(candidates, key=lambda item: item.name.casefold()):
        try:
            text = path.read_text(encoding="utf-8")
            identifier = detect_code_licence(text)
        except (UnicodeError, PolicyError):
            continue
        detected.append((path, text, identifier))
    identifiers = {item[2] for item in detected}
    if len(identifiers) != 1 or not detected:
        raise PolicyError("MISSING_OR_AMBIGUOUS_CODE_LICENCE")
    path, text, identifier = detected[0]
    return path, text, identifier


def _transport_hashes(bare_repository: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted((bare_repository / "objects" / "pack").glob("*")):
        if path.is_file() and path.suffix in {".pack", ".idx", ".rev"}:
            artifacts.append(
                {
                    "kind": path.suffix.removeprefix(".").upper(),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    if not artifacts:
        raise ContractError("inert acquisition retained no transport pack")
    return artifacts


def acquire(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_governed_root(args.active_root, "F:")
    private_root = _require_governed_root(args.private_root, "G:")
    catalog = _load_catalog(args.catalog)
    prepared = active_root / "intake" / VERSION / "prepared"
    verify_package(prepared)
    acquired = private_root / "repositories" / VERSION
    receipts_root = active_root / "intake" / VERSION / "acquired"
    if (receipts_root / "manifest.json").exists():
        raise ValueError("refusing to overwrite sealed acquired V0.3.1 intake receipts")
    acquired.mkdir(parents=True, exist_ok=True)
    receipts_root.mkdir(parents=True, exist_ok=True)
    preparation = load_json(prepared / "preparation.json")
    by_token = {item["private_token"]: item for item in preparation["repositories"]}
    results: list[dict[str, Any]] = []
    for repository in catalog["repositories"]:
        slug = repository["slug"]
        token = _safe_token("natural-repository", slug)
        completed_record = receipts_root / "repositories" / token / "acquired-repository.json"
        if completed_record.is_file():
            completed = load_json(completed_record)
            if completed.get("private_token") != token:
                raise ContractError("resumed acquisition repository identity mismatch")
            results.append(completed)
            continue
        prepared_records = prepared / "repositories" / token
        proposal = load_json(prepared_records / "proposal.json")
        decision = load_json(prepared_records / "acquisition-decision.json")
        bare_repository = acquired / token / "objects.git"
        control_root = active_root / "intake" / VERSION / "controls" / token
        hooks = control_root / "empty-hooks"
        config = control_root / "isolated-config"
        hooks.mkdir(parents=True, exist_ok=True)
        config.mkdir(parents=True, exist_ok=True)
        (config / "empty.gitconfig").write_text("", encoding="utf-8")
        plan = acquisition_plan(
            proposal,
            decision,
            bare_repository=str(bare_repository),
            empty_hooks_directory=str(hooks),
            isolated_config_root=str(config),
        )
        environment = _git_environment(plan)
        if not bare_repository.exists():
            for command in plan["commands"]:
                _run(command, environment=environment)
        transport = _transport_hashes(bare_repository)
        case_results: list[dict[str, Any]] = []
        for case in repository["cases"]:
            fix, fix_tree_object, parent = _commit_identity(
                bare_repository, case["fix"], environment=environment
            )
            case_token = _safe_token("natural-case", case["ghsa"])
            case_root = acquired / token / "snapshots" / case_token
            fixed_identity, fixed_scan = _materialise(
                bare_repository,
                fix,
                case_root / "fixed",
                environment=environment,
            )
            vulnerable_identity, vulnerable_scan = _materialise(
                bare_repository,
                parent,
                case_root / "vulnerable",
                environment=environment,
            )
            fixed_licence_path, fixed_licence_text, fixed_licence = _licence_file(
                case_root / "fixed"
            )
            vulnerable_licence_path, vulnerable_licence_text, vulnerable_licence = _licence_file(
                case_root / "vulnerable"
            )
            for revision, path, text, identifier in (
                (fix, fixed_licence_path, fixed_licence_text, fixed_licence),
                (
                    parent,
                    vulnerable_licence_path,
                    vulnerable_licence_text,
                    vulnerable_licence,
                ),
            ):
                if identifier != repository["licence"]:
                    raise PolicyError("EXACT_REVISION_LICENCE_PRECHECK_MISMATCH")
                verify_licence_evidence(
                    text=text,
                    exact_revision=revision,
                    expected_revision=revision,
                    expected_identifier=repository["licence"],
                    expected_file_hash=sha256_file(path),
                )
            lineage_id = f"lineage:{token}"
            family_id = f"family:{token}"
            receipt = make_record(
                "acquisition-receipt-v1",
                {
                    "proposal_id": proposal["record_id"],
                    "decision_id": decision["record_id"],
                    "canonical_upstream_url": proposal["payload"]["canonical_upstream_url"],
                    "requested_revision": case["fix"],
                    "resolved_revision": fix,
                    "commit_object_hash": fix,
                    "tree_object_hash": fix_tree_object,
                    "transport": "GIT_SMART_HTTPS_INERT_BARE_FETCH",
                    "transport_hashes": [item["sha256"] for item in transport],
                    "snapshot_tree_id": fixed_identity["manifest_id"],
                    "licence_file_hash": sha256_file(fixed_licence_path),
                    "lineage_id": lineage_id,
                    "family_id": family_id,
                    "state": "ACQUIRED_UNADMITTED",
                    "retention_location": "GOVERNED_G_DRIVE_PRIVATE_STORE",
                    "safety_controls": {
                        "hooks_disabled": True,
                        "submodule_recursion_disabled": True,
                        "lfs_smudge_disabled": True,
                        "remote_includes_disabled": True,
                        "checkout_filters_disabled": True,
                        "build_or_setup_execution": False,
                    },
                    "scan": {
                        "fixed": fixed_scan,
                        "vulnerable": vulnerable_scan,
                    },
                    "repository_code_executed": False,
                },
            )
            verify_acquisition_receipt(receipt, proposal=proposal, decision=decision)
            case_receipts = receipts_root / "repositories" / token / "cases" / case_token
            dump_json(case_receipts / "acquisition-receipt.json", receipt)
            licence_evidence = {
                "schema_version": "lumi-trace-exact-licence-evidence-v1",
                "case_token": case_token,
                "expected_identifier": repository["licence"],
                "fixed_revision": fix,
                "fixed_path": fixed_licence_path.relative_to(case_root / "fixed").as_posix(),
                "fixed_sha256": sha256_file(fixed_licence_path),
                "vulnerable_revision": parent,
                "vulnerable_path": vulnerable_licence_path.relative_to(
                    case_root / "vulnerable"
                ).as_posix(),
                "vulnerable_sha256": sha256_file(vulnerable_licence_path),
                "identifier_agreement": fixed_licence == vulnerable_licence,
            }
            licence_evidence["licence_evidence_id"] = stable_id(
                "exact-licence-evidence", licence_evidence
            )
            dump_json(case_receipts / "licence-evidence.json", licence_evidence)
            identities = {
                "schema_version": "lumi-trace-revision-identities-v1",
                "case_token": case_token,
                "fix_revision": fix,
                "parent_revision": parent,
                "fix_tree_object": fix_tree_object,
                "fixed_snapshot": fixed_identity,
                "vulnerable_snapshot": vulnerable_identity,
            }
            identities["revision_identities_id"] = stable_id("revision-identities", identities)
            dump_json(case_receipts / "revision-identities.json", identities)
            case_results.append(
                {
                    "case_token": case_token,
                    "receipt_id": receipt["record_id"],
                    "fix_revision": fix,
                    "vulnerable_revision": parent,
                    "fixed_tree_id": fixed_identity["manifest_id"],
                    "vulnerable_tree_id": vulnerable_identity["manifest_id"],
                }
            )
        result = {
            "private_token": token,
            "proposal_id": proposal["record_id"],
            "decision_id": decision["record_id"],
            "split": by_token[token]["proposed_split"],
            "licence": repository["licence"],
            "transport_artifacts": transport,
            "cases": case_results,
            "repository_code_executed": False,
        }
        result["acquired_repository_id"] = stable_id("acquired-natural-repository", result)
        dump_json(receipts_root / "repositories" / token / "acquired-repository.json", result)
        results.append(result)
    acquisition = {
        "schema_version": "lumi-trace-v0.3.1-acquisition-summary-v1",
        "prepared_package_id": verify_package(prepared)["package_id"],
        "repository_count": len(results),
        "case_count": sum(len(item["cases"]) for item in results),
        "repository_code_executed": False,
        "submodules_acquired": False,
        "lfs_objects_acquired": False,
        "holdback_opened": False,
        "training_started": False,
        "repositories": results,
    }
    acquisition["acquisition_summary_id"] = stable_id("v0.3.1-acquisition", acquisition)
    dump_json(receipts_root / "acquisition-summary.json", acquisition)
    manifest = seal_package(receipts_root)
    return {
        "acquired_package_id": manifest["package_id"],
        "repository_count": acquisition["repository_count"],
        "case_count": acquisition["case_count"],
        "repository_code_executed": False,
    }


def _changed_paths(
    bare_repository: Path,
    parent: str,
    fix: str,
    *,
    environment: dict[str, str],
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
        environment=environment,
    )
    paths = [item.decode("utf-8", errors="strict") for item in raw.split(b"\x00") if item]
    for path in paths:
        scan_tree_entries(
            [TreeEntry("100644", "blob", "0" * 40, path, 0)],
            limits=AcquisitionLimits(maximum_files=1, maximum_total_bytes=1),
        )
    return paths


def _is_python_production(path: str) -> bool:
    parts = [part.casefold() for part in path.split("/")]
    return path.casefold().endswith(".py") and not any(
        part in _NON_PRODUCTION_PARTS or part.startswith("test_") or part.endswith("_test.py")
        for part in parts
    )


def _is_python_harness(path: str) -> bool:
    parts = [part.casefold() for part in path.split("/")]
    return path.casefold().endswith(".py") and any(
        part in {"test", "testing", "tests"} or part.startswith("test_") for part in parts
    )


def _diff_old_regions(
    bare_repository: Path,
    parent: str,
    fix: str,
    path: str,
    *,
    environment: dict[str, str],
) -> tuple[list[dict[str, int]], bytes]:
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
        environment=environment,
    )
    regions: list[dict[str, int]] = []
    for line in patch.decode("utf-8", errors="replace").splitlines():
        match = _DIFF_HUNK.match(line)
        if match is None:
            continue
        start = int(match.group("start"))
        count = int(match.group("count") or "1")
        if count:
            regions.append({"start_line": start, "end_line": start + count - 1})
        else:
            insertion_site = max(1, start)
            regions.append({"start_line": insertion_site, "end_line": insertion_site})
    return regions, patch


def _enclosing_symbol(path: Path, line: int) -> tuple[str | None, dict[str, int] | None]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError):
        return None, None
    matches: list[tuple[int, str, int, int]] = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        name = getattr(node, "name", None)
        qualified = (*parents, name) if isinstance(name, str) else parents
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            start = int(getattr(node, "lineno", 0))
            end = int(getattr(node, "end_lineno", start))
            if start <= line <= end:
                matches.append((end - start, ".".join(qualified), start, end))
        for child in ast.iter_child_nodes(node):
            visit(child, qualified)

    visit(tree, ())
    if not matches:
        return None, None
    _, symbol, start, end = min(matches)
    return symbol, {"start_line": start, "end_line": end}


def _construct_case_locations(
    *,
    bare_repository: Path,
    vulnerable_revision: str,
    fixed_revision: str,
    vulnerable_snapshot: Path,
    environment: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bytes, str]:
    paths = _changed_paths(
        bare_repository,
        vulnerable_revision,
        fixed_revision,
        environment=environment,
    )
    target_paths = [path for path in paths if _is_python_production(path)]
    harness_paths = [path for path in paths if _is_python_harness(path)]
    targets: list[dict[str, Any]] = []
    patches: list[bytes] = []
    for path in target_paths:
        regions, patch = _diff_old_regions(
            bare_repository,
            vulnerable_revision,
            fixed_revision,
            path,
            environment=environment,
        )
        patches.append(patch)
        if not regions or not (vulnerable_snapshot / path).is_file():
            continue
        symbol_rows = [
            (
                region,
                *_enclosing_symbol(vulnerable_snapshot / path, region["start_line"]),
            )
            for region in regions
        ]
        region, symbol, symbol_region = next(
            (row for row in symbol_rows if row[1] is not None),
            symbol_rows[0],
        )
        target: dict[str, Any] = {
            "path": path,
            "role": "VULNERABLE_IMPLEMENTATION",
            "region": region,
        }
        if symbol is not None:
            target["symbol"] = symbol
            if symbol_region is not None:
                target["symbol_region"] = symbol_region
        targets.append(target)
    hard_negatives = [
        {
            "path": path,
            "role": "HARNESS",
            "family": "NATURAL_SECURITY_TEST_OR_REPRODUCTION_HARNESS",
        }
        for path in harness_paths[:5]
    ]
    ambiguity = (
        "RESOLVED"
        if 1 <= len(targets) <= 8
        else "UNRESOLVED_NO_TARGET"
        if not targets
        else "UNRESOLVED_TOO_MANY_TARGETS"
    )
    return targets, hard_negatives, b"\n".join(patches), ambiguity


def _fingerprints(snapshot: Path) -> list[str]:
    paths = sorted(
        (
            path
            for path in snapshot.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.suffix.casefold() in {".py", ".c", ".h", ".js", ".ts"}
        ),
        key=lambda path: path.relative_to(snapshot).as_posix().encode("utf-8"),
    )
    return sorted({sha256_file(path) for path in paths[:2048]})


def _repository_size_band(identity: dict[str, Any]) -> str:
    files = int(identity["file_count"])
    if files < 500:
        return "SMALL"
    if files < 5_000:
        return "MEDIUM"
    return "LARGE"


def _manual_finding(
    *,
    case_token: str,
    advisory: dict[str, Any],
    cve: str,
    cwes: list[str],
) -> dict[str, Any]:
    summary = str(advisory.get("summary", "")).strip()
    details = str(advisory.get("details", "")).strip()
    description = details.splitlines()[0].strip() if details else summary
    if not summary or not description:
        raise PolicyError("FINDING_EVIDENCE_INSUFFICIENT")
    keywords = sorted(
        {
            word.casefold()
            for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", f"{summary} {description}")
            if word.casefold()
            not in {"this", "that", "with", "from", "when", "where", "which", "vulnerability"}
        }
    )[:16]
    return {
        "schema_version": "manual-finding-v1",
        "id": f"NATURAL-{case_token.upper()}",
        "title": summary[:300],
        "description": description[:2_000],
        "severity": "unknown",
        "rule": {
            "id": cve,
            "name": summary[:200],
            "cwes": cwes,
            "tags": ["public-security-advisory", "natural-corpus"],
        },
        "keywords": keywords,
        "fingerprints": {"public-advisory/v1": sha256_bytes(case_token.encode())},
    }


def _location_for_label_set(target: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"path": target["path"]}
    if "region" in target:
        result["kind"] = "region"
        result["region"] = target["region"]
    elif "symbol" in target:
        result["kind"] = "symbol"
        result["symbol"] = target["symbol"]
    else:
        result["kind"] = "file"
    return result


def _rights_record(
    *,
    identity: dict[str, Any],
    family_id: str,
    lineage_id: str,
    split: str,
    governed_location: str,
    licence: str,
    licence_hash: str,
    receipt_id: str,
    fingerprints: list[str],
) -> dict[str, Any]:
    exposure = "DEVELOPMENT_VISIBLE" if split == "development" else "EVALUATOR_ONLY"
    return make_record(
        "repository-rights-manifest-v1",
        {
            "repository_id": identity["repository_id"],
            "tree_id": identity["manifest_id"],
            "source": "PUBLIC_UPSTREAM_IMMUTABLE_REVISION_PRIVATE_EVALUATION",
            "acquisition_method": "APPROVED_INERT_GIT_OBJECT_ACQUISITION",
            "licence": licence,
            "rights_basis": "EXACT_REVISION_PERMISSIVE_CODE_LICENCE",
            "redistribution_status": "PRIVATE_EVALUATION_ONLY",
            "review_status": "CONTROLLED_REVIEWED",
            "lineage_id": lineage_id,
            "family_id": family_id,
            "shared_history_root": lineage_id,
            "exposure_state": exposure,
            "governed_location": governed_location,
            "input_hashes": [identity["manifest_id"], licence_hash],
            "content_fingerprints": fingerprints,
            "acquisition_receipt_id": receipt_id,
            "future_training_use_permitted": False,
        },
    )


def _group_and_labels(
    *,
    group_token: str,
    repository_rights: dict[str, Any],
    split: str,
    finding_relative: str,
    finding_hash: str,
    repository_relative: str,
    targets: list[dict[str, Any]],
    hard_negatives: list[dict[str, Any]],
    safe_control: bool,
    family_id: str,
    cwe: str,
    size_band: str,
    construction_inputs: list[str],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    group_id = f"natural-group:{group_token}"
    label_set_id = f"natural-label-set:{group_token}"
    construction = make_record(
        "controlled-review-receipt-v1",
        {
            "role": "LABEL_CONSTRUCTION_BLIND_PASS",
            "method": (
                "Authoritative fixing-diff old-line and syntax-tree inspection without "
                "Lumi Trace candidate output"
            ),
            "input_hashes": construction_inputs,
            "decision": "TARGETS_CONSTRUCTED" if not safe_control else "SAFE_PAIR_CONSTRUCTED",
            "disagreements": [],
            "corrections": [],
        },
    )
    review = make_record(
        "controlled-review-receipt-v1",
        {
            "role": "CONTROLLED_REVIEW_BLIND_PASS",
            "method": (
                "Separate rule-bound review of evidence, role, pair identity, and "
                "no-plan disposition before baseline execution"
            ),
            "input_hashes": [construction["record_id"], *construction_inputs],
            "decision": "ACCEPTED_NATURAL_GROUP",
            "disagreements": [],
            "corrections": [],
        },
    )
    label_state = "ACCEPTED_WITH_MULTIPLE_TARGETS" if len(targets) > 1 else "ACCEPTED"
    location_label = make_record(
        "trace-code-location-label-v1",
        {
            "group_id": group_id,
            "label_state": label_state,
            "repository_id": repository_rights["payload"]["repository_id"],
            "repository_family": family_id,
            "expected_disposition": "INSUFFICIENT_EVIDENCE",
            "targets": targets,
            "primary_role": "VULNERABLE_IMPLEMENTATION",
            "hard_negatives": hard_negatives,
            "safe_control": safe_control,
            "review_receipt_ids": [construction["record_id"], review["record_id"]],
            "corrections": [],
            "constructed_without_runner_output": True,
        },
    )
    label_set = make_record(
        "label-set-v1",
        {
            "label_set_id": label_set_id,
            "group_id": group_id,
            "targets": [_location_for_label_set(target) for target in targets],
            "matching_rule": "FIRST_ACCEPTED_EXACT_KIND_WITH_ANY_LINE_OVERLAP",
            "review_receipt_ids": [construction["record_id"], review["record_id"]],
            "corrections": [],
            "hard_negative_paths": [item["path"] for item in hard_negatives],
            "reproduction": {
                "expected_outcome": "INSUFFICIENT_EVIDENCE",
                "plan_state": "INTENTIONALLY_ABSENT",
            },
        },
    )
    group = make_record(
        "candidate-ranking-group-v1",
        {
            "group_id": group_id,
            "repository_id": repository_rights["payload"]["repository_id"],
            "finding_id": stable_id("natural-finding-input", {"sha256": finding_hash}),
            "rights_id": repository_rights["record_id"],
            "split": split,
            "case_class": "NATURAL_PRIMARY",
            "origin": "natural",
            "taxonomy": {
                "cwe": cwe,
                "difficulty": "NATURAL_PILOT",
                "finding_format": "manual",
                "language": "Python",
                "origin": "natural",
                "repository_size_band": size_band,
                "target_kind": "WITHHELD_FROM_RUNNER",
            },
            "runner_inputs": {
                "finding": finding_relative,
                "finding_format": "manual",
                "repository": repository_relative,
            },
            "label_set_id": label_set_id,
            "repository_tree_id": repository_rights["payload"]["tree_id"],
            "exposure_state": repository_rights["payload"]["exposure_state"],
            "input_hashes": [repository_rights["payload"]["tree_id"], finding_hash],
        },
    )
    natural_review = make_record(
        "natural-group-review-v1",
        {
            "group_id": group_id,
            "label_id": location_label["record_id"],
            "reviewer_role": "CONTROLLED_INTERNAL_LABEL_REVIEW",
            "security_evidence_verified": True,
            "licence_revision_verified": True,
            "roles_verified": True,
            "ambiguity_state": "RESOLVED",
            "ranking_output_available": False,
            "fixing_diff_available": not safe_control,
            "decision": "ACCEPT",
            "corrections": [],
        },
    )
    cue_profile = make_record(
        "finding-cue-profile-v1",
        {
            "group_id": group_id,
            "finding_id": group["payload"]["finding_id"],
            "available_cues": ["ADVISORY_TITLE", "ADVISORY_DESCRIPTION", "CWE", "KEYWORDS"],
            "withheld_cues": [
                "FIXING_DIFF",
                "ACCEPTED_TARGETS",
                "SAFE_OR_VULNERABLE_STATE",
                "REVISION_ROLE",
            ],
            "fixing_diff_in_runner_input": False,
            "label_fields_in_runner_input": False,
            "ablation_of_group_id": None,
            "counts_toward_natural_total": True,
        },
    )
    validate_group_review(natural_review)
    validate_finding_cue_profile(cue_profile)
    return group, label_set, location_label, construction, review, natural_review, cue_profile


def construct(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_governed_root(args.active_root, "F:")
    private_root = _require_governed_root(args.private_root, "G:")
    catalog = _load_catalog(args.catalog)
    acquired_root = active_root / "intake" / VERSION / "acquired"
    verify_package(acquired_root)
    acquisition = load_json(acquired_root / "acquisition-summary.json")
    corpus_root = private_root / "manifests" / VERSION / "corpus"
    runner_root = private_root / "artifacts" / VERSION / "runner-inputs"
    if corpus_root.exists() or runner_root.exists():
        raise ValueError("refusing to overwrite V0.3.1 corpus construction")
    corpus_root.mkdir(parents=True)
    runner_root.mkdir(parents=True)
    acquired_by_token = {item["private_token"]: item for item in acquisition["repositories"]}
    repository_rights: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    label_sets: list[dict[str, Any]] = []
    location_labels: list[dict[str, Any]] = []
    review_records: list[dict[str, Any]] = []
    cue_profiles: list[dict[str, Any]] = []
    rights_dimensions: list[dict[str, Any]] = []
    revision_pairs: list[dict[str, Any]] = []
    rejection_rows: list[dict[str, str]] = []
    split_assignments: dict[str, str] = {}
    accepted_case_count = 0
    for repository in catalog["repositories"]:
        slug = repository["slug"]
        token = _safe_token("natural-repository", slug)
        acquired_repository = acquired_by_token[token]
        bare_repository = private_root / "repositories" / VERSION / token / "objects.git"
        prepared_records = active_root / "intake" / VERSION / "prepared" / "repositories" / token
        proposal = load_json(prepared_records / "proposal.json")
        plan = acquisition_plan(
            proposal,
            load_json(prepared_records / "acquisition-decision.json"),
            bare_repository=str(bare_repository),
            empty_hooks_directory=str(
                active_root / "intake" / VERSION / "controls" / token / "empty-hooks"
            ),
            isolated_config_root=str(
                active_root / "intake" / VERSION / "controls" / token / "isolated-config"
            ),
        )
        environment = _git_environment(plan)
        cases_by_token = {item["case_token"]: item for item in acquired_repository["cases"]}
        family_id = f"family:{token}"
        lineage_id = f"lineage:{token}"
        for case in repository["cases"]:
            case_token = _safe_token("natural-case", case["ghsa"])
            acquired_case = cases_by_token[case_token]
            snapshot_root = (
                private_root / "repositories" / VERSION / token / "snapshots" / case_token
            )
            targets, hard_negatives, patch, ambiguity = _construct_case_locations(
                bare_repository=bare_repository,
                vulnerable_revision=acquired_case["vulnerable_revision"],
                fixed_revision=acquired_case["fix_revision"],
                vulnerable_snapshot=snapshot_root / "vulnerable",
                environment=environment,
            )
            patch_hash = sha256_bytes(patch)
            patch_path = corpus_root / "private-fixing-diffs" / f"{case_token}.patch"
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_bytes(patch)
            if ambiguity != "RESOLVED":
                rejection_rows.append(
                    {
                        "case_token": case_token,
                        "reason": ambiguity,
                        "evidence_hash": patch_hash,
                    }
                )
                continue
            advisory_path = next(
                (
                    path
                    for path in (prepared_records / "security-evidence").glob("*.json")
                    if load_json(path).get("id") == case["ghsa"]
                ),
                None,
            )
            if advisory_path is None:
                raise ContractError("prepared security evidence is missing")
            advisory = load_json(advisory_path)
            cwes = sorted(
                item
                for item in advisory.get("database_specific", {}).get("cwe_ids", [])
                if isinstance(item, str) and item.startswith("CWE-")
            ) or ["CWE-UNKNOWN"]
            finding = _manual_finding(
                case_token=case_token,
                advisory=advisory,
                cve=case["cve"],
                cwes=cwes,
            )
            finding_relative = f"findings/{case_token}.json"
            finding_path = runner_root / finding_relative
            dump_json(finding_path, finding)
            finding_hash = sha256_file(finding_path)
            case_receipts = acquired_root / "repositories" / token / "cases" / case_token
            receipt = load_json(case_receipts / "acquisition-receipt.json")
            licence = load_json(case_receipts / "licence-evidence.json")
            revision_identity = load_json(case_receipts / "revision-identities.json")
            revision_pair = make_record(
                "revision-pair-v1",
                {
                    "pair_id": f"revision-pair:{case_token}",
                    "repository_id": f"natural-repository:{token}",
                    "vulnerability_lineage_id": f"vulnerability-lineage:{case_token}",
                    "security_evidence_ids": [f"public-advisory:{case['ghsa']}"],
                    "vulnerable_revision": acquired_case["vulnerable_revision"],
                    "fixed_revision": acquired_case["fix_revision"],
                    "vulnerable_tree_id": acquired_case["vulnerable_tree_id"],
                    "fixed_tree_id": acquired_case["fixed_tree_id"],
                    "label_construction_state": "CONTROLLED_REVIEW_ACCEPTED",
                },
            )
            revision_pairs.append(revision_pair)
            state_rows = (
                (
                    "vulnerable",
                    revision_identity["vulnerable_snapshot"],
                    licence["vulnerable_sha256"],
                    targets,
                    hard_negatives,
                    False,
                ),
                (
                    "fixed",
                    revision_identity["fixed_snapshot"],
                    licence["fixed_sha256"],
                    [],
                    hard_negatives,
                    True,
                ),
            )
            for (
                state,
                identity,
                licence_hash,
                state_targets,
                state_negatives,
                safe_control,
            ) in state_rows:
                group_token = _safe_token("natural-group", f"{case['ghsa']}:{state}")
                repository_relative = f"repositories/{group_token}"
                runner_snapshot = runner_root / repository_relative
                shutil.copytree(snapshot_root / state, runner_snapshot)
                rights = _rights_record(
                    identity=identity,
                    family_id=family_id,
                    lineage_id=lineage_id,
                    split=repository["split"],
                    governed_location=repository_relative,
                    licence=repository["licence"],
                    licence_hash=licence_hash,
                    receipt_id=receipt["record_id"],
                    fingerprints=_fingerprints(runner_snapshot),
                )
                repository_rights.append(rights)
                split_assignments[rights["payload"]["repository_id"]] = repository["split"]
                rights_dimension = make_record(
                    "rights-dimensions-v1",
                    {
                        "proposal_id": proposal["record_id"],
                        "exact_revision": acquired_case[
                            "vulnerable_revision" if state == "vulnerable" else "fix_revision"
                        ],
                        "licence_identifier": repository["licence"],
                        "licence_file_hash": licence_hash,
                        "source_access": "PUBLIC_READ",
                        "private_evaluation": "PERMITTED",
                        "source_redistribution": "PRIVATE_ONLY_BY_PROJECT_POLICY",
                        "finding_use": "PERMITTED_WITH_ATTRIBUTION",
                        "label_use": "PRIVATE_EVALUATION_ONLY",
                        "future_training_use_reviewed": False,
                        "future_training_use_permitted": False,
                        "weight_licence": "NONE",
                        "review_status": "APPROVED_FOR_PRIVATE_EVALUATION",
                    },
                )
                validate_rights_dimensions(rights_dimension)
                rights_dimensions.append(rights_dimension)
                records = _group_and_labels(
                    group_token=group_token,
                    repository_rights=rights,
                    split=repository["split"],
                    finding_relative=finding_relative,
                    finding_hash=finding_hash,
                    repository_relative=repository_relative,
                    targets=state_targets,
                    hard_negatives=state_negatives,
                    safe_control=safe_control,
                    family_id=family_id,
                    cwe=cwes[0],
                    size_band=_repository_size_band(identity),
                    construction_inputs=[
                        acquired_case[
                            "vulnerable_tree_id" if state == "vulnerable" else "fixed_tree_id"
                        ],
                        patch_hash,
                        receipt["record_id"],
                    ],
                )
                group, label_set, location_label, construction, review, natural_review, cue = (
                    records
                )
                groups.append(group)
                label_sets.append(label_set)
                location_labels.append(location_label)
                review_records.extend([construction, review, natural_review])
                cue_profiles.append(cue)
            accepted_case_count += 1
    if not groups:
        raise PolicyError("NATURAL_CORPUS_HAS_NO_ACCEPTED_GROUPS")
    audit_revision_pairs(revision_pairs)
    partitions: dict[str, list[str]] = {
        "public_regression": [],
        "construction": [],
        "future_training_candidate": [],
        "development": [],
        "qualification": [],
        "frozen_holdback": [],
    }
    for repository_id, split in sorted(split_assignments.items()):
        partitions[split].append(repository_id)
    split_manifest = make_record(
        "split-manifest-v1",
        {
            "partitions": partitions,
            "repositories": dict(sorted(split_assignments.items())),
            "locked": True,
            "independence_method": (
                "upstream family, lineage, shared history, tree identity, and "
                "content-fingerprint audit before baseline execution"
            ),
        },
    )
    audit = audit_repository_independence(repository_rights, split_manifest)
    registry_snapshot = make_record(
        "registry-snapshot-v1",
        {
            "repositories": [item["record_id"] for item in repository_rights],
            "groups": [item["record_id"] for item in groups],
            "split_manifest_id": split_manifest["record_id"],
            "exposure_log_ids": [],
        },
    )
    runner_registry = write_registry(
        corpus_root / "runner-registry.json",
        [*repository_rights, split_manifest, registry_snapshot, *groups],
    )
    labels_registry = write_registry(
        corpus_root / "labels-evaluator-only.json",
        [*label_sets, *location_labels, *review_records, *cue_profiles],
    )
    natural_registry, lineage_audit = assess_natural_corpus(
        repositories=repository_rights,
        labels=location_labels,
        split_manifest=split_manifest,
        private_evidence_location="GOVERNED_G_DRIVE_PRIVATE_STORE",
    )
    distribution = make_record(
        "corpus-distribution-v1",
        {
            "accepted_groups": len(location_labels),
            "rejected_groups": len(rejection_rows) * 2,
            "repositories": natural_registry["payload"]["accepted_repository_count"],
            "partitions": {
                split: sum(group["payload"]["split"] == split for group in groups)
                for split in ("development", "qualification")
            },
            "state_counts": {
                "vulnerable_or_affected": sum(
                    not label["payload"]["safe_control"] for label in location_labels
                ),
                "fixed_safe_control": sum(
                    label["payload"]["safe_control"] for label in location_labels
                ),
            },
            "role_counts": dict(
                sorted(
                    Counter(
                        target["role"]
                        for label in location_labels
                        for target in label["payload"]["targets"]
                    ).items()
                )
            ),
            "language_counts": {"Python": len(location_labels)},
            "weakness_counts": dict(
                sorted(Counter(group["payload"]["taxonomy"]["cwe"] for group in groups).items())
            ),
            "evidence_strength_counts": {
                "AUTHORITATIVE_ADVISORY_PLUS_FIXING_DIFF": len(location_labels)
            },
            "safe_control_count": sum(
                label["payload"]["safe_control"] for label in location_labels
            ),
            "hard_negative_count": sum(
                bool(label["payload"]["hard_negatives"]) for label in location_labels
            ),
            "missing_strata": [
                "REPRODUCTION_WITNESS_LABELS",
                "NON_PYTHON_LANGUAGES",
            ],
        },
    )
    rights_dimensions = list({record["record_id"]: record for record in rights_dimensions}.values())
    write_registry(
        corpus_root / "governance-records.json",
        [
            *rights_dimensions,
            *revision_pairs,
            natural_registry,
            lineage_audit,
            distribution,
        ],
    )
    construction_summary = {
        "schema_version": "lumi-trace-v0.3.1-corpus-construction-summary-v1",
        "runner_registry_id": runner_registry["registry_id"],
        "labels_registry_id": labels_registry["registry_id"],
        "natural_registry_id": natural_registry["record_id"],
        "lineage_audit_id": lineage_audit["record_id"],
        "distribution_id": distribution["record_id"],
        "accepted_security_cases": accepted_case_count,
        "accepted_groups": len(location_labels),
        "rejected_security_cases": len(rejection_rows),
        "accepted_repository_families": natural_registry["payload"]["accepted_repository_count"],
        "sufficiency": natural_registry["payload"]["sufficiency"],
        "split_audit": audit,
        "runner_input_state_labels": False,
        "runner_input_fixing_diffs": False,
        "labels_evaluator_only": True,
        "construction_completed_before_runtime_output": True,
        "holdback_opened": False,
        "training_started": False,
        "rejections": rejection_rows,
    }
    construction_summary["construction_summary_id"] = stable_id(
        "v0.3.1-corpus-construction", construction_summary
    )
    dump_json(corpus_root / "construction-summary.json", construction_summary)
    manifest = seal_package(corpus_root)
    return {
        "corpus_package_id": manifest["package_id"],
        "runner_registry_id": runner_registry["registry_id"],
        "accepted_groups": len(location_labels),
        "accepted_repository_families": natural_registry["payload"]["accepted_repository_count"],
        "rejected_security_cases": len(rejection_rows),
        "sufficiency": natural_registry["payload"]["sufficiency"],
    }


def _configuration(mode: str, metric_spec_id: str) -> dict[str, Any]:
    return make_record(
        "evaluator-configuration-v1",
        {
            "runtime": {
                "artifact_sha256": EXPECTED_V01_WHEEL,
                "release": "v0.1.0",
                "release_commit": "04bee651f6347ec3b4b5d3a941029ef8f6bfc48d",
                "source_revision": "8f7c235333ab7e270d6dce320481ebb28960a212",
                "version": "0.1.0",
            },
            "mode": mode,
            "limits": {
                "case_disk_bytes": 134_217_728,
                "case_timeout_seconds": 180,
                "file_count": 100_000,
                "memory_bytes": 1_073_741_824,
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
    run_link = {
        "schema_version": "lumi-trace-v0.3.1-code-score-run-link-v1",
        "run_id": run_record["payload"]["run_id"],
        "raw_output_seal_id": run_record["payload"]["raw_output_seal_id"],
        "case_result_ids": [item["record_id"] for item in cases],
        "labels_applied_after_raw_seal": True,
    }
    run_link["run_link_id"] = stable_id("v0.3.1-code-score-run-link", run_link)
    dump_json(output / "run-link.json", run_link)
    manifest = seal_package(output)
    return {
        "aggregate": aggregate,
        "manifest": manifest,
        "run_record": run_record,
        "cases": cases,
    }


def _rate(metric: dict[str, Any]) -> float | None:
    value = metric.get("rate")
    return float(value) if isinstance(value, int | float) else None


def _development_threshold(
    aggregate: dict[str, Any],
    *,
    replay_record: dict[str, Any],
    all_attempts_completed: bool,
    integrity_floors: dict[str, int],
) -> tuple[bool, list[dict[str, Any]], str]:
    micro = aggregate["payload"]["micro"]
    checks = [
        {
            "metric": "file_recall_at_20",
            "observed": _rate(micro["file_recall"]["20"]),
            "operator": ">=",
            "threshold": 0.70,
        },
        {
            "metric": "target_indexability",
            "observed": _rate(micro["target_indexability"]),
            "operator": ">=",
            "threshold": 0.90,
        },
        {
            "metric": "false_supported_disposition",
            "observed": _rate(micro["false_supported_disposition"]["rate"]),
            "operator": "<=",
            "threshold": 0.0,
        },
        {
            "metric": "false_vulnerability_rate",
            "observed": _rate(micro["false_vulnerability_rate"]),
            "operator": "<=",
            "threshold": 0.0,
        },
        {
            "metric": "unsafe_non_abstention",
            "observed": _rate(micro["unsafe_non_abstention"]),
            "operator": "<=",
            "threshold": 0.0,
        },
        {
            "metric": "wrong_location_role_top_one",
            "observed": _rate(micro["wrong_location_role_top_one"]),
            "operator": "<=",
            "threshold": 0.25,
        },
        {
            "metric": "hard_negative_outrank",
            "observed": _rate(micro["hard_negative_outrank"]),
            "operator": "<=",
            "threshold": 0.25,
        },
    ]
    for check in checks:
        observed = check["observed"]
        check["passed"] = bool(
            observed is not None
            and (
                observed >= check["threshold"]
                if check["operator"] == ">="
                else observed <= check["threshold"]
            )
        )
    integrity_passed = (
        all(value == 0 for value in integrity_floors.values())
        and all_attempts_completed
        and replay_record["payload"]["semantic_agreement"] is True
        and replay_record["payload"]["identity_agreement"] is True
    )
    passed = integrity_passed and all(check["passed"] for check in checks)
    if not integrity_passed:
        remediation = "NOT_QUALIFIED / REMEDIATION_REQUIRED"
    elif _rate(micro["hard_negative_outrank"]) is None:
        remediation = "MORE_NATURAL_DATA_REQUIRED"
    elif not passed:
        remediation = "DETERMINISTIC_REMEDIATION_REQUIRED"
    else:
        remediation = "PROVISIONAL_THRESHOLDS_APPROVED"
    return passed, checks, remediation


def baseline(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_governed_root(args.active_root, "F:")
    private_root = _require_governed_root(args.private_root, "G:")
    v03 = verify_v03(ROOT / "evidence" / "v0.3.0")
    if v03["seal_id"] != EXPECTED_V03_SEAL:
        raise PolicyError("SEALED_V0_3_BASELINE_MISMATCH")
    if sha256_file(args.runtime_wheel) != EXPECTED_V01_WHEEL:
        raise PolicyError("UNCHANGED_V0_1_RUNTIME_ARTIFACT_MISMATCH")
    evaluator_hash = sha256_file(args.evaluator_wheel)
    corpus_root = private_root / "manifests" / VERSION / "corpus"
    verify_package(corpus_root)
    construction = load_json(corpus_root / "construction-summary.json")
    if construction["sufficiency"] != "PILOT_TARGET_MET":
        raise PolicyError("NATURAL_PILOT_PRECONDITIONS_NOT_MET")
    control_root = private_root / "manifests" / VERSION / "pre-run"
    if control_root.exists():
        raise ValueError("refusing to overwrite V0.3.1 pre-run seal")
    control_root.mkdir(parents=True)
    legacy_metric_spec = load_json(
        ROOT / "eval" / "public-fixtures" / "v0.2" / "metric-specification.json"
    )
    code_metric_spec = default_metric_specification()
    development_configuration = _configuration("development", legacy_metric_spec["record_id"])
    qualification_configuration = _configuration("qualification", legacy_metric_spec["record_id"])
    dump_json(control_root / "legacy-metric-specification.json", legacy_metric_spec)
    dump_json(control_root / "code-metric-specification.json", code_metric_spec)
    dump_json(control_root / "development-configuration.json", development_configuration)
    dump_json(control_root / "qualification-configuration.json", qualification_configuration)
    threshold_policy = {
        "schema_version": "lumi-trace-v0.3.1-predeclared-threshold-policy-v1",
        "file_recall_at_20_minimum": 0.70,
        "target_indexability_minimum": 0.90,
        "false_supported_maximum": 0.0,
        "false_vulnerability_maximum": 0.0,
        "unsafe_non_abstention_maximum": 0.0,
        "wrong_role_top_one_maximum": 0.25,
        "hard_negative_outrank_maximum": 0.25,
        "integrity_floors": {
            "protected_holdback_exposure": 0,
            "unauthorised_corpus_access": 0,
            "manifest_verification_failure": 0,
            "cross_split_lineage_overlap": 0,
            "retained_evidence_verification_failure": 0,
            "third_party_source_in_public_evidence": 0,
        },
        "qualification_policy": "ONE_RUN_ONLY_AFTER_ALL_DEVELOPMENT_GATES_PASS",
    }
    threshold_policy["threshold_policy_id"] = stable_id("v0.3.1-threshold-policy", threshold_policy)
    dump_json(control_root / "threshold-policy.json", threshold_policy)
    budget = make_record(
        "qualification-budget-v1",
        {
            "split_manifest_id": next(
                record["record_id"]
                for record in load_registry(corpus_root / "runner-registry.json")["records"]
                if record["schema_version"] == "split-manifest-v1"
            ),
            "maximum_runs": 1,
            "consumed_runs": 0,
            "state": "AVAILABLE_IF_PRECONDITIONS_PASS",
            "consumption_receipt_ids": [],
        },
    )
    dump_json(control_root / "qualification-budget.json", budget)
    sealed_hashes = [
        sha256_file(corpus_root / "manifest.json"),
        sha256_file(control_root / "legacy-metric-specification.json"),
        sha256_file(control_root / "code-metric-specification.json"),
        sha256_file(control_root / "development-configuration.json"),
        sha256_file(control_root / "qualification-configuration.json"),
        sha256_file(control_root / "threshold-policy.json"),
        sha256_file(control_root / "qualification-budget.json"),
        evaluator_hash,
        EXPECTED_V01_WHEEL,
    ]
    pre_run = make_record(
        "pre-run-seal-v1",
        {
            "runtime_id": "skylark-lumi-trace:0.1.0",
            "runtime_artifact_hash": EXPECTED_V01_WHEEL,
            "evaluator_id": f"skylark-lumi-trace-eval:0.3.1:{evaluator_hash}",
            "registry_id": construction["runner_registry_id"],
            "split_manifest_id": budget["payload"]["split_manifest_id"],
            "metric_spec_id": code_metric_spec["record_id"],
            "threshold_policy": threshold_policy,
            "runner_blindness_verified": True,
            "qualification_budget_id": budget["record_id"],
            "sealed_artifact_hashes": sorted(sealed_hashes),
            "sealed_before_execution": True,
        },
    )
    verify_pre_run_seal(pre_run, expected_runtime_hash=EXPECTED_V01_WHEEL)
    dump_json(control_root / "pre-run-seal.json", pre_run)
    control_manifest = seal_package(control_root)
    runner_source = private_root / "artifacts" / VERSION / "runner-inputs"
    run_root = active_root / "runs" / VERSION
    workspace = active_root / "workspace" / VERSION
    development = run_registry(
        registry_path=corpus_root / "runner-registry.json",
        configuration_path=control_root / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=runner_source,
        workspace_root=workspace,
        output=run_root / "development-raw",
    )
    legacy_scored = score_run(
        run_root=run_root / "development-raw",
        registry_path=corpus_root / "runner-registry.json",
        labels_path=corpus_root / "labels-evaluator-only.json",
        metric_spec_path=control_root / "legacy-metric-specification.json",
        output=run_root / "development-scored",
    )
    code_scored = _score_code_run(
        run_root=run_root / "development-raw",
        registry_path=corpus_root / "runner-registry.json",
        labels_path=corpus_root / "labels-evaluator-only.json",
        metric_spec=code_metric_spec,
        output=run_root / "development-code-scored",
    )
    replay = replay_run(
        original=run_root / "development-raw",
        registry=corpus_root / "runner-registry.json",
        configuration=control_root / "development-configuration.json",
        executable=args.runtime_executable,
        runtime_artifact=args.runtime_wheel,
        source_root=runner_source,
        workspace_root=workspace,
        output=run_root / "development-replay",
    )
    attempts = development["attempts"]
    integrity = dict(threshold_policy["integrity_floors"])
    passed, threshold_checks, remediation = _development_threshold(
        code_scored["aggregate"],
        replay_record=replay["record"],
        all_attempts_completed=all(
            attempt["payload"]["status"] == "COMPLETED" for attempt in attempts
        ),
        integrity_floors=integrity,
    )
    threshold_decision = make_record(
        "natural-threshold-decision-v1",
        {
            "development_run_id": development["run_record"]["payload"]["run_id"],
            "decision": "APPROVE" if passed else "DECLINE",
            "thresholds": threshold_checks,
            "integrity_floors": integrity,
            "remediation_class": remediation,
            "qualification_authorised": passed,
            "qualification_evidence_used": False,
            "decided_before_qualification": True,
        },
    )
    validate_threshold_decision(threshold_decision)
    decisions_root = private_root / "manifests" / VERSION / "decisions"
    decisions_root.mkdir(parents=True)
    dump_json(decisions_root / "development-threshold-decision.json", threshold_decision)
    qualification_result: dict[str, Any] | None = None
    qualification_code: dict[str, Any] | None = None
    budget_consumed = 0
    if passed:
        qualification_result = run_registry(
            registry_path=corpus_root / "runner-registry.json",
            configuration_path=control_root / "qualification-configuration.json",
            executable=args.runtime_executable,
            runtime_artifact=args.runtime_wheel,
            source_root=runner_source,
            workspace_root=workspace,
            output=run_root / "qualification-raw",
        )
        score_run(
            run_root=run_root / "qualification-raw",
            registry_path=corpus_root / "runner-registry.json",
            labels_path=corpus_root / "labels-evaluator-only.json",
            metric_spec_path=control_root / "legacy-metric-specification.json",
            output=run_root / "qualification-scored",
        )
        qualification_code = _score_code_run(
            run_root=run_root / "qualification-raw",
            registry_path=corpus_root / "runner-registry.json",
            labels_path=corpus_root / "labels-evaluator-only.json",
            metric_spec=code_metric_spec,
            output=run_root / "qualification-code-scored",
        )
        budget_consumed = 1
    if not passed:
        closure_state = remediation
    elif qualification_code is None:
        closure_state = "NOT_QUALIFIED / REMEDIATION_REQUIRED"
    else:
        qualification_micro = qualification_code["aggregate"]["payload"]["micro"]
        qualification_passed = (
            _rate(qualification_micro["file_recall"]["20"]) is not None
            and _rate(qualification_micro["file_recall"]["20"]) >= 0.70
            and _rate(qualification_micro["false_supported_disposition"]["rate"]) == 0.0
            and _rate(qualification_micro["unsafe_non_abstention"]) == 0.0
        )
        closure_state = (
            "NATURAL_PILOT_QUALIFIED / SCALE_CORPUS"
            if qualification_passed
            else "NOT_QUALIFIED / REMEDIATION_REQUIRED"
        )
    consumed_budget = make_record(
        "qualification-budget-v1",
        {
            "split_manifest_id": budget["payload"]["split_manifest_id"],
            "maximum_runs": 1,
            "consumed_runs": budget_consumed,
            "state": "CONSUMED" if budget_consumed else "UNUSED_PRECONDITIONS_FAILED",
            "consumption_receipt_ids": (
                [qualification_result["run_record"]["record_id"]]
                if qualification_result is not None
                else []
            ),
        },
    )
    closure = make_record(
        "v0.3.1-closure-v1",
        {
            "closure_state": closure_state,
            "natural_corpus_state": construction["sufficiency"],
            "development_run": True,
            "qualification_run": qualification_result is not None,
            "qualification_budget_consumed": budget_consumed,
            "holdback_opened": False,
            "trace_ir_state": "IR_FEASIBILITY_SUPPORTED_UNCHANGED",
            "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
            "training_started": False,
            "weights_acquired": False,
            "publication_decision": "NO_GO_PENDING_USER_REVIEW",
            "evidence_ids": [
                pre_run["record_id"],
                development["run_record"]["record_id"],
                code_scored["aggregate"]["record_id"],
                replay["record"]["record_id"],
                threshold_decision["record_id"],
            ],
        },
    )
    enforce_publication_decision(closure)
    dump_json(decisions_root / "qualification-budget-final.json", consumed_budget)
    dump_json(decisions_root / "v0.3.1-closure.json", closure)
    if qualification_code is not None:
        dump_json(
            decisions_root / "qualification-aggregate-copy.json",
            qualification_code["aggregate"],
        )
    dump_json(
        decisions_root / "development-aggregate-copy.json",
        code_scored["aggregate"],
    )
    decision_manifest = seal_package(decisions_root)
    return {
        "pre_run_package_id": control_manifest["package_id"],
        "development_run_id": development["run_record"]["payload"]["run_id"],
        "development_raw_package_id": development["manifest"]["package_id"],
        "development_scored_package_id": legacy_scored["manifest"]["package_id"],
        "development_code_package_id": code_scored["manifest"]["package_id"],
        "replay_identity_agreement": replay["record"]["payload"]["identity_agreement"],
        "threshold_decision": threshold_decision["payload"]["decision"],
        "qualification_run": qualification_result is not None,
        "qualification_budget_consumed": budget_consumed,
        "closure_state": closure_state,
        "decision_package_id": decision_manifest["package_id"],
        "publication_decision": "NO_GO_PENDING_USER_REVIEW",
        "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
    }


def status(args: argparse.Namespace) -> dict[str, Any]:
    active_root = _require_governed_root(args.active_root, "F:")
    private_root = _require_governed_root(args.private_root, "G:")
    locations = {
        "prepared": active_root / "intake" / VERSION / "prepared",
        "acquired": active_root / "intake" / VERSION / "acquired",
        "repositories": private_root / "repositories" / VERSION,
        "corpus": private_root / "manifests" / VERSION / "corpus",
        "pre_run": private_root / "manifests" / VERSION / "pre-run",
        "decisions": private_root / "manifests" / VERSION / "decisions",
    }
    return {
        "version": VERSION,
        "locations": {
            name: {
                "exists": path.exists(),
                "package_id": (
                    verify_package(path)["package_id"]
                    if path.is_dir() and (path / "manifest.json").is_file()
                    else None
                ),
            }
            for name, path in locations.items()
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/manifests/v0.3.1/intake-catalog.private.json"
        ),
    )
    parser.add_argument(
        "--active-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval"),
    )
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval"),
    )
    parser.add_argument(
        "--runtime-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/staging/"
            "skylark_lumi_trace-0.1.0-py3-none-any.whl"
        ),
    )
    parser.add_argument(
        "--runtime-executable",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/runtime/sut-v0.1.0/Scripts/lumi-trace.exe"),
    )
    parser.add_argument(
        "--evaluator-wheel",
        type=Path,
        default=Path(
            "G:/Data/skylark-lumi-trace-eval/artifacts/v0.3.1-build-k/"
            "skylark_lumi_trace_eval-0.3.1-py3-none-any.whl"
        ),
    )
    parser.add_argument("phase", choices=("prepare", "acquire", "construct", "baseline", "status"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = {
            "prepare": prepare,
            "acquire": acquire,
            "construct": construct,
            "baseline": baseline,
            "status": status,
        }[args.phase](args)
    except (OSError, ValueError, ContractError, PolicyError) as exc:
        print(f"build-v0.3.1-natural: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
