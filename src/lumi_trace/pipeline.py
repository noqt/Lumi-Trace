# SPDX-License-Identifier: Apache-2.0
"""End-to-end Lumi Trace runtime flow."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from . import __version__
from .canonical import canonical_sha256, dump_json, load_json, sha256_file, stable_id
from .errors import InputError
from .findings import import_manual, import_sarif, load_normalized_finding
from .indexing import build_repository_index
from .localization import (
    STEP1_MAXIMUM_CANDIDATES,
    build_raw_localization,
    construct_inference_request,
)
from .ranking import project_localization_candidates
from .reporting import build_evidence_bundle, export_sarif
from .repository import RepositoryWorkspace
from .sandbox import DockerSandbox, load_reproduction_plan

FindingFormat = Literal["manual", "sarif", "normalized"]


def source_revision(project_root: Path | None = None) -> str:
    """Resolve the checked-out implementation revision when available."""

    root = project_root or Path(__file__).resolve().parents[2]
    if not (root / ".git").exists():
        return f"release:{__version__}"
    try:
        top_level = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if Path(top_level).resolve(strict=True) != root.resolve(strict=True):
            return f"release:{__version__}"
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        return f"uncommitted:{revision}" if dirty.strip() else revision
    except (FileNotFoundError, subprocess.SubprocessError):
        return f"release:{__version__}"


def _select_finding(
    finding_path: Path,
    finding_format: FindingFormat,
    repository_root: Path | None,
    run_index: int | None,
    result_index: int | None,
) -> dict[str, object]:
    if finding_format == "manual":
        return import_manual(finding_path, repository_root)
    if finding_format == "normalized":
        return load_normalized_finding(finding_path)
    findings = import_sarif(
        finding_path,
        run_index=run_index,
        result_index=result_index,
        repository_root=repository_root,
    )
    if len(findings) != 1:
        raise InputError(
            f"SARIF selection produced {len(findings)} findings; select one with "
            "--run-index and --result-index"
        )
    return findings[0]


def _artifact_manifest(output_directory: Path, names: list[str]) -> dict[str, object]:
    artifacts = [
        {
            "path": name,
            "sha256": sha256_file(output_directory / name),
            "size_bytes": (output_directory / name).stat().st_size,
        }
        for name in sorted(names)
    ]
    payload: dict[str, object] = {
        "schema_version": "evidence-package-manifest-v1",
        "artifacts": artifacts,
    }
    payload["manifest_id"] = stable_id("evidence-package", payload)
    return payload


def trace_repository(
    *,
    finding_path: Path,
    finding_format: FindingFormat,
    repository_source: Path,
    output_directory: Path,
    reproduction_plan_path: Path | None = None,
    image: str | None = None,
    top_k: int = 20,
    run_index: int | None = None,
    result_index: int | None = None,
    implementation_revision: str | None = None,
) -> dict[str, object]:
    """Execute import, snapshot, index, rank, reproduce, classify, and export."""

    if reproduction_plan_path is not None and not image:
        raise InputError("--image is required when --plan is supplied")
    if image is not None and reproduction_plan_path is None:
        raise InputError("--image is only valid when --plan is supplied")
    if finding_format != "sarif" and (run_index is not None or result_index is not None):
        raise InputError("--run-index and --result-index are only valid for SARIF input")
    if output_directory.exists():
        raise InputError("output directory already exists; choose a new evidence-package path")
    original_repository_root = repository_source if repository_source.is_dir() else None
    finding = _select_finding(
        finding_path,
        finding_format,
        original_repository_root,
        run_index,
        result_index,
    )

    plan: dict[str, object] | None = None
    with RepositoryWorkspace(repository_source) as workspace:
        if workspace.root is None or workspace.identity is None:
            raise RuntimeError("repository workspace did not materialise")
        index = build_repository_index(workspace.root, workspace.identity)
        request = construct_inference_request(
            finding=finding,
            repository_artifact_sha256=canonical_sha256(workspace.identity["manifest_id"]),
            source_kind="directory",
            top_k=top_k,
            maximum_candidates=STEP1_MAXIMUM_CANDIDATES,
            measure_peak_memory=False,
        )
        raw_localization = build_raw_localization(
            request,
            repository_source=workspace.root,
        )
        candidate_set = project_localization_candidates(
            finding,
            index,
            raw_localization,
            top_k=top_k,
        )
        receipt = None
        if reproduction_plan_path is not None:
            plan = load_reproduction_plan(reproduction_plan_path)
            receipt = DockerSandbox(image=str(image)).run(
                workspace.root,
                str(workspace.identity["repository_id"]),
                plan,
            )
        bundle = build_evidence_bundle(
            finding=finding,
            repository=workspace.identity,
            index=index,
            candidate_set=candidate_set,
            reproduction_requested=reproduction_plan_path is not None,
            receipt=receipt,
            source_revision=implementation_revision or source_revision(),
        )
        sarif = export_sarif(bundle)

    artifacts: list[tuple[str, object]] = [
        ("normalized-finding.json", finding),
        ("repository-index.json", index),
        ("candidates.json", candidate_set),
        ("evidence-bundle.json", bundle),
        ("evidence.sarif", sarif),
    ]
    if receipt is not None:
        artifacts.append(("reproduction-plan.json", plan))
        artifacts.append(("reproduction-receipt.json", receipt))
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=output_directory.parent, prefix=".lumi-trace-package-"
    ) as temporary_root:
        staging = Path(temporary_root) / "package"
        staging.mkdir()
        for name, value in artifacts:
            dump_json(staging / name, value)
        manifest = _artifact_manifest(staging, [name for name, _ in artifacts])
        dump_json(staging / "manifest.json", manifest)
        staging.replace(output_directory)
    return {
        "bundle": bundle,
        "candidate_set": candidate_set,
        "sarif": sarif,
        "manifest": manifest,
        "output_directory": output_directory,
    }


def load_bundle(path: Path) -> dict[str, object]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise InputError("evidence bundle must be a JSON object")
    return value
