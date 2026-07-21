# SPDX-License-Identifier: Apache-2.0
"""Same-host deterministic replay and semantic comparison."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import dump_json, load_json, stable_id
from .contracts import make_record
from .package import seal_package
from .runner import load_run_package, run_registry


def _semantic_fingerprints(root: Path, attempts: list[dict[str, Any]]) -> list[str]:
    fingerprints: list[str] = []
    for attempt in attempts:
        group_id = attempt["payload"]["group_id"]
        suffix = group_id.rsplit(":", 1)[-1]
        evidence = root / "raw" / suffix / "evidence-package"
        if not evidence.is_dir():
            fingerprints.append(
                stable_id(
                    "trace-eval-semantic-case",
                    {
                        "group_id": group_id,
                        "status": attempt["payload"]["status"],
                        "failure_codes": attempt["payload"]["failure_codes"],
                    },
                )
            )
            continue
        candidates = load_json(evidence / "candidates.json")
        index = load_json(evidence / "repository-index.json")
        bundle = load_json(evidence / "evidence-bundle.json")
        fingerprints.append(
            stable_id(
                "trace-eval-semantic-case",
                {
                    "group_id": group_id,
                    "candidate_set_id": candidates.get("candidate_set_id"),
                    "candidate_ids": [
                        item.get("candidate_id") for item in candidates.get("candidates", [])
                    ],
                    "index_id": index.get("index_id"),
                    "repository_id": index.get("repository", {}).get("repository_id"),
                    "classification": bundle.get("classification", {}).get("outcome"),
                },
            )
        )
    return sorted(fingerprints)


def compare_run_packages(left: Path, right: Path, *, identity_required: bool) -> dict[str, Any]:
    """Compare same-host identity or approved cross-host semantics."""

    left_run, left_attempts, _ = load_run_package(left)
    right_run, right_attempts, _ = load_run_package(right)
    identity_agreement = (
        left_run["payload"]["run_id"] == right_run["payload"]["run_id"]
        and load_json(left / "raw-output-seal.json")["record_id"]
        == load_json(right / "raw-output-seal.json")["record_id"]
    )
    semantic_agreement = left_run["payload"]["run_id"] == right_run["payload"][
        "run_id"
    ] and _semantic_fingerprints(left, left_attempts) == _semantic_fingerprints(
        right, right_attempts
    )
    mismatches: list[str] = []
    if identity_required and not identity_agreement:
        mismatches.append("identity")
    if not semantic_agreement:
        mismatches.append("semantics")
    return make_record(
        "replay-verification-v1",
        {
            "run_id": left_run["payload"]["run_id"],
            "replay_run_id": right_run["payload"]["run_id"],
            "identity_agreement": identity_agreement,
            "semantic_agreement": semantic_agreement,
            "mismatches": mismatches,
        },
    )


def replay_run(
    *,
    original: Path,
    registry: Path,
    configuration: Path,
    executable: Path,
    runtime_artifact: Path,
    source_root: Path,
    workspace_root: Path,
    output: Path,
) -> dict[str, Any]:
    load_run_package(original)
    replay_root = output / "replayed-run"
    replay = run_registry(
        registry_path=registry,
        configuration_path=configuration,
        executable=executable,
        runtime_artifact=runtime_artifact,
        source_root=source_root,
        workspace_root=workspace_root,
        output=replay_root,
    )
    record = compare_run_packages(original, replay_root, identity_required=True)
    dump_json(output / "replay-verification.json", record)
    seal_package(output)
    return {"record": record, "run": replay}
