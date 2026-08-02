# SPDX-License-Identifier: Apache-2.0
"""Tests for the V0.6 unique-path reviewer shortlist projection."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from lumi_trace.canonical import stable_id
from lumi_trace.errors import IntegrityError
from lumi_trace.findings import import_sarif
from lumi_trace.indexing import build_repository_index
from lumi_trace.localization import (
    V05_DEFAULT_RANKER,
    V06_DEFAULT_RANKER,
    build_raw_localization,
    construct_inference_request,
    repository_artifact_identity,
)
from lumi_trace.ranking import project_localization_candidates, verify_candidate_set
from lumi_trace.repository import RepositoryWorkspace


def _raw_localization(repository: Path, finding_path: Path, ranker: str) -> tuple[dict, dict]:
    finding = import_sarif(finding_path, repository_root=repository)[0]
    identity, source_kind = repository_artifact_identity(repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
        ranker=ranker,
        top_k=20,
    )
    return finding, build_raw_localization(request, repository_source=repository)


def _index(repository: Path) -> dict:
    with RepositoryWorkspace(repository) as workspace:
        assert workspace.root is not None and workspace.identity is not None
        return build_repository_index(workspace.root, workspace.identity)


def test_v06_projects_first_ranked_anchor_for_each_unique_path(
    project_root: Path,
    sarif_finding_path: Path,
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    finding, raw = _raw_localization(repository, sarif_finding_path, V06_DEFAULT_RANKER)

    projected = project_localization_candidates(finding, _index(repository), raw, top_k=10)

    assert projected["algorithm"] == V06_DEFAULT_RANKER
    paths = [candidate["path"] for candidate in projected["candidates"]]
    assert paths == ["src/archive.py", "tests/archive_case.py"]
    assert len(paths) == len(set(paths))
    assert [candidate["rank"] for candidate in projected["candidates"]] == [1, 2]


def test_v05_projection_remains_its_existing_raw_candidate_projection(
    project_root: Path,
    sarif_finding_path: Path,
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    finding, raw = _raw_localization(repository, sarif_finding_path, V05_DEFAULT_RANKER)

    projected = project_localization_candidates(finding, _index(repository), raw, top_k=2)

    assert projected["algorithm"] == V05_DEFAULT_RANKER
    assert [candidate["path"] for candidate in projected["candidates"]] == [
        candidate["path"] for candidate in raw["candidates"][:2]
    ]


def test_v06_candidate_set_rejects_duplicate_paths(
    project_root: Path,
    sarif_finding_path: Path,
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    finding, raw = _raw_localization(repository, sarif_finding_path, V06_DEFAULT_RANKER)
    candidate_set = project_localization_candidates(finding, _index(repository), raw, top_k=2)

    tampered = deepcopy(candidate_set)
    duplicate = deepcopy(tampered["candidates"][0])
    duplicate["rank"] = 2
    tampered["candidates"][1] = duplicate
    ranking_identity = {
        "algorithm": tampered["algorithm"],
        "candidate_algorithm": tampered["candidate_algorithm"],
        "finding_id": tampered["finding_id"],
        "index_id": tampered["index_id"],
        "candidate_ids": [candidate["candidate_id"] for candidate in tampered["candidates"]],
        "abstention": tampered["abstention"],
    }
    tampered["ranking_id"] = stable_id("ranking", ranking_identity)
    tampered["candidate_set_id"] = stable_id(
        "candidate-set", tampered, omit_keys=("candidate_set_id",)
    )

    with pytest.raises(IntegrityError, match="paths must be unique"):
        verify_candidate_set(tampered)
