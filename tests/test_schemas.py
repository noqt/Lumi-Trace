# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from lumi_trace.canonical import load_json, sha256_file, stable_id
from lumi_trace.findings import import_manual
from lumi_trace.indexing import build_repository_index
from lumi_trace.pipeline import trace_repository
from lumi_trace.ranking import rank_candidates
from lumi_trace.reporting import build_evidence_bundle
from lumi_trace.repository import RepositoryWorkspace


@pytest.mark.parametrize(
    ("schema_name", "definition_name", "valid_value"),
    [
        ("normalized-finding-v1.json", "relativePath", "src/module.py"),
        ("repository-index-v1.json", "relativePath", "src/module.py"),
        ("candidate-set-v1.json", "relativePath", "src/module.py"),
        ("reproduction-receipt-v1.json", "relativeDirectory", "."),
    ],
)
def test_contract_paths_are_canonical_posix_relative(
    project_root: Path,
    schema_name: str,
    definition_name: str,
    valid_value: str,
) -> None:
    schemas, _ = _schemas(project_root)
    validator = Draft202012Validator(schemas[schema_name]["$defs"][definition_name])
    assert not list(validator.iter_errors(valid_value))
    for invalid_value in (
        "/absolute/path",
        "C:/absolute/path",
        "C:drive-relative/path",
        "C:\\absolute\\path",
        "../escape",
        "parent/../escape",
        "nested\\windows",
        "nul\x00byte",
    ):
        assert list(validator.iter_errors(invalid_value)), invalid_value


def _schemas(project_root: Path) -> tuple[dict[str, dict], Registry]:
    documents: dict[str, dict] = {}
    registry = Registry()
    for path in sorted((project_root / "schemas").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(document)
        documents[path.name] = document
        registry = registry.with_resource(path.name, Resource.from_contents(document))
    return documents, registry


def test_contract_schemas_validate_emitted_documents(
    project_root: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    schemas, registry = _schemas(project_root)
    finding = import_manual(manual_finding_path, fixture_repository)
    with RepositoryWorkspace(fixture_repository) as workspace:
        index = build_repository_index(workspace.root, workspace.identity)
        candidates = rank_candidates(finding, index)
        bundle = build_evidence_bundle(
            finding=finding,
            repository=workspace.identity,
            index=index,
            candidate_set=candidates,
            reproduction_requested=False,
            receipt=None,
            source_revision="fixture-revision",
        )
    emitted = {
        "normalized-finding-v1.json": finding,
        "repository-index-v1.json": index,
        "candidate-set-v1.json": candidates,
        "evidence-bundle-v1.json": bundle,
    }
    for name, document in emitted.items():
        Draft202012Validator(schemas[name], registry=registry).validate(document)


def test_v041_localization_schemas_validate_product_documents(
    project_root: Path,
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    from lumi_trace.learned_ranker import (
        ALGORITHM,
        BASE_RANKER,
        DIMENSIONS,
        FEATURE_CONTRACT,
        MODEL_SCHEMA,
    )
    from lumi_trace.localization import (
        build_raw_localization,
        construct_inference_request,
        repository_artifact_identity,
    )

    schemas, registry = _schemas(project_root)
    finding = import_manual(manual_finding_path, fixture_repository)
    repository_sha256, source_kind = repository_artifact_identity(fixture_repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=repository_sha256,
        source_kind=source_kind,
        top_k=100,
    )
    raw = build_raw_localization(request, repository_source=fixture_repository)
    Draft202012Validator(
        schemas["localization-inference-request-v0.4.1.json"],
        registry=registry,
    ).validate(request)
    Draft202012Validator(
        schemas["localization-raw-ranking-v0.4.1.json"],
        registry=registry,
    ).validate(raw)

    model = {
        "schema_version": MODEL_SCHEMA,
        "algorithm": ALGORITHM,
        "feature_contract": FEATURE_CONTRACT,
        "dimensions": DIMENSIONS,
        "base_ranker": BASE_RANKER,
        "weights": [{"index": 0, "weight": 1}],
        "active_parameters": 1,
        "training_manifest_id": "manifest:test",
        "training_data_id": "data:test",
        "training_config": {
            "epochs": 1,
            "margin": 1,
            "maximum_candidates_per_group": 2,
            "maximum_pairs_per_group": 1,
            "seed": 0,
        },
        "completed_epochs": 1,
        "pair_updates": 1,
        "family_balanced": True,
        "foundation_model": None,
        "tokenizer": None,
        "remote_code": False,
        "hosted_service": False,
        "cpu_inference": True,
    }
    model["artifact_id"] = stable_id("lumi-trace-localization-model", model)
    Draft202012Validator(
        schemas["localization-linear-model-v0.4.1.json"],
        registry=registry,
    ).validate(model)


@pytest.mark.parametrize("count", [1, 8, 9, 10, 20])
def test_candidate_schema_accepts_canonical_reason_match_boundaries(
    project_root: Path, count: int
) -> None:
    schemas, _ = _schemas(project_root)
    validator = Draft202012Validator(schemas["candidate-set-v1.json"]["$defs"]["scoreReason"])
    reason = {
        "code": "MESSAGE_CONTENT_MATCH",
        "points": count,
        "matches": [f"match-{index:02d}" for index in range(count)],
    }

    assert not list(validator.iter_errors(reason))


@pytest.mark.parametrize(
    "matches",
    [
        [],
        ["duplicate", "duplicate"],
        [f"match-{index:02d}" for index in range(21)],
        ["valid", ""],
        ["valid", 1],
    ],
)
def test_candidate_schema_rejects_invalid_reason_matches(
    project_root: Path, matches: list[object]
) -> None:
    schemas, _ = _schemas(project_root)
    validator = Draft202012Validator(schemas["candidate-set-v1.json"]["$defs"]["scoreReason"])

    assert list(
        validator.iter_errors({"code": "MESSAGE_CONTENT_MATCH", "points": 1, "matches": matches})
    )


def test_inventory_record_validates(project_root: Path) -> None:
    schemas, registry = _schemas(project_root)
    inventory = yaml.safe_load((project_root / "model-inventory.yaml").read_text(encoding="utf-8"))
    Draft202012Validator(schemas["model-inventory-v1.json"], registry=registry).validate(inventory)


def test_input_and_package_schemas_validate_owned_examples(
    project_root: Path,
    tmp_path: Path,
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    schemas, registry = _schemas(project_root)
    manual = load_json(manual_finding_path)
    plan = load_json(project_root / "tests" / "data" / "reproduction-plan.json")
    Draft202012Validator(schemas["manual-finding-v1.json"], registry=registry).validate(manual)
    Draft202012Validator(schemas["reproduction-plan-v1.json"], registry=registry).validate(plan)

    collection: dict[str, object] = {
        "schema_version": "normalized-finding-collection-v1",
        "artifacts": [
            {
                "path": "finding-000-00000.json",
                "sha256": sha256_file(manual_finding_path),
            }
        ],
    }
    collection["manifest_id"] = stable_id("finding-collection", collection)
    Draft202012Validator(
        schemas["normalized-finding-collection-v1.json"], registry=registry
    ).validate(collection)

    output = tmp_path / "package"
    trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=fixture_repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )
    manifest = load_json(output / "manifest.json")
    Draft202012Validator(schemas["evidence-package-manifest-v1.json"], registry=registry).validate(
        manifest
    )


def test_fixture_manifest_has_valid_owned_hashes(project_root: Path) -> None:
    manifest_path = project_root / "tests" / "fixtures" / "fixture-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["licence"] == "Apache-2.0"
    assert manifest["third_party_repository_contents"] is False
    for entry in manifest["entries"]:
        path = project_root / entry["path"]
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
