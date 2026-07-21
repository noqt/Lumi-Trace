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
