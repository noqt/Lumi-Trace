# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from lumi_trace.canonical import dump_json, load_json, sha256_file, stable_id
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
    mismatched_non_python = deepcopy(index)
    non_python_symbol = next(
        symbol
        for file_record in mismatched_non_python["files"]
        if file_record["language"] != "python"
        for symbol in file_record["symbols"]
    )
    non_python_symbol["extractor"] = "python-lexical-v1"
    assert list(
        Draft202012Validator(
            schemas["repository-index-v1.json"],
            registry=registry,
        ).iter_errors(mismatched_non_python)
    )


def test_repository_index_schema_preserves_the_sealed_v01_profile(project_root: Path) -> None:
    schemas, registry = _schemas(project_root)
    historical = load_json(
        project_root / "evidence" / "v0.1.0" / "evidence-package" / "repository-index.json"
    )

    errors = list(
        Draft202012Validator(
            schemas["repository-index-v1.json"],
            registry=registry,
        ).iter_errors(historical)
    )

    assert not errors


def test_product_schemas_bind_the_fixed_python_extractor_to_the_current_profile(
    project_root: Path,
    tmp_path: Path,
) -> None:
    schemas, registry = _schemas(project_root)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "target.py").write_text(
        "def validate_input(value):\n    return value\n",
        encoding="utf-8",
    )
    finding_path = tmp_path / "finding.json"
    finding = load_json(project_root / "tests" / "data" / "manual-finding.json")
    finding["title"] = "Input validation bypass"
    finding["description"] = "validate_input accepts an unsafe input value."
    finding["rule"]["name"] = "Input validation bypass"
    finding["locations"] = [
        {
            "path": "target.py",
            "symbol": "validate_input",
            "start_line": 1,
            "start_column": 1,
            "end_line": 2,
            "end_column": 16,
        }
    ]
    finding["keywords"] = ["input", "validate", "validation"]
    dump_json(finding_path, finding)
    output = tmp_path / "evidence"
    trace_repository(
        finding_path=finding_path,
        finding_format="manual",
        repository_source=repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )

    index = load_json(output / "repository-index.json")
    candidates = load_json(output / "candidates.json")
    bundle = load_json(output / "evidence-bundle.json")
    index_validator = Draft202012Validator(
        schemas["repository-index-v1.json"],
        registry=registry,
    )
    candidate_validator = Draft202012Validator(
        schemas["candidate-set-v1.json"],
        registry=registry,
    )
    bundle_validator = Draft202012Validator(
        schemas["evidence-bundle-v1.json"],
        registry=registry,
    )
    index_validator.validate(index)
    candidate_validator.validate(candidates)
    bundle_validator.validate(bundle)

    mismatched_index = deepcopy(index)
    mismatched_index["files"][0]["symbols"][0]["extractor"] = "python-ast-v1"
    assert list(index_validator.iter_errors(mismatched_index))
    partial_index = deepcopy(index)
    partial_index["files"][0]["symbol_extraction_issue"] = "syntax_error"
    assert list(index_validator.iter_errors(partial_index))
    mismatched_candidates = deepcopy(candidates)
    symbol_candidate = next(
        candidate
        for candidate in mismatched_candidates["candidates"]
        if candidate["kind"] == "symbol"
    )
    symbol_candidate["symbol"]["extractor"] = "python-ast-v1"
    assert list(candidate_validator.iter_errors(mismatched_candidates))
    mismatched_bundle = deepcopy(bundle)
    bundle_symbol = next(
        candidate for candidate in mismatched_bundle["candidates"] if candidate["kind"] == "symbol"
    )
    bundle_symbol["symbol"]["extractor"] = "python-ast-v1"
    assert list(bundle_validator.iter_errors(mismatched_bundle))
    for invalid_path in ("caf\u00e9.py", "target\x7f.py", "target.py\n"):
        invalid_index = deepcopy(index)
        invalid_index["files"][0]["path"] = invalid_path
        assert list(index_validator.iter_errors(invalid_index))
        invalid_candidates = deepcopy(candidates)
        invalid_candidates["candidates"][0]["path"] = invalid_path
        assert list(candidate_validator.iter_errors(invalid_candidates))
        invalid_bundle = deepcopy(bundle)
        invalid_bundle["candidates"][0]["path"] = invalid_path
        assert list(bundle_validator.iter_errors(invalid_bundle))


def test_v041_localization_schemas_validate_product_documents(
    project_root: Path,
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
    localization_repository = project_root / "tests" / "fixtures" / "localization-repository"
    finding = import_manual(manual_finding_path, localization_repository)
    repository_sha256, source_kind = repository_artifact_identity(localization_repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=repository_sha256,
        source_kind=source_kind,
        top_k=100,
    )
    raw = build_raw_localization(request, repository_source=localization_repository)
    request_validator = Draft202012Validator(
        schemas["localization-inference-request-v0.4.1.json"],
        registry=registry,
    )
    request_validator.validate(request)
    raw_validator = Draft202012Validator(
        schemas["localization-raw-ranking-v0.4.1.json"],
        registry=registry,
    )
    raw_validator.validate(raw)
    mismatched_request = deepcopy(request)
    mismatched_request["configuration"]["candidate_algorithm"] = (
        "label-blind-python-role-candidates-v0.4.1.5"
    )
    assert list(request_validator.iter_errors(mismatched_request))
    mismatched_raw = deepcopy(raw)
    mismatched_raw["candidate_algorithm"] = "label-blind-python-role-candidates-v0.4.1.5"
    assert list(raw_validator.iter_errors(mismatched_raw))
    for invalid_path in ("caf\u00e9.py", "target\x7f.py", "target.py\n"):
        invalid_raw = deepcopy(raw)
        invalid_raw["candidate_inventory"][0]["path"] = invalid_path
        assert list(raw_validator.iter_errors(invalid_raw))
        invalid_raw = deepcopy(raw)
        invalid_raw["candidates"][0]["path"] = invalid_path
        assert list(raw_validator.iter_errors(invalid_raw))

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
    Draft202012Validator(schemas["candidate-set-v1.json"], registry=registry).validate(
        load_json(output / "candidates.json")
    )
    bundle_validator = Draft202012Validator(schemas["evidence-bundle-v1.json"], registry=registry)
    bundle = load_json(output / "evidence-bundle.json")
    bundle_validator.validate(bundle)
    mismatched_bundle = deepcopy(bundle)
    mismatched_bundle["index"]["algorithm"] = "deterministic-lexical-index-v2"
    assert list(bundle_validator.iter_errors(mismatched_bundle))


def test_fixture_manifest_has_valid_owned_hashes(project_root: Path) -> None:
    manifest_path = project_root / "tests" / "fixtures" / "fixture-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["licence"] == "Apache-2.0"
    assert manifest["third_party_repository_contents"] is False
    for entry in manifest["entries"]:
        path = project_root / entry["path"]
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
