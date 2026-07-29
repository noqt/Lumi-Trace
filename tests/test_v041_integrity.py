# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import inspect
import json
import subprocess
import sys
from pathlib import Path

import pytest

from lumi_trace.errors import InputError
from lumi_trace.findings import import_manual, import_sarif
from lumi_trace.localization import (
    CANDIDATE_TRUNCATION_ABSTENTION,
    DEFAULT_RANKER,
    RUNTIME_IDENTITY,
    V041_EVIDENCE_DEFAULT_RANKER,
    V041_EVIDENCE_RUNTIME_IDENTITY,
    build_access_policy,
    build_raw_localization,
    construct_inference_request,
    information_flow_manifest,
    repository_artifact_identity,
    validate_inference_request,
    verify_raw_localization,
)


def _learned_model() -> dict:
    from lumi_trace.canonical import stable_id
    from lumi_trace.learned_ranker import (
        ALGORITHM,
        BASE_RANKER,
        DIMENSIONS,
        FEATURE_CONTRACT,
        MODEL_SCHEMA,
    )

    value = {
        "schema_version": MODEL_SCHEMA,
        "algorithm": ALGORITHM,
        "feature_contract": FEATURE_CONTRACT,
        "dimensions": DIMENSIONS,
        "base_ranker": BASE_RANKER,
        "weights": [{"index": 0, "weight": 1}],
        "active_parameters": 1,
        "training_manifest_id": "manifest:test",
        "training_data_id": "data:test",
        "training_config": {"epochs": 1},
        "completed_epochs": 1,
        "pair_updates": 1,
        "family_balanced": True,
        "foundation_model": None,
        "tokenizer": None,
        "remote_code": False,
        "hosted_service": False,
        "cpu_inference": True,
    }
    value["artifact_id"] = stable_id("lumi-trace-localization-model", value)
    return value


def _request(
    fixture_repository: Path,
    manual_finding_path: Path,
    *,
    ranker: str = DEFAULT_RANKER,
) -> dict:
    finding = import_manual(manual_finding_path, fixture_repository)
    identity, source_kind = repository_artifact_identity(fixture_repository)
    return construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
        ranker=ranker,
        top_k=100,
    )


def test_product_default_freezes_the_reviewed_deterministic_runtime(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    request = _request(fixture_repository, manual_finding_path)
    assert request["configuration"]["ranker"] == "role-aware-sparse-v0.4.1.3"
    assert request["configuration"]["runtime_identity"] == RUNTIME_IDENTITY
    assert RUNTIME_IDENTITY == "lumi-trace-runtime-v0.4.1-pre-release.9"


def test_sarif_projection_preserves_required_source_provenance(
    fixture_repository: Path,
    sarif_finding_path: Path,
) -> None:
    finding = import_sarif(
        sarif_finding_path,
        repository_root=fixture_repository,
    )[0]
    identity, source_kind = repository_artifact_identity(fixture_repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
    )
    assert request["finding"]["source"]["tool_name"] == "Skylark Fixture Analyzer"
    assert request["finding"]["source"]["tool_version"] == "1.0.0"
    assert request["finding"]["source"]["sarif_run_index"] == 0
    assert request["finding"]["source"]["sarif_result_index"] == 0


def test_historical_runtime_request_remains_explicitly_reconstructable(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    finding = import_manual(manual_finding_path, fixture_repository)
    identity, source_kind = repository_artifact_identity(fixture_repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
        runtime_identity=V041_EVIDENCE_RUNTIME_IDENTITY,
        ranker=V041_EVIDENCE_DEFAULT_RANKER,
        top_k=100,
    )
    assert request["request_id"] == (
        "localization-request:7b25e65517680a3851e253258609391c288663ee2384215737479a5f198af927"
    )
    assert validate_inference_request(request) == request
    raw = build_raw_localization(request, repository_source=fixture_repository)
    assert raw["runtime_identity"] == V041_EVIDENCE_RUNTIME_IDENTITY
    assert raw["ranker"] == V041_EVIDENCE_DEFAULT_RANKER
    assert (
        information_flow_manifest(runtime_identity=V041_EVIDENCE_RUNTIME_IDENTITY)[
            "runtime_identity"
        ]
        == V041_EVIDENCE_RUNTIME_IDENTITY
    )


def test_step1_runtime_abstains_when_candidate_generation_is_truncated(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = "\n".join(
        f"def vulnerable_reference_loader_{number}():\n    return 'reference body'"
        for number in range(25)
    )
    (repository / "loader.py").write_text(source + "\n", encoding="utf-8")
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(
        json.dumps(
            {
                "title": "Vulnerable reference loader",
                "description": "Reference body loader may escape its root",
                "keywords": ["reference", "loader"],
            }
        ),
        encoding="utf-8",
    )
    finding = import_manual(finding_path, repository)
    identity, source_kind = repository_artifact_identity(repository)
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
        top_k=20,
        maximum_candidates=20,
        measure_peak_memory=False,
    )
    raw = build_raw_localization(request, repository_source=repository)
    assert raw["generation"]["truncated"] is True
    assert raw["abstention"] == {
        "abstained": True,
        "reason": CANDIDATE_TRUNCATION_ABSTENTION,
    }


def test_allowed_projection_has_no_answer_bearing_field(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    request = _request(fixture_repository, manual_finding_path)
    rendered = json.dumps(request, sort_keys=True)
    for marker in (
        "private_targets",
        "fixed_revision",
        "candidate_target",
        "qualification",
        "reviewer_conclusion",
    ):
        assert marker not in rendered
    assert validate_inference_request(request) == request


def test_builder_rejects_audit_receipt_and_target_canary(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    request = _request(fixture_repository, manual_finding_path)
    request["private_targets"] = [{"path": "CANARY-TARGET.py"}]
    with pytest.raises(InputError, match="allowed-field"):
        validate_inference_request(request)


def test_missing_and_permuted_labels_cannot_change_raw_output(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    request = _request(fixture_repository, manual_finding_path)
    first = build_raw_localization(request, repository_source=fixture_repository)
    # These scorer-side envelopes are deliberately never passed to the
    # constructor or builder.
    labels_a = {"private_targets": [{"path": "CANARY-A.py"}], "outcome": "A"}
    labels_b = {"private_targets": [{"path": "CANARY-B.py"}], "outcome": "B"}
    assert labels_a != labels_b
    second = build_raw_localization(request, repository_source=fixture_repository)
    assert first["request_id"] == second["request_id"]
    assert first["ranking_id"] == second["ranking_id"]
    assert first["candidates"] == second["candidates"]
    assert first["generation"] == second["generation"]
    assert "CANARY-" not in json.dumps(first, sort_keys=True)


def test_builder_path_policy_denies_scorer_and_custodian_roots(tmp_path: Path) -> None:
    builder = tmp_path / "builder"
    labels = tmp_path / "scorer" / "labels"
    custodian = tmp_path / "custodian"
    builder.mkdir()
    labels.mkdir(parents=True)
    custodian.mkdir()
    policy = build_access_policy(
        allowed_roots=[builder],
        forbidden_roots=[labels, custodian],
    )
    from lumi_trace.localization import assert_builder_path

    assert assert_builder_path(builder, policy, must_exist=True) == builder.resolve()
    with pytest.raises(InputError, match="outside"):
        assert_builder_path(labels, policy, must_exist=True)


def test_builder_runtime_guard_denies_arbitrary_label_and_socket_access(
    tmp_path: Path,
) -> None:
    builder = tmp_path / "builder"
    labels = tmp_path / "scorer" / "labels"
    builder.mkdir()
    labels.mkdir(parents=True)
    canary = labels / "CANARY-TARGET.txt"
    canary.write_text("must-not-be-readable", encoding="utf-8")
    policy = build_access_policy(
        allowed_roots=[builder],
        forbidden_roots=[labels],
    )
    script = """
import json
import socket
import sys
from pathlib import Path
from lumi_trace.builder import _install_runtime_guard
_install_runtime_guard(json.loads(sys.argv[1]))
denied = []
try:
    Path(sys.argv[2]).read_text(encoding="utf-8")
except PermissionError:
    denied.append("file")
try:
    socket.socket()
except PermissionError:
    denied.append("socket")
raise SystemExit(0 if denied == ["file", "socket"] else 9)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, json.dumps(policy), str(canary)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_builder_api_cannot_accept_labels_targets_or_receipts() -> None:
    parameters = set(inspect.signature(build_raw_localization).parameters)
    assert parameters == {
        "request",
        "repository_source",
        "access_policy",
        "model_artifact",
    }
    assert not parameters & {
        "audit_receipt",
        "labels",
        "private_targets",
        "targets",
        "fixed_revision",
    }


def test_information_flow_manifest_has_no_forbidden_output_path() -> None:
    manifest = information_flow_manifest()
    assert manifest["forbidden_paths_to_output"] == []
    assert manifest["scoring_boundary"] == {
        "builder_emits": "localization-raw-ranking-v0.4.1",
        "scoring_requires_raw_output_seal": True,
        "builder_imports_scorer": False,
        "builder_accepts_audit_receipt": False,
    }
    assert manifest["manifest_id"].startswith("localization-information-flow:")


@pytest.mark.parametrize(
    "ranker",
    [
        "role-aware-sparse-v0.4.1.1",
        "role-aware-sparse-v0.4.1.2",
        "role-aware-sparse-v0.4.1.3",
        "structured-role-sparse-v0.4.1.4",
    ],
)
def test_product_runtime_localizer_is_bounded_and_replayable(
    fixture_repository: Path,
    manual_finding_path: Path,
    ranker: str,
) -> None:
    request = _request(fixture_repository, manual_finding_path, ranker=ranker)
    first = build_raw_localization(request, repository_source=fixture_repository)
    second = build_raw_localization(request, repository_source=fixture_repository)
    verify_raw_localization(first)
    assert first["ranking_id"] == second["ranking_id"]
    assert first["candidates"] == second["candidates"]
    assert first["candidate_inventory"] == second["candidate_inventory"]
    assert len(first["candidates"]) <= 100
    assert first["candidate_count_ranked"] == len(first["candidate_inventory"])
    assert first["telemetry"]["network_used"] is False
    assert first["telemetry"]["repository_code_executed"] is False


def test_frozen_v012_comparator_ranking_is_unchanged(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    from lumi_trace.indexing import build_repository_index
    from lumi_trace.ranking import rank_candidates
    from lumi_trace.repository import compute_repository_identity

    finding = import_manual(manual_finding_path, fixture_repository)
    index = build_repository_index(
        fixture_repository,
        compute_repository_identity(fixture_repository),
    )
    result = rank_candidates(finding, index, top_k=20)
    assert (
        result["candidate_set_id"]
        == "candidate-set:af05245d12675c7f4556ae1807ad9f1ce55155a5681096fd80103b4097fdccb7"
    )
    assert [
        (
            candidate["rank"],
            candidate["kind"],
            candidate["path"],
            candidate["integer_score"],
        )
        for candidate in result["candidates"]
    ] == [
        (1, "symbol", "src/archive.sh", 38600),
        (2, "file", "src/archive.sh", 18100),
        (3, "file", "tests/reproduce.sh", 3300),
        (4, "file", "README.md", 1200),
        (5, "file", "LICENSE", 400),
    ]


def test_failed_attempts_remain_in_capability_denominators() -> None:
    from scripts.build_v0_4_1_integrity import _aggregate_attempts

    completed_metrics = {
        "family_id": "family:one",
        "candidate_count": 10,
        "valid_attempt": True,
        "target_indexable": True,
        "file_target_indexable": True,
        "role_target_indexable": True,
        "file_recall_at_5": True,
        "file_recall_at_10": True,
        "file_recall_at_20": True,
        "location_role_recall_at_20": True,
        "reciprocal_rank": 1.0,
        "no_relevant_candidate": False,
        "has_hard_negative": True,
        "hard_negative_outrank": False,
        "wrong_location_role_top_one": False,
        "disposition_emitted": False,
        "false_supported_disposition": False,
        "false_vulnerability_safe_control": False,
        "unsafe_non_abstention": False,
    }
    aggregate = _aggregate_attempts(
        [
            {
                "status": "COMPLETED",
                "family_id": "family:one",
                "has_hard_negative": True,
                "metrics": completed_metrics,
            },
            {
                "status": "BUILDER_TIMEOUT",
                "family_id": "family:two",
                "has_hard_negative": True,
            },
        ]
    )
    assert aggregate["valid_attempt_completion"] == 0.5
    assert aggregate["file_target_indexability"] == 0.5
    assert aggregate["role_target_indexability"] == 0.5
    assert aggregate["file_recall_at_20"] == 0.5
    assert aggregate["location_role_correct_recall_at_20"] == 0.5
    assert aggregate["hard_negative_outrank"] == 0.5


def test_final_capability_gates_enforce_family_role_and_safety_floors_independently() -> None:
    from scripts.seal_v0_4_1 import _gate_results

    passing = {
        "valid_attempt_completion": 1.0,
        "file_target_indexability": 0.95,
        "role_target_indexability": 0.95,
        "file_recall_at_5": 0.65,
        "file_recall_at_10": 0.75,
        "file_recall_at_20": 0.85,
        "location_role_correct_recall_at_20": 0.70,
        "mean_reciprocal_rank": 0.35,
        "no_relevant_candidate": 0.15,
        "hard_negative_outrank": 0.20,
        "wrong_location_role_top_one": 0.15,
        "repository_family_macro_recall_at_20": 0.80,
        "minimum_family_recall_at_20": 0.60,
        "zero_recall_family_count": 0,
        "false_supported_disposition": 0,
        "false_vulnerability_safe_control": 0,
        "unsafe_non_abstention": 0,
    }
    assert all(_gate_results(passing).values())
    regressions = {
        "role_target_indexability": 0.94,
        "minimum_family_recall_at_20": 0.59,
        "zero_recall_family_count": 1,
        "false_supported_disposition": 1,
        "false_vulnerability_safe_control": 1,
        "unsafe_non_abstention": 1,
    }
    for field, failing_value in regressions.items():
        gates = _gate_results({**passing, field: failing_value})
        assert gates[field] is False
        assert all(value for gate, value in gates.items() if gate != field)


def test_learned_route_is_hash_bound_and_runs_through_the_product_runtime(
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    from lumi_trace.learned_ranker import LEARNED_RANKER

    finding = import_manual(manual_finding_path, fixture_repository)
    identity, source_kind = repository_artifact_identity(fixture_repository)
    model = _learned_model()
    request = construct_inference_request(
        finding=finding,
        repository_artifact_sha256=identity,
        source_kind=source_kind,
        ranker=LEARNED_RANKER,
        top_k=100,
        model_artifact=model,
    )
    output = build_raw_localization(
        request,
        repository_source=fixture_repository,
        model_artifact=model,
    )
    assert output["model_artifact_id"] == model["artifact_id"]
    assert output["ranker"] == LEARNED_RANKER
    assert all(
        {
            "LEARNED_INTEGER_LINEAR",
            "LEARNED_HYBRID_CONTRIBUTION",
        }
        <= candidate["score_components"].keys()
        for candidate in output["candidates"]
    )
    tampered = {**model, "weights": [{"index": 0, "weight": 2}]}
    with pytest.raises(Exception, match="identity"):
        build_raw_localization(
            request,
            repository_source=fixture_repository,
            model_artifact=tampered,
        )
