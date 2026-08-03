# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import lumi_trace.pipeline as pipeline_module
from lumi_trace.canonical import dump_json, load_json, stable_id
from lumi_trace.errors import InputError, IntegrityError
from lumi_trace.pipeline import source_revision, trace_repository
from lumi_trace.ranking import verify_candidate_set
from lumi_trace.reporting import verify_evidence_bundle


def test_pipeline_emits_complete_package_without_reproduction(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    output = tmp_path / "evidence"
    result = trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=fixture_repository,
        output_directory=output,
        top_k=8,
        implementation_revision="fixture-revision",
    )
    assert result["bundle"]["classification"]["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert result["candidate_set"]["algorithm"] == "role-aware-sparse-v0.6.0.1"
    assert (
        result["candidate_set"]["candidate_algorithm"]
        == "label-blind-python-role-candidates-v0.4.1.7"
    )
    assert result["bundle"]["index"]["algorithm"] == "deterministic-lexical-index-v4"
    assert result["candidate_set"]["abstention"] == {
        "abstained": True,
        "reason": "NO_POSITIVE_FINDING_GUIDED_SIGNAL",
    }
    assert result["bundle"]["ranking"]["ranking_id"] == result["candidate_set"]["ranking_id"]
    assert (
        "Step 1 implementation-location ranking considers Python files and symbols only."
        in result["bundle"]["limitations"]
    )
    assert (
        "Extracted symbols are lexical landmarks and do not assert that files compile."
        in result["bundle"]["limitations"]
    )
    assert (
        "Current Step 1 deterministic artifacts require printable-ASCII repository paths."
        in result["bundle"]["limitations"]
    )
    expected = {
        "normalized-finding.json",
        "repository-index.json",
        "candidates.json",
        "evidence-bundle.json",
        "evidence.sarif",
        "manifest.json",
    }
    assert {item.name for item in output.iterdir()} == expected
    verify_evidence_bundle(load_json(output / "evidence-bundle.json"))

    mismatched_profile = deepcopy(result["bundle"])
    mismatched_profile["index"]["algorithm"] = "deterministic-lexical-index-v2"
    mismatched_profile["bundle_id"] = stable_id(
        "evidence-bundle", mismatched_profile, omit_keys=("bundle_id",)
    )
    with pytest.raises(IntegrityError, match="ranking summary"):
        verify_evidence_bundle(mismatched_profile)


def test_v04_product_artifacts_remain_verifiable_after_v05_default_switch(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    result = trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=fixture_repository,
        output_directory=tmp_path / "evidence",
        top_k=8,
        implementation_revision="fixture-revision",
    )
    legacy_ranker = "role-aware-sparse-v0.4.1.3"
    legacy_candidates = deepcopy(result["candidate_set"])
    legacy_candidates["algorithm"] = legacy_ranker
    ranking_identity = {
        "algorithm": legacy_ranker,
        "candidate_algorithm": legacy_candidates["candidate_algorithm"],
        "finding_id": legacy_candidates["finding_id"],
        "index_id": legacy_candidates["index_id"],
        "candidate_ids": [item["candidate_id"] for item in legacy_candidates["candidates"]],
        "abstention": legacy_candidates["abstention"],
    }
    legacy_candidates["ranking_id"] = stable_id("ranking", ranking_identity)
    legacy_candidates["candidate_set_id"] = stable_id(
        "candidate-set", legacy_candidates, omit_keys=("candidate_set_id",)
    )
    verify_candidate_set(legacy_candidates)

    legacy_bundle = deepcopy(result["bundle"])
    legacy_bundle["ranking"]["ranker"] = legacy_ranker
    legacy_bundle["ranking"]["ranking_id"] = legacy_candidates["ranking_id"]
    legacy_bundle["provenance"]["candidate_set_id"] = legacy_candidates["candidate_set_id"]
    legacy_bundle["bundle_id"] = stable_id(
        "evidence-bundle", legacy_bundle, omit_keys=("bundle_id",)
    )
    verify_evidence_bundle(legacy_bundle)


def test_pipeline_is_byte_deterministic_without_reproduction(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    kwargs = {
        "finding_path": manual_finding_path,
        "finding_format": "manual",
        "repository_source": fixture_repository,
        "top_k": 8,
        "implementation_revision": "fixture-revision",
    }
    trace_repository(output_directory=first, **kwargs)
    trace_repository(output_directory=second, **kwargs)
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }


def test_python_minor_versions_share_one_frozen_lexical_profile(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "target.py").write_bytes(
        b"def parse_alias(value):\n    return value\n",
    )
    (repository / "future.py").write_bytes(
        b"type FutureAlias = dict[str, str]\n\nclass FutureSyntax:\n    pass\n",
    )
    finding_path = tmp_path / "finding.json"
    dump_json(
        finding_path,
        {
            "schema_version": "manual-finding-v1",
            "id": "TRACE-LEXICAL-PROFILE-001",
            "title": "Alias parser accepts an unsafe value",
            "description": "parse_alias must validate the supplied alias value.",
            "severity": "high",
            "rule": {
                "id": "TRACE-LEXICAL-PROFILE-001",
                "name": "Unsafe alias parser",
                "cwes": ["CWE-20"],
                "tags": ["alias", "validation"],
            },
            "locations": [
                {
                    "path": "target.py",
                    "symbol": "parse_alias",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 2,
                    "end_column": 17,
                }
            ],
            "keywords": ["alias", "parse", "validation"],
            "fingerprints": {"fixture/v1": "trace-lexical-profile-001"},
        },
    )
    output = tmp_path / "evidence"

    result = trace_repository(
        finding_path=finding_path,
        finding_format="manual",
        repository_source=repository,
        output_directory=output,
        implementation_revision="fixture-revision",
    )
    index = load_json(output / "repository-index.json")

    assert index["algorithm"] == "deterministic-lexical-index-v4"
    assert index["symbol_count"] == 1
    future = next(record for record in index["files"] if record["path"] == "future.py")
    assert future["symbols"] == []
    assert future["symbol_extraction_issue"] == "syntax_error"
    assert result["candidate_set"]["candidate_count_considered"] == 3
    assert index["index_id"] == (
        "index:3a133f8622267b3763668b07f18e4d244531e17fc867aeac1d97cac095ed8e07"
    )
    assert result["candidate_set"]["algorithm"] == "role-aware-sparse-v0.6.0.1"
    assert result["candidate_set"]["ranking_id"].startswith("ranking:")
    assert result["candidate_set"]["candidate_set_id"].startswith("candidate-set:")


def test_pipeline_refuses_existing_output_directory(
    tmp_path: Path, fixture_repository: Path, manual_finding_path: Path
) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    stale = output / "stale-receipt.json"
    stale.write_text("do not retain", encoding="utf-8")
    with pytest.raises(InputError, match="already exists"):
        trace_repository(
            finding_path=manual_finding_path,
            finding_format="manual",
            repository_source=fixture_repository,
            output_directory=output,
            implementation_revision="fixture-revision",
        )
    assert stale.read_text(encoding="utf-8") == "do not retain"


def test_no_reproduction_path_never_requires_docker(
    tmp_path: Path,
    fixture_repository: Path,
    manual_finding_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenDocker:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("Docker must not be inspected without an explicit plan")

    monkeypatch.setattr(pipeline_module, "DockerSandbox", ForbiddenDocker)
    result = trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=fixture_repository,
        output_directory=tmp_path / "evidence",
        implementation_revision="fixture-revision",
    )
    assert result["bundle"]["reproduction"] == {
        "requested": False,
        "attempted": False,
        "receipts": [],
    }
    assert result["bundle"]["classification"]["reason_codes"] == ["NO_REPRODUCTION_PLAN"]


def test_pipeline_rejects_ambiguous_option_combinations(
    tmp_path: Path,
    fixture_repository: Path,
    manual_finding_path: Path,
) -> None:
    with pytest.raises(InputError, match="only valid for SARIF"):
        trace_repository(
            finding_path=manual_finding_path,
            finding_format="manual",
            repository_source=fixture_repository,
            output_directory=tmp_path / "unused-selectors",
            run_index=0,
            result_index=0,
        )
    with pytest.raises(InputError, match="only valid when --plan"):
        trace_repository(
            finding_path=manual_finding_path,
            finding_format="manual",
            repository_source=fixture_repository,
            output_directory=tmp_path / "unused-image",
            image="example@sha256:" + "a" * 64,
        )


def test_pipeline_abstains_when_only_generic_ranking_priors_are_positive(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "plain.py").write_text(
        "def ordinary():\n    return 1\n",
        encoding="utf-8",
    )
    finding = tmp_path / "finding.json"
    dump_json(
        finding,
        {
            "schema_version": "manual-finding-v1",
            "id": "NO-SIGNAL",
            "title": "Quasar nebula mismatch",
            "description": "Zephyr xylophone unrelated terminology",
            "severity": "note",
            "rule": {
                "id": "UNRELATED",
                "name": "Unrelated signal",
                "cwes": [],
                "tags": [],
            },
            "locations": [],
            "keywords": ["quasar", "nebula"],
            "fingerprints": {},
        },
    )

    result = trace_repository(
        finding_path=finding,
        finding_format="manual",
        repository_source=repository,
        output_directory=tmp_path / "evidence",
        implementation_revision="fixture-revision",
    )

    candidate_set = result["candidate_set"]
    assert candidate_set["candidate_count_considered"] == 2
    assert candidate_set["candidates"] == []
    assert candidate_set["abstention"] == {
        "abstained": True,
        "reason": "NO_POSITIVE_FINDING_GUIDED_SIGNAL",
    }
    assert candidate_set["confidence_descriptor"] == "ABSTAINED"
    assert result["bundle"]["ranking"]["candidates_emitted"] == 0
    assert "localization.json" not in {item.name for item in (tmp_path / "evidence").iterdir()}

    false_non_abstention = deepcopy(candidate_set)
    false_non_abstention["abstention"] = {"abstained": False, "reason": None}
    false_non_abstention["confidence_descriptor"] = "FINDING_GUIDED_SIGNAL_PRESENT"
    with pytest.raises(IntegrityError, match="abstention or confidence"):
        verify_candidate_set(false_non_abstention)

    inconsistent_bundle = deepcopy(result["bundle"])
    inconsistent_bundle["ranking"]["abstention"] = {"abstained": False, "reason": None}
    inconsistent_bundle["ranking"]["confidence_descriptor"] = "FINDING_GUIDED_SIGNAL_PRESENT"
    with pytest.raises(IntegrityError, match="ranking summary is inconsistent"):
        verify_evidence_bundle(inconsistent_bundle)


def test_product_verifiers_reject_abstention_with_emitted_candidates(
    tmp_path: Path,
    project_root: Path,
    manual_finding_path: Path,
) -> None:
    repository = project_root / "tests" / "fixtures" / "localization-repository"
    result = trace_repository(
        finding_path=manual_finding_path,
        finding_format="manual",
        repository_source=repository,
        output_directory=tmp_path / "evidence",
        implementation_revision="fixture-revision",
    )
    assert result["candidate_set"]["candidates"]
    sarif_locations = [
        result["sarif"]["runs"][0]["results"][0]["locations"][0],
        *result["sarif"]["runs"][0]["results"][0].get("relatedLocations", []),
    ]
    assert [location["properties"]["locationRole"] for location in sarif_locations] == [
        candidate["role"] for candidate in result["candidate_set"]["candidates"]
    ]

    false_abstention = deepcopy(result["candidate_set"])
    false_abstention["abstention"] = {
        "abstained": True,
        "reason": "NO_POSITIVE_FINDING_GUIDED_SIGNAL",
    }
    false_abstention["confidence_descriptor"] = "ABSTAINED"
    with pytest.raises(IntegrityError, match="abstention or confidence"):
        verify_candidate_set(false_abstention)

    inconsistent_bundle = deepcopy(result["bundle"])
    inconsistent_bundle["ranking"]["abstention"] = {
        "abstained": True,
        "reason": "NO_POSITIVE_FINDING_GUIDED_SIGNAL",
    }
    inconsistent_bundle["ranking"]["confidence_descriptor"] = "ABSTAINED"
    with pytest.raises(IntegrityError, match="ranking summary is inconsistent"):
        verify_evidence_bundle(inconsistent_bundle)


def test_source_revision_does_not_inherit_an_unrelated_parent_repository(tmp_path: Path) -> None:
    package_like_directory = tmp_path / "site-packages"
    package_like_directory.mkdir()
    assert source_revision(package_like_directory) == "release:0.8.0"


def test_source_revision_marks_a_dirty_checkout_as_uncommitted(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Lumi Trace Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    tracked = repository / "tracked.txt"
    tracked.write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert source_revision(repository) == revision
    tracked.write_text("dirty\n", encoding="utf-8")
    assert source_revision(repository) == f"uncommitted:{revision}"
