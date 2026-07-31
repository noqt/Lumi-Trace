# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from trace_eval.contracts import make_record, validate_record
from trace_eval.errors import ContractError, PolicyError
from trace_eval.policy import (
    assert_runner_blind,
    audit_repository_independence,
    sanitize_environment,
    verify_public_document,
    verify_rights,
    verify_transition,
)


def _rights(name: str, **changes: object) -> dict[str, object]:
    digest = (name.encode().hex() + "0" * 64)[:64]
    payload: dict[str, object] = {
        "repository_id": f"repository:{digest}",
        "tree_id": f"sha256:{digest}",
        "source": "public synthetic fixture",
        "acquisition_method": "versioned source",
        "licence": "Apache-2.0",
        "rights_basis": "authorship",
        "redistribution_status": "PUBLIC_REDISTRIBUTION_PERMITTED",
        "review_status": "SKYLARK_AUTHORED",
        "lineage_id": f"lineage:{name}",
        "family_id": f"family:{name}",
        "shared_history_root": f"history:{name}",
        "exposure_state": "CONSTRUCTION_VISIBLE",
        "governed_location": f"fixtures/{name}",
        "input_hashes": [f"sha256:{digest}"],
        "content_fingerprints": [f"sha256:{digest}"],
    }
    payload.update(changes)
    return make_record("repository-rights-manifest-v1", payload)


def _split(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    left_id = left["payload"]["repository_id"]
    right_id = right["payload"]["repository_id"]
    return make_record(
        "split-manifest-v1",
        {
            "partitions": {
                "public_regression": [],
                "future_training_candidate": [],
                "development": [left_id],
                "qualification": [right_id],
                "frozen_holdback": [],
            },
            "repositories": {left_id: "development", right_id: "qualification"},
            "locked": True,
            "independence_method": "test",
        },
    )


def test_canonical_identity_detects_tamper_but_excludes_declared_observations() -> None:
    record = make_record(
        "exposure-transition-v1",
        {
            "subject_id": "repository:test",
            "from_state": "CONSTRUCTION_VISIBLE",
            "to_state": "DEVELOPMENT_VISIBLE",
            "decision_receipt_id": "receipt:test",
        },
        observations={"wall_time_ms": 1},
    )
    observed = deepcopy(record)
    observed["observations"]["wall_time_ms"] = 999
    validate_record(observed)
    tampered = deepcopy(record)
    tampered["payload"]["to_state"] = "RETIRED"
    with pytest.raises(ContractError, match="identity mismatch"):
        validate_record(tampered)


def test_schema_rejects_missing_payload_fields() -> None:
    record = make_record(
        "exposure-transition-v1",
        {
            "subject_id": "repository:test",
            "from_state": "CONSTRUCTION_VISIBLE",
            "to_state": "DEVELOPMENT_VISIBLE",
            "decision_receipt_id": "receipt:test",
        },
    )
    record["payload"].pop("decision_receipt_id")
    with pytest.raises(ContractError):
        validate_record(record)


def test_rights_fail_closed_and_frozen_content_cannot_be_scheduled() -> None:
    verify_rights(_rights("public"), mode="public-fixture")
    incomplete = _rights("missing", rights_basis="")
    with pytest.raises(PolicyError, match="RIGHTS_OR_PROVENANCE_REJECTED"):
        verify_rights(incomplete, mode="public-fixture")
    frozen = _rights("frozen", exposure_state="FROZEN_UNOPENED")
    with pytest.raises(PolicyError, match="frozen holdback"):
        verify_rights(frozen, mode="qualification")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tree_id", "sha256:" + "a" * 64),
        ("lineage_id", "lineage:fork"),
        ("family_id", "family:vendored-copy"),
        ("shared_history_root", "history:shared"),
    ],
)
def test_direct_fork_vendored_and_history_overlap_fail_closed(field: str, value: str) -> None:
    left = _rights("left", **{field: value})
    right = _rights("right", **{field: value})
    with pytest.raises(PolicyError, match="SPLIT_OR_LINEAGE_VIOLATION"):
        audit_repository_independence([left, right], _split(left, right))


def test_near_duplicate_cross_split_overlap_fails_closed() -> None:
    common = [f"sha256:{number:064x}" for number in range(1, 6)]
    left = _rights("left", content_fingerprints=common)
    right = _rights("right", content_fingerprints=common[:4])
    with pytest.raises(PolicyError, match="near-duplicate"):
        audit_repository_independence([left, right], _split(left, right))


def test_invalid_and_frozen_exposure_transitions_are_rejected() -> None:
    invalid = make_record(
        "exposure-transition-v1",
        {
            "subject_id": "repository:test",
            "from_state": "DEVELOPMENT_VISIBLE",
            "to_state": "CONSTRUCTION_VISIBLE",
            "decision_receipt_id": "receipt:test",
        },
    )
    with pytest.raises(PolicyError, match="invalid transition"):
        verify_transition(invalid)
    frozen = make_record(
        "exposure-transition-v1",
        {
            "subject_id": "repository:test",
            "from_state": "FROZEN_UNOPENED",
            "to_state": "RETIRED",
            "decision_receipt_id": "receipt:test",
        },
    )
    with pytest.raises(PolicyError, match="cannot open frozen"):
        verify_transition(frozen)


def test_label_and_secret_leakage_is_removed_or_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="label field"):
        assert_runner_blind({"accepted_target": "src/secret.py"})
    environment = sanitize_environment(
        {
            "PATH": "safe",
            "API_KEY": "secret",
            "GROUND_TRUTH_LABEL": "src/secret.py",
        },
        temp_root=tmp_path,
    )
    assert environment["PATH"] == "safe"
    assert "API_KEY" not in environment
    assert "GROUND_TRUTH_LABEL" not in environment


def test_public_output_rejects_private_paths_and_source_content() -> None:
    with pytest.raises(PolicyError, match="absolute private path"):
        verify_public_document({"path": "C:/private/evidence.json"})
    with pytest.raises(PolicyError, match="protected field"):
        verify_public_document({"source_text": "protected"})
    with pytest.raises(PolicyError, match="protected field"):
        verify_public_document({"vulnerable_revision": "a" * 40})
    with pytest.raises(PolicyError, match="protected field"):
        verify_public_document({"targets": [{"path": "private/location.py"}]})
