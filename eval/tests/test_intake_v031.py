# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

import pytest

from trace_eval.canonical import sha256_bytes
from trace_eval.contracts import make_record
from trace_eval.errors import PolicyError
from trace_eval.intake import (
    AcquisitionLimits,
    QualificationBudget,
    TreeEntry,
    acquisition_plan,
    assert_acquisition_authorised,
    audit_revision_pairs,
    canonical_upstream_url,
    enforce_publication_decision,
    reject_remote_git_configuration,
    scan_tree_entries,
    validate_finding_cue_profile,
    validate_group_review,
    validate_rights_dimensions,
    validate_threshold_decision,
    verify_acquisition_receipt,
    verify_licence_evidence,
    verify_pre_run_seal,
)

REVISION = "1" * 40
PARENT = "2" * 40
TREE_ID = "sha256:" + "3" * 64
LICENCE_TEXT = "Permission is hereby granted, free of charge, to any person obtaining a copy."


def _proposal() -> dict[str, object]:
    return make_record(
        "intake-proposal-v1",
        {
            "proposed_repository_id": "proposed-repository:alpha",
            "canonical_upstream_url": "https://github.com/example/alpha.git",
            "hosting_provider": "GITHUB_PUBLIC",
            "requested_revisions": [REVISION],
            "licence_evidence_location": "LICENSE",
            "security_evidence_references": ["public-advisory:alpha"],
            "expected_language": "Python",
            "expected_weakness_classes": ["CWE-20"],
            "project_family": "family:alpha",
            "known_fork_lineage": "lineage:alpha",
            "proposed_use": "PRIVATE_EVALUATION_ONLY",
            "expected_retention": "GOVERNED_PRIVATE_STORE",
            "operator_id": "operator:controlled-intake",
            "decision_identity": "decision:pending",
            "acquisition_state": "PROPOSED",
        },
    )


def _decision(*, approved: bool = True) -> dict[str, object]:
    proposal = _proposal()
    return make_record(
        "acquisition-decision-v1",
        {
            "proposal_id": proposal["record_id"],
            "decision": "APPROVE" if approved else "REJECT",
            "from_state": "RIGHTS_PRECHECK_PASSED",
            "to_state": "ACQUISITION_APPROVED" if approved else "REJECTED",
            "reviewer_role": "CONTROLLED_INTAKE_REVIEWER",
            "rights_precheck": "PASSED" if approved else "FAILED",
            "decided_before_fetch": True,
            "rationale": "Public permissive source and immutable security evidence.",
        },
    )


def _rights(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "proposal_id": _proposal()["record_id"],
        "exact_revision": REVISION,
        "licence_identifier": "MIT",
        "licence_file_hash": sha256_bytes(LICENCE_TEXT.encode()),
        "source_access": "PUBLIC_READ",
        "private_evaluation": "PERMITTED",
        "source_redistribution": "PRIVATE_ONLY_BY_PROJECT_POLICY",
        "finding_use": "PERMITTED_WITH_ATTRIBUTION",
        "label_use": "PRIVATE_EVALUATION_ONLY",
        "future_training_use_reviewed": False,
        "future_training_use_permitted": False,
        "weight_licence": "NONE",
        "review_status": "APPROVED_FOR_PRIVATE_EVALUATION",
    }
    payload.update(changes)
    return make_record("rights-dimensions-v1", payload)


def _receipt() -> dict[str, object]:
    proposal = _proposal()
    decision = _decision()
    return make_record(
        "acquisition-receipt-v1",
        {
            "proposal_id": proposal["record_id"],
            "decision_id": decision["record_id"],
            "canonical_upstream_url": proposal["payload"]["canonical_upstream_url"],
            "requested_revision": REVISION,
            "resolved_revision": REVISION,
            "commit_object_hash": REVISION,
            "tree_object_hash": "4" * 40,
            "transport": "GIT_SMART_HTTPS_INERT_BARE_FETCH",
            "transport_hashes": ["sha256:" + "5" * 64],
            "snapshot_tree_id": TREE_ID,
            "licence_file_hash": sha256_bytes(LICENCE_TEXT.encode()),
            "lineage_id": "lineage:alpha",
            "family_id": "family:alpha",
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
                "regular_files": 1,
                "symlinks": 0,
                "special_files": 0,
                "inert_gitlinks": 0,
            },
            "repository_code_executed": False,
        },
    )


def _pair(number: int, *, lineage: str | None = None) -> dict[str, object]:
    vulnerable = f"{number + 10:040x}"
    fixed = f"{number + 20:040x}"
    return make_record(
        "revision-pair-v1",
        {
            "pair_id": f"pair:{number}",
            "repository_id": f"repository:{number}",
            "vulnerability_lineage_id": lineage or f"vulnerability:{number}",
            "security_evidence_ids": [f"advisory:{number}"],
            "vulnerable_revision": vulnerable,
            "fixed_revision": fixed,
            "vulnerable_tree_id": f"sha256:{number + 30:064x}",
            "fixed_tree_id": f"sha256:{number + 40:064x}",
            "label_construction_state": "PENDING_BLIND_CONSTRUCTION",
        },
    )


def _cue(*, ablation: bool = False, leaked: bool = False) -> dict[str, object]:
    return make_record(
        "finding-cue-profile-v1",
        {
            "group_id": "group:alpha-ablation" if ablation else "group:alpha",
            "finding_id": "finding:alpha",
            "available_cues": ["advisory_summary", "weakness"],
            "withheld_cues": ["fixing_diff", "accepted_targets"],
            "fixing_diff_in_runner_input": leaked,
            "label_fields_in_runner_input": False,
            "ablation_of_group_id": "group:alpha" if ablation else None,
            "counts_toward_natural_total": not ablation,
        },
    )


def _review(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "group_id": "group:alpha",
        "label_id": "trace-code-location-label:alpha",
        "reviewer_role": "CONTROLLED_LABEL_REVIEWER",
        "security_evidence_verified": True,
        "licence_revision_verified": True,
        "roles_verified": True,
        "ambiguity_state": "RESOLVED",
        "ranking_output_available": False,
        "fixing_diff_available": True,
        "decision": "ACCEPT",
        "corrections": [],
    }
    payload.update(changes)
    return make_record("natural-group-review-v1", payload)


def test_unapproved_fetch_is_blocked() -> None:
    with pytest.raises(PolicyError, match="UNAPPROVED"):
        assert_acquisition_authorised(_proposal(), _decision(approved=False))


def test_inert_acquisition_plan_disables_active_git_features() -> None:
    plan = acquisition_plan(
        _proposal(),
        _decision(),
        bare_repository="private/bare.git",
        empty_hooks_directory="private/empty-hooks",
        isolated_config_root="private/isolated-config",
    )
    fetch = plan["commands"][1]
    rendered = " ".join(fetch)
    assert "--no-recurse-submodules" in fetch
    assert "--depth=2" in fetch
    assert "core.hooksPath=private/empty-hooks" in fetch
    assert "filter.lfs.smudge=" in fetch
    assert "protocol.ext.allow=never" in fetch
    assert plan["environment"]["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert plan["repository_code_execution"] is False
    assert not any(word in rendered for word in ("checkout", "submodule update", "build", "test"))


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/example/alpha.git",
        "https://user@github.com/example/alpha.git",
        "https://github.com/example/alpha.git?ref=main",
        "https://example.invalid/example/alpha.git",
        "https://github.com/example/alpha/extra.git",
    ],
)
def test_noncanonical_or_credentialed_upstream_is_rejected(value: str) -> None:
    with pytest.raises(PolicyError):
        canonical_upstream_url(value)


def test_remote_includes_and_repository_git_configuration_are_rejected() -> None:
    with pytest.raises(PolicyError, match="REMOTE_GIT_CONFIGURATION"):
        reject_remote_git_configuration({"include.path": "https://example.invalid/config"})
    with pytest.raises(PolicyError, match="REMOTE_GIT_CONFIGURATION"):
        reject_remote_git_configuration({"core.sshCommand": "repo-controlled-helper"})


@pytest.mark.parametrize(
    "entry",
    [
        TreeEntry("100644", "blob", "a" * 40, "../escape.py", 1),
        TreeEntry("100644", "blob", "a" * 40, "AUX.txt", 1),
        TreeEntry("100644", "blob", "a" * 40, "src\\escape.py", 1),
    ],
)
def test_unsafe_and_nonportable_repository_paths_are_rejected(entry: TreeEntry) -> None:
    with pytest.raises(PolicyError, match="UNSAFE"):
        scan_tree_entries([entry])


def test_symlink_is_inert_and_special_file_handling_fails_closed() -> None:
    scan = scan_tree_entries([TreeEntry("120000", "blob", "a" * 40, "link", 4)])
    assert scan["regular_file_count"] == 0
    assert scan["inert_symlinks"] == [{"path": "link", "object_id": "a" * 40}]
    with pytest.raises(PolicyError, match="SPECIAL_FILE"):
        scan_tree_entries([TreeEntry("040000", "tree", "a" * 40, "device", None)])


def test_submodule_is_retained_as_inert_reference_not_materialised() -> None:
    scan = scan_tree_entries(
        [
            TreeEntry("160000", "commit", "a" * 40, "vendor/reference", None),
            TreeEntry("100644", "blob", "b" * 40, "src/main.py", 3),
        ]
    )
    assert scan["regular_file_count"] == 1
    assert scan["inert_gitlinks"] == [{"path": "vendor/reference", "object_id": "a" * 40}]


def test_excessive_count_file_size_and_total_size_are_rejected() -> None:
    entries = [
        TreeEntry("100644", "blob", f"{number + 1:040x}", f"src/{number}.py", 2)
        for number in range(3)
    ]
    with pytest.raises(PolicyError, match="SIZE_OR_COUNT"):
        scan_tree_entries(entries, limits=AcquisitionLimits(maximum_files=2))
    with pytest.raises(PolicyError, match="FILE_SIZE"):
        scan_tree_entries(entries[:1], limits=AcquisitionLimits(maximum_file_bytes=1))
    with pytest.raises(PolicyError, match="SIZE_OR_COUNT"):
        scan_tree_entries(entries, limits=AcquisitionLimits(maximum_total_bytes=5))


def test_missing_mismatched_and_unapproved_licence_fails_closed() -> None:
    digest = sha256_bytes(LICENCE_TEXT.encode())
    verify_licence_evidence(
        text=LICENCE_TEXT,
        exact_revision=REVISION,
        expected_revision=REVISION,
        expected_identifier="MIT",
        expected_file_hash=digest,
    )
    with pytest.raises(PolicyError, match="LICENCE_REVISION_MISMATCH"):
        verify_licence_evidence(
            text=LICENCE_TEXT,
            exact_revision=PARENT,
            expected_revision=REVISION,
            expected_identifier="MIT",
            expected_file_hash=digest,
        )
    with pytest.raises(PolicyError, match="MISSING_OR_AMBIGUOUS"):
        verify_licence_evidence(
            text="No licence grant.",
            exact_revision=REVISION,
            expected_revision=REVISION,
            expected_identifier="MIT",
            expected_file_hash=sha256_bytes(b"No licence grant."),
        )


def test_primary_permissive_grant_can_precede_bundled_permissive_notices() -> None:
    from trace_eval.intake import detect_code_licence

    apache = "Apache License\nVersion 2.0\n"
    bundled_mit = "Permission is hereby granted, free of charge\n"
    assert detect_code_licence(apache + bundled_mit) == "Apache-2.0"
    with pytest.raises(PolicyError, match="COPYLEFT_OR_MIXED"):
        detect_code_licence(apache + bundled_mit + "\nGNU General Public License\n")


def test_rights_dimensions_are_separate_and_training_defaults_false() -> None:
    validate_rights_dimensions(_rights())
    with pytest.raises(PolicyError, match="TRAINING_ELIGIBILITY"):
        validate_rights_dimensions(
            _rights(
                future_training_use_reviewed=True,
                future_training_use_permitted=True,
            )
        )
    with pytest.raises(PolicyError, match="RIGHTS_OR_PROVENANCE"):
        validate_rights_dimensions(_rights(private_evaluation="UNKNOWN"))


def test_public_source_redistribution_is_not_inferred_from_private_evaluation() -> None:
    rights = _rights(source_redistribution="PRIVATE_ONLY_BY_PROJECT_POLICY")
    validate_rights_dimensions(rights)
    assert rights["payload"]["private_evaluation"] == "PERMITTED"
    assert rights["payload"]["source_redistribution"] == "PRIVATE_ONLY_BY_PROJECT_POLICY"


def test_receipt_binds_approval_revision_identity_licence_and_safety() -> None:
    verify_acquisition_receipt(_receipt(), proposal=_proposal(), decision=_decision())
    tampered = deepcopy(_receipt())
    tampered["payload"]["repository_code_executed"] = True
    tampered = make_record("acquisition-receipt-v1", tampered["payload"])
    with pytest.raises(PolicyError, match="ACQUISITION_RECEIPT_REJECTED"):
        verify_acquisition_receipt(tampered, proposal=_proposal(), decision=_decision())
    mismatched = deepcopy(_receipt())
    mismatched["payload"]["resolved_revision"] = PARENT
    mismatched = make_record("acquisition-receipt-v1", mismatched["payload"])
    with pytest.raises(PolicyError, match="ACQUISITION_RECEIPT_REJECTED"):
        verify_acquisition_receipt(mismatched, proposal=_proposal(), decision=_decision())


def test_revision_pairs_reject_duplicate_vulnerability_lineage() -> None:
    assert audit_revision_pairs([_pair(1), _pair(2)])["pair_count"] == 2
    with pytest.raises(PolicyError, match="DUPLICATE_VULNERABILITY_LINEAGE"):
        audit_revision_pairs(
            [
                _pair(1, lineage="vulnerability:same"),
                _pair(2, lineage="vulnerability:same"),
            ]
        )


def test_cue_ablation_does_not_inflate_natural_count_and_leakage_is_rejected() -> None:
    validate_finding_cue_profile(_cue())
    ablation = _cue(ablation=True)
    validate_finding_cue_profile(ablation)
    assert ablation["payload"]["counts_toward_natural_total"] is False
    with pytest.raises(PolicyError, match="FIXING_DIFF_LEAKAGE"):
        validate_finding_cue_profile(_cue(leaked=True))


def test_controlled_review_is_ranking_blind_and_fail_closed_on_ambiguity() -> None:
    validate_group_review(_review())
    with pytest.raises(PolicyError, match="RANKING_BLIND"):
        validate_group_review(_review(ranking_output_available=True))
    with pytest.raises(PolicyError, match="REVIEW_INCOMPLETE"):
        validate_group_review(_review(ambiguity_state="UNRESOLVED"))


def test_qualification_budget_can_be_consumed_exactly_once() -> None:
    budget = QualificationBudget("qualification-budget:test")
    consumed = budget.consume()
    assert consumed.consumed_runs == 1
    with pytest.raises(PolicyError, match="BUDGET_EXHAUSTED"):
        consumed.consume()


def test_pre_run_seal_requires_exact_unchanged_runtime_and_blindness() -> None:
    runtime_hash = "sha256:" + "9" * 64
    record = make_record(
        "pre-run-seal-v1",
        {
            "runtime_id": "skylark-lumi-trace:0.1.0",
            "runtime_artifact_hash": runtime_hash,
            "evaluator_id": "skylark-lumi-trace-eval:0.3.1",
            "registry_id": "registry:test",
            "split_manifest_id": "split:test",
            "metric_spec_id": "metric:test",
            "threshold_policy": {"status": "PREDECLARED"},
            "runner_blindness_verified": True,
            "qualification_budget_id": "qualification-budget:test",
            "sealed_artifact_hashes": [runtime_hash],
            "sealed_before_execution": True,
        },
    )
    verify_pre_run_seal(record, expected_runtime_hash=runtime_hash)
    with pytest.raises(PolicyError, match="PRE_RUN_SEAL_REJECTED"):
        verify_pre_run_seal(record, expected_runtime_hash="sha256:" + "8" * 64)


def test_threshold_is_decided_before_qualification_without_qualification_evidence() -> None:
    record = make_record(
        "natural-threshold-decision-v1",
        {
            "development_run_id": "run:development",
            "decision": "DECLINE",
            "thresholds": {},
            "integrity_floors": {"public_source_files": 0},
            "remediation_class": "MORE_NATURAL_DATA_REQUIRED",
            "qualification_authorised": False,
            "qualification_evidence_used": False,
            "decided_before_qualification": True,
        },
    )
    validate_threshold_decision(record)


def test_v031_closure_enforces_training_holdback_and_publication_stops() -> None:
    record = make_record(
        "v0.3.1-closure-v1",
        {
            "closure_state": "MORE_NATURAL_DATA_REQUIRED",
            "natural_corpus_state": "PILOT_INSUFFICIENT",
            "development_run": False,
            "qualification_run": False,
            "qualification_budget_consumed": 0,
            "holdback_opened": False,
            "trace_ir_state": "IR_FEASIBILITY_SUPPORTED_UNCHANGED",
            "training_recommendation": "DO_NOT_BEGIN_TRACE_001",
            "training_started": False,
            "weights_acquired": False,
            "publication_decision": "NO_GO_PENDING_USER_REVIEW",
            "evidence_ids": ["lumi-trace-v0.3-public-evidence:test"],
        },
    )
    enforce_publication_decision(record)
    unsafe = deepcopy(record)
    unsafe["payload"]["publication_decision"] = "GO"
    unsafe = make_record("v0.3.1-closure-v1", unsafe["payload"])
    with pytest.raises(PolicyError, match="STOP_GATE"):
        enforce_publication_decision(unsafe)
