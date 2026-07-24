# SPDX-License-Identifier: Apache-2.0
"""Verify the disclosure-safe Lumi Trace V0.3.2 public evidence seal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402

EXPECTED = {
    "baseline-provenance.json",
    "capability-decision.json",
    "capability-development-aggregate.json",
    "closure-record.json",
    "contract-recovery.json",
    "corpus-and-rights-gap.json",
    "first-valid-baseline-aggregate.json",
    "public-boundary-review.json",
    "qualification-aggregate.json",
    "qualification-summary.json",
    "resource-summary.json",
    "seal-manifest.json",
    "trace-ir-boundary.json",
    "training-readiness-decision.json",
}
EXPECTED_V031_SEAL = (
    "lumi-trace-v0.3.1-public-evidence:"
    "e06658ab3ab0b6f1d9085f1d3f5d0c672f7d4283d5e554f0305452e8492f567f"
)
EXPECTED_V010_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
EXPECTED_V012_WHEEL = "sha256:6c674f15eb2d0178e3d0054d05dd733127981e640e8891fe37c135d394d42173"
EXPECTED_EVALUATOR = "sha256:1c597ae51e84a4f0b5f497f297ee3326c0e1adf7d8d624285a25a690927b5de8"


def verify(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("V0.3.2 evidence root must be a regular directory")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != EXPECTED:
        raise ValueError("V0.3.2 evidence tree membership differs from the sealed contract")
    manifest = load_json(root / "seal-manifest.json")
    expected_id = stable_id(
        "lumi-trace-v0.3.2-public-evidence",
        {key: value for key, value in manifest.items() if key != "seal_id"},
    )
    if manifest.get("seal_id") != expected_id:
        raise ValueError("V0.3.2 evidence seal identity mismatch")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    if set(declared) != EXPECTED - {"seal-manifest.json"}:
        raise ValueError("V0.3.2 evidence artifact list is incomplete")
    for name, item in declared.items():
        path = root / name
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size_bytes"]:
            raise ValueError(f"V0.3.2 evidence artifact mismatch: {name}")
        verify_public_document(load_json(path))

    provenance = load_json(root / "baseline-provenance.json")
    capability = load_json(root / "capability-decision.json")
    closure = load_json(root / "closure-record.json")
    contract = load_json(root / "contract-recovery.json")
    corpus = load_json(root / "corpus-and-rights-gap.json")
    development = load_json(root / "capability-development-aggregate.json")
    qualification = load_json(root / "qualification-summary.json")
    qualification_aggregate = load_json(root / "qualification-aggregate.json")
    resources = load_json(root / "resource-summary.json")
    readiness = load_json(root / "training-readiness-decision.json")
    review = load_json(root / "public-boundary-review.json")
    trace_ir = load_json(root / "trace-ir-boundary.json")

    if (
        provenance["previous_public_evidence_seal"] != EXPECTED_V031_SEAL
        or provenance["original_runtime_artifact_sha256"] != EXPECTED_V010_WHEEL
        or provenance["runtime_artifact_sha256"] != EXPECTED_V012_WHEEL
        or provenance["evaluator_artifact_sha256"] != EXPECTED_EVALUATOR
        or provenance["runtime_reproducible_builds"] is not True
        or provenance["evaluator_reproducible_builds"] is not True
        or provenance["development_replay_identity_agreement"] is not True
        or provenance["development_replay_semantic_agreement"] is not True
        or contract["score_reason_canonical_maximum"] != 20
        or contract["boundary_cases_tested"] != [0, 1, 8, 9, 10, 20, 21]
        or contract["producer_verifier_schema_agreement"] is not True
        or capability["all_development_attempts_completed"] is not True
        or capability["replay_identity_agreement"] is not True
        or capability["replay_semantic_agreement"] is not True
        or capability["qualification_evidence_used_for_development"] is not False
        or capability["case_specific_rules_added"] is not False
        or development["micro"]["group_count"] != 40
        or resources["development"]["attempt_count"] != 40
        or resources["development"]["completed_attempts"] != 40
        or resources["development"]["failed_attempts"] != 0
        or resources["diagnostic"]["resource_failure_count"] != 4
        or resources["declared_hardware_envelope"]["case_wall_limit_seconds"] != 600
        or resources["declared_hardware_envelope"]["maximum_index_json_items"] != 900_000
        or resources["networked_reproduction_runs"] != 0
        or resources["repository_controlled_code_executed"] is not False
        or corpus["evaluation_material_repurposed_for_training"] is not False
        or corpus["training_eligible_groups"] != 0
        or corpus["training_eligible_repository_families"] != 0
        or readiness["recommendation"] != "DO_NOT_BEGIN_TRACE_001"
        or readiness["all_entry_gates_satisfied"] is not False
        or readiness["training_started"] is not False
        or readiness["weights_downloaded"] is not False
        or readiness["weights_produced"] is not False
        or readiness["model_provider_used"] is not False
        or review["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or review["trace_001_decision"] != "NO_GO"
        or any(value is not False for key, value in review.items() if key.endswith("_present"))
        or trace_ir["feasibility_lane_run"] is not False
        or trace_ir["new_trace_ir_artifacts"] != 0
        or trace_ir["attack_detection_claim"] is not False
        or closure["trace_001_training"] is not False
        or closure["weights"] != 0
        or closure["holdback_opened"] is not False
        or closure["public_release"] is not False
        or closure["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
    ):
        raise ValueError("V0.3.2 evidence or stop gates are not intact")

    consumed = qualification["consumed_runs"]
    if qualification["maximum_runs"] != 1 or consumed not in {0, 1}:
        raise ValueError("V0.3.2 qualification budget is invalid")
    if (
        qualification["run"] != (consumed == 1)
        or qualification_aggregate["run"] != qualification["run"]
        or qualification["used_for_threshold_selection"] is not False
        or qualification["used_for_remediation"] is not False
        or qualification["holdback_opened"] is not False
        or closure["qualification_run"] != qualification["run"]
        or closure["qualification_budget_consumed"] != consumed
    ):
        raise ValueError("V0.3.2 qualification evidence is inconsistent")
    if qualification["run"]:
        expected_closure = (
            "CAPABILITY_QUALIFIED / PILOT_READY"
            if qualification["passed"]
            else "CAPABILITY_RECOVERED / CORPUS_SCALE_REQUIRED"
        )
        if (
            qualification_aggregate["aggregate"] is None
            or resources["qualification"]["attempt_count"] != 18
            or closure["qualification_passed"] != qualification["passed"]
            or closure["closure_state"] != expected_closure
        ):
            raise ValueError("V0.3.2 qualification result is inconsistent")
    elif (
        qualification["passed"] is not None
        or qualification_aggregate["aggregate"] is not None
        or resources["qualification"] is not None
        or closure["qualification_passed"] is not False
        or closure["closure_state"] != "CAPABILITY_RECOVERED / CORPUS_SCALE_REQUIRED"
    ):
        raise ValueError("V0.3.2 unused qualification state is inconsistent")
    if capability["qualification_authorised"] != qualification["run"]:
        raise ValueError("V0.3.2 development authorisation did not control qualification")
    if capability["performance_gates_passed"] is not capability["qualification_authorised"]:
        raise ValueError("V0.3.2 development gate state is inconsistent")
    json.dumps(manifest, allow_nan=False, sort_keys=True)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    manifest = verify(parser.parse_args().root)
    print(manifest["seal_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
