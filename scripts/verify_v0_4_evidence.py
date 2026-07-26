# SPDX-License-Identifier: Apache-2.0
"""Verify the disclosure-safe Lumi Trace V0.4 public evidence seal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
for source_path in (EVAL_SRC, ROOT):
    if str(source_path) not in sys.path:
        sys.path.insert(0, str(source_path))

from trace_eval.canonical import load_json, sha256_file, stable_id  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402

from scripts.seal_v0_4 import (  # noqa: E402
    EXPECTED_V032_SEAL,
    _assert_disclosure_safe,
)

EXPECTED = {
    "baseline-comparators.json",
    "closure-record.json",
    "corpus-assurance.json",
    "partition-assurance.json",
    "pilot-package.json",
    "public-boundary-review.json",
    "qualification-summary.json",
    "resource-summary.json",
    "seal-manifest.json",
    "starting-state.json",
    "trace-001-experiment.json",
    "training-readiness.json",
}
_CLOSURE_STATES = {
    "TRACE_001_VALIDATED / CONTROLLED_PILOT_READY",
    "DETERMINISTIC_GENERALISATION_QUALIFIED / CONTROLLED_PILOT_READY",
    "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION",
    "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE",
}


def verify(root: Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("V0.4 evidence root must be a regular directory")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != EXPECTED:
        raise ValueError("V0.4 evidence tree membership differs from the sealed contract")
    manifest = load_json(root / "seal-manifest.json")
    expected_id = stable_id(
        "lumi-trace-v0.4-public-evidence",
        {key: value for key, value in manifest.items() if key != "seal_id"},
    )
    if manifest.get("seal_id") != expected_id:
        raise ValueError("V0.4 evidence seal identity mismatch")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    if set(declared) != EXPECTED - {"seal-manifest.json"}:
        raise ValueError("V0.4 evidence artifact list is incomplete")
    for name, item in declared.items():
        path = root / name
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size_bytes"]:
            raise ValueError(f"V0.4 evidence artifact mismatch: {name}")
        value = load_json(path)
        verify_public_document(value)
        _assert_disclosure_safe(value)
    starting = load_json(root / "starting-state.json")
    corpus = load_json(root / "corpus-assurance.json")
    partitions = load_json(root / "partition-assurance.json")
    training = load_json(root / "training-readiness.json")
    trace = load_json(root / "trace-001-experiment.json")
    qualification = load_json(root / "qualification-summary.json")
    resources = load_json(root / "resource-summary.json")
    review = load_json(root / "public-boundary-review.json")
    closure = load_json(root / "closure-record.json")
    pilot = load_json(root / "pilot-package.json")
    if (
        starting["previous_public_evidence_seal"] != EXPECTED_V032_SEAL
        or starting["historical_v0_3_2_evidence_unchanged"] is not True
        or starting["spent_v0_3_2_qualification_used_for_development"] is not False
        or corpus["all_corpus_floors_passed"] is not True
        or corpus["cross_partition_family_count"] != 0
        or corpus["contains_case_identities"] is not False
        or corpus["contains_source_or_labels"] is not False
        or corpus["contains_private_paths"] is not False
        or partitions["family_disjoint"] is not True
        or partitions["qualification_runs_consumed"] != 1
        or partitions["qualification_used_for_tuning"] is not False
        or partitions["protected_holdback_opened"] is not False
        or qualification["maximum_runs"] != 1
        or qualification["consumed_runs"] != 1
        or qualification["remaining_runs"] != 0
        or qualification["used_for_tuning"] is not False
        or qualification["thresholds_changed_after_opening"] is not False
        or qualification["protected_holdback_opened"] is not False
        or qualification["group_count"] < 97
        or qualification["family_count"] < 8
        or qualification["matched_safe_control_count"] < 97
        or training["weights_downloaded"] is not False
        or training["external_model_or_tokenizer_used"] is not False
        or training["hosted_service_used"] is not False
        or training["protected_holdback_opened"] is not False
        or trace["weight_files_published"] is not False
        or trace["public_weight_release_authorised"] is not False
        or resources["networked_inference_runs"] != 0
        or resources["repository_controlled_code_executed"] is not False
        or review["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or review["weight_publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or any(value is not False for key, value in review.items() if key.endswith("_present"))
        or closure["qualification_budget_consumed"] != 1
        or closure["weight_files_published"] is not False
        or closure["protected_holdback_opened"] is not False
        or closure["public_release"] is not False
        or closure["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or closure["closure_state"] not in _CLOSURE_STATES
        or pilot["protected_holdback_opened"] is not False
        or pilot["customer_data"] != "LOCAL_EVALUATION_ONLY"
        or pilot["hosted_inference"] is not False
        or pilot["api_keys_required"] is not False
        or pilot["human_review_required"] is not True
    ):
        raise ValueError("V0.4 evidence or hard stops are not intact")
    trained = training["training_started"]
    if (
        trace["run"] is not trained
        or (trace["active_parameters"] > 0) is not trained
        or closure["training_run"] is not trained
        or (training["recommendation"] == "TRACE_001_EXECUTION_AUTHORISED") is not trained
    ):
        raise ValueError("V0.4 training evidence is inconsistent")
    passed = qualification["passed"]
    selected_kind = qualification["selected_candidate_kind"]
    if passed and selected_kind == "TRACE_001_LINEAR":
        expected_closure = "TRACE_001_VALIDATED / CONTROLLED_PILOT_READY"
    elif passed:
        expected_closure = "DETERMINISTIC_GENERALISATION_QUALIFIED / CONTROLLED_PILOT_READY"
    elif trained:
        expected_closure = "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE"
    else:
        expected_closure = "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION"
    if (
        closure["qualification_passed"] is not passed
        or (pilot["readiness"] == "CONTROLLED_PILOT_READY") is not passed
        or closure["closure_state"] != expected_closure
    ):
        raise ValueError("V0.4 qualification closure is inconsistent")
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
