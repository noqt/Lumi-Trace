# SPDX-License-Identifier: Apache-2.0
"""Verify the disclosure-safe Lumi Trace V0.3.1 public evidence seal."""

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
from trace_eval.contracts import validate_record  # noqa: E402
from trace_eval.intake import enforce_publication_decision  # noqa: E402
from trace_eval.policy import verify_public_document  # noqa: E402

EXPECTED = {
    "baseline-provenance.json",
    "closure-record.json",
    "development-aggregate-metrics.json",
    "natural-corpus-summary.json",
    "public-boundary-review.json",
    "qualification-aggregate-metrics.json",
    "qualification-summary.json",
    "resource-summary.json",
    "seal-manifest.json",
    "threshold-decision.json",
    "trace-ir-boundary.json",
    "training-readiness-decision.json",
}
EXPECTED_V03_SEAL = (
    "lumi-trace-v0.3-public-evidence:"
    "a56044b38ff78687739a9d01ea32697c57f5b45d67063e8babf9931cc2da7b70"
)
EXPECTED_V01_WHEEL = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"


def verify(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("V0.3.1 evidence root must be a regular directory")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != EXPECTED:
        raise ValueError("V0.3.1 evidence tree membership differs from the sealed contract")
    manifest = load_json(root / "seal-manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("V0.3.1 seal manifest must be an object")
    expected_id = stable_id(
        "lumi-trace-v0.3.1-public-evidence",
        {key: value for key, value in manifest.items() if key != "seal_id"},
    )
    if manifest.get("seal_id") != expected_id:
        raise ValueError("V0.3.1 evidence seal identity mismatch")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    if set(declared) != EXPECTED - {"seal-manifest.json"}:
        raise ValueError("V0.3.1 evidence artifact list is incomplete")
    for name, item in declared.items():
        path = root / name
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size_bytes"]:
            raise ValueError(f"V0.3.1 evidence artifact mismatch: {name}")
        value = load_json(path)
        verify_public_document(value)
        if isinstance(value, dict) and "record_id" in value:
            validate_record(value)
    provenance = load_json(root / "baseline-provenance.json")
    corpus = load_json(root / "natural-corpus-summary.json")
    closure = load_json(root / "closure-record.json")
    threshold = load_json(root / "threshold-decision.json")
    qualification = load_json(root / "qualification-summary.json")
    readiness = load_json(root / "training-readiness-decision.json")
    review = load_json(root / "public-boundary-review.json")
    trace_ir = load_json(root / "trace-ir-boundary.json")
    resources = load_json(root / "resource-summary.json")
    enforce_publication_decision(closure)
    if (
        provenance["previous_public_evidence_seal"] != EXPECTED_V03_SEAL
        or provenance["runtime_artifact_sha256"] != EXPECTED_V01_WHEEL
        or provenance["runtime_changed"] is not False
        or provenance["raw_sealed_before_labels"] is not True
        or provenance["replay_identity_agreement"] is not True
        or provenance["replay_semantic_agreement"] is not True
        or not 50 <= corpus["accepted_groups"] <= 100
        or not 8 <= corpus["admitted_repository_families"] <= 12
        or corpus["future_training_use_permitted"] is not False
        or corpus["cross_partition_overlap_count"] != 0
        or threshold["qualification_evidence_used"] is not False
        or threshold["decided_before_qualification"] is not True
        or threshold["execution_integrity"]["all_attempts_completed"]
        != (
            resources["development"]["completed_attempts"]
            == resources["development"]["attempt_count"]
        )
        or sum(resources["development"]["failure_code_counts"].values())
        != resources["development"]["failed_attempts"]
        or qualification["maximum_runs"] != 1
        or qualification["consumed_runs"] not in {0, 1}
        or qualification["used_for_threshold_selection"] is not False
        or qualification["used_for_remediation"] is not False
        or readiness["payload"]["recommendation"] != "DO_NOT_BEGIN_TRACE_001"
        or readiness["payload"]["training_started"] is not False
        or readiness["payload"]["weights_downloaded"] is not False
        or review["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or any(value is not False for key, value in review.items() if key.endswith("_present"))
        or trace_ir["state"] != "IR_FEASIBILITY_SUPPORTED_UNCHANGED"
        or trace_ir["new_trace_ir_artifacts"] != 0
        or trace_ir["live_integrations"] is not False
        or trace_ir["response_actions"] is not False
        or trace_ir["attack_detection_claim"] is not False
        or resources["networked_reproduction_runs"] != 0
        or resources["repository_build_or_test_runs"] != 0
    ):
        raise ValueError("V0.3.1 evidence or stop gates are not intact")
    if threshold["execution_integrity"]["all_attempts_completed"] is False and (
        threshold["decision"] != "DECLINE"
        or threshold["qualification_authorised"] is not False
        or qualification["run"] is not False
        or qualification["consumed_runs"] != 0
        or closure["payload"]["closure_state"] != "NOT_QUALIFIED / REMEDIATION_REQUIRED"
    ):
        raise ValueError("V0.3.1 incomplete execution did not fail closed")
    json.dumps(manifest, allow_nan=False, sort_keys=True)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    manifest = verify(args.root)
    print(manifest["seal_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
