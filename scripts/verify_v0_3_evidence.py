# SPDX-License-Identifier: Apache-2.0
"""Verify the disclosure-safe Lumi Trace V0.3 public evidence seal."""

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
from trace_eval.policy import verify_public_document  # noqa: E402

EXPECTED = {
    "artifact-register.json",
    "baseline-provenance.json",
    "closure-record.json",
    "environment-summary.json",
    "micro-model-decision.json",
    "natural-corpus-summary.json",
    "programme-boundary.json",
    "public-boundary-review.json",
    "resource-deployment-envelope.json",
    "seal-manifest.json",
    "trace-code-metric-specification.json",
    "trace-ir-feasibility-decision.json",
    "trace-ir-summary.json",
    "training-readiness-decision.json",
}


def verify(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("V0.3 evidence root must be a regular directory")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != EXPECTED:
        raise ValueError("V0.3 evidence tree membership differs from the sealed contract")
    manifest = load_json(root / "seal-manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("V0.3 seal manifest must be an object")
    expected_id = stable_id(
        "lumi-trace-v0.3-public-evidence",
        {key: value for key, value in manifest.items() if key != "seal_id"},
    )
    if manifest.get("seal_id") != expected_id:
        raise ValueError("V0.3 evidence seal identity mismatch")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    if set(declared) != EXPECTED - {"seal-manifest.json"}:
        raise ValueError("V0.3 evidence artifact list is incomplete")
    for name, item in declared.items():
        path = root / name
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size_bytes"]:
            raise ValueError(f"V0.3 evidence artifact mismatch: {name}")
        value = load_json(path)
        verify_public_document(value)
        if isinstance(value, dict) and "record_id" in value:
            validate_record(value)
    closure = load_json(root / "closure-record.json")
    readiness = load_json(root / "training-readiness-decision.json")
    review = load_json(root / "public-boundary-review.json")
    ir_summary = load_json(root / "trace-ir-summary.json")
    if (
        closure["payload"]["programme_state"] != "DATA_GATES_PENDING"
        or closure["payload"]["qualification_run"] is not False
        or closure["payload"]["holdback_opened"] is not False
        or readiness["payload"]["recommendation"] != "DO_NOT_BEGIN_TRACE_001"
        or readiness["payload"]["training_started"] is not False
        or readiness["payload"]["weights_downloaded"] is not False
        or review["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
        or ir_summary["attack_detection_claim"] is not False
        or ir_summary["live_integrations"] is not False
        or ir_summary["response_actions_available"] != 0
    ):
        raise ValueError("V0.3 stop gates are not intact")
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
