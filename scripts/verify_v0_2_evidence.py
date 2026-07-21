# SPDX-License-Identifier: Apache-2.0
"""Verify the exact public-safe Lumi Trace V0.2 evidence seal."""

from __future__ import annotations

import argparse
from pathlib import Path

from trace_eval.canonical import load_json, sha256_file, stable_id
from trace_eval.contracts import validate_record
from trace_eval.policy import verify_public_document

EXPECTED = {
    "baseline-provenance.json",
    "environment-summary.json",
    "public-boundary-review.json",
    "public-summary.json",
    "qualification-decision.json",
    "seal-manifest.json",
    "training-readiness-decision.json",
}


def verify(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("V0.2 evidence root must be a regular directory")
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != EXPECTED:
        raise ValueError("V0.2 evidence tree membership differs from the sealed contract")
    manifest = load_json(root / "seal-manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("V0.2 seal manifest must be an object")
    expected_id = stable_id(
        "lumi-trace-v0.2-public-evidence",
        {key: value for key, value in manifest.items() if key != "seal_id"},
    )
    if manifest.get("seal_id") != expected_id:
        raise ValueError("V0.2 evidence seal identity mismatch")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    if set(declared) != EXPECTED - {"seal-manifest.json"}:
        raise ValueError("V0.2 evidence artifact list is incomplete")
    for name, item in declared.items():
        path = root / name
        if sha256_file(path) != item["sha256"] or path.stat().st_size != item["size_bytes"]:
            raise ValueError(f"V0.2 evidence artifact mismatch: {name}")
        value = load_json(path)
        verify_public_document(value)
        if isinstance(value, dict) and "record_id" in value:
            validate_record(value)
    readiness = load_json(root / "training-readiness-decision.json")
    review = load_json(root / "public-boundary-review.json")
    if (
        readiness["payload"]["recommendation"] != "DO_NOT_BEGIN_TRACE_001"
        or readiness["payload"]["training_started"] is not False
        or review["publication_decision"] != "NO_GO_PENDING_USER_REVIEW"
    ):
        raise ValueError("V0.2 stop gates are not intact")
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
