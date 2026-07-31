# SPDX-License-Identifier: Apache-2.0
"""Verify the aggregate-only Lumi Trace V0.4.1 evidence seal."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from lumi_trace.canonical import stable_id

EXPECTED_MEMBERS = {
    "adversarial-review.json",
    "closure-record.json",
    "continuation-package.json",
    "data-readiness.json",
    "development-summary.json",
    "integrity-remediation.json",
    "model-summary.json",
    "public-boundary-review.json",
    "qualification-readiness.json",
    "resource-summary.json",
    "runtime-integration.json",
    "seal-manifest.json",
    "starting-state.json",
}


class EvidenceError(ValueError):
    """V0.4.1 evidence verification failure."""


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path.name} is not a JSON object")
    return value


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def verify(root: Path) -> dict:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise EvidenceError("evidence root is not a directory")
    files = {path.name for path in resolved.iterdir() if path.is_file()}
    if files != EXPECTED_MEMBERS:
        raise EvidenceError("evidence membership differs from the sealed contract")
    manifest = _load(resolved / "seal-manifest.json")
    required = {
        "schema_version",
        "source_state_id",
        "members",
        "public_boundary_review_id",
        "closure_id",
        "seal_id",
    }
    if (
        set(manifest) != required
        or manifest.get("schema_version") != "lumi-trace-v0.4.1-public-evidence-seal-v1"
        or not isinstance(manifest.get("members"), list)
    ):
        raise EvidenceError("seal manifest contract is invalid")
    expected_paths = EXPECTED_MEMBERS - {"seal-manifest.json"}
    observed_paths = {item.get("path") for item in manifest["members"]}
    if observed_paths != expected_paths:
        raise EvidenceError("sealed member list is incomplete")
    for item in manifest["members"]:
        if set(item) != {"path", "sha256", "size_bytes"}:
            raise EvidenceError("sealed member entry is malformed")
        path = resolved / item["path"]
        if (
            not path.is_file()
            or _sha256(path) != item["sha256"]
            or path.stat().st_size != item["size_bytes"]
        ):
            raise EvidenceError(f"sealed member does not match: {item['path']}")
    expected_id = stable_id(
        "lumi-trace-v0.4.1-public-evidence",
        manifest,
        omit_keys=("seal_id",),
    )
    if manifest.get("seal_id") != expected_id:
        raise EvidenceError("seal identity mismatch")
    boundary = _load(resolved / "public-boundary-review.json")
    closure = _load(resolved / "closure-record.json")
    if (
        boundary.get("review_id") != manifest["public_boundary_review_id"]
        or closure.get("closure_id") != manifest["closure_id"]
        or boundary.get("decision") != "APPROVED_AGGREGATE_ONLY"
    ):
        raise EvidenceError("seal decision references do not verify")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify(args.evidence_root)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"verify-v0.4.1-evidence: {exc}", file=sys.stderr)
        return 2
    print(manifest["seal_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
