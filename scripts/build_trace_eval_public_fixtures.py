# SPDX-License-Identifier: Apache-2.0
"""Build canonical Trace-Eval V0.2 registries from Skylark-owned public fixtures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.canonical import dump_json, sha256_file, stable_id  # noqa: E402
from trace_eval.contracts import make_record  # noqa: E402
from trace_eval.registry import write_registry  # noqa: E402

RUNTIME_SHA256 = "sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba"
REPOSITORY_ID = "repository:24e0f02418f391392143fdf102135b2d42124ab2b57a06c650771a82c2790dc1"
TREE_ID = "sha256:24e0f02418f391392143fdf102135b2d42124ab2b57a06c650771a82c2790dc1"


def group(
    *,
    group_id: str,
    finding: str,
    label_set_id: str,
    case_class: str,
    origin: str,
    rights_id: str,
    target_kind: str,
    review_receipt_ids: list[str],
) -> dict[str, object]:
    finding_hash = sha256_file(ROOT / finding)
    return make_record(
        "candidate-ranking-group-v1",
        {
            "group_id": group_id,
            "repository_id": REPOSITORY_ID,
            "finding_id": stable_id(
                "public-finding-input", {"path": finding, "sha256": finding_hash}
            ),
            "rights_id": rights_id,
            "split": "public_regression",
            "case_class": case_class,
            "origin": origin,
            "taxonomy": {
                "language": "shell",
                "cwe": "CWE-22",
                "finding_format": "manual",
                "target_kind": target_kind,
                "repository_size_band": "TINY",
                "origin": origin,
                "difficulty": "PUBLIC_SYNTHETIC_CONTROL",
            },
            "runner_inputs": {
                "repository": "tests/fixtures/demo-repository",
                "finding": finding,
                "finding_format": "manual",
            },
            "label_set_id": label_set_id,
            "repository_tree_id": TREE_ID,
            "exposure_state": "CONSTRUCTION_VISIBLE",
            "input_hashes": [TREE_ID, finding_hash],
            "label_method": "Skylark-authored constructed fixture source of truth",
            "accepted_target_semantics": "first accepted exact-kind target",
            "review_receipt_ids": review_receipt_ids,
            "correction_history": [],
        },
    )


def build(output: Path) -> None:
    fixture_files = [
        ROOT / "tests" / "fixtures" / "demo-repository" / relative
        for relative in ("LICENSE", "README.md", "src/archive.sh", "tests/reproduce.sh")
    ]
    rights = make_record(
        "repository-rights-manifest-v1",
        {
            "repository_id": REPOSITORY_ID,
            "tree_id": TREE_ID,
            "source": "Skylark.AI-authored synthetic repository",
            "acquisition_method": "versioned public fixture in noqt/Lumi-Trace",
            "licence": "Apache-2.0",
            "rights_basis": "Skylark.AI authorship and Apache-2.0 fixture licence",
            "redistribution_status": "PUBLIC_REDISTRIBUTION_PERMITTED",
            "review_status": "SKYLARK_AUTHORED",
            "lineage_id": "lineage:skylark-lumi-trace-demo-v1",
            "family_id": "family:skylark-public-synthetic-archive",
            "shared_history_root": "history:skylark-lumi-trace-demo-v1",
            "exposure_state": "CONSTRUCTION_VISIBLE",
            "governed_location": "tests/fixtures/demo-repository",
            "input_hashes": [sha256_file(path) for path in fixture_files],
            "content_fingerprints": [sha256_file(path) for path in fixture_files],
        },
    )
    construction_review = make_record(
        "controlled-review-receipt-v1",
        {
            "role": "LABEL_CONSTRUCTION_BLIND_PASS",
            "method": "Source-of-truth fixture inspection without Lumi Trace candidate output",
            "input_hashes": [sha256_file(path) for path in fixture_files],
            "decision": "TARGETS_CONSTRUCTED",
            "disagreements": [],
            "corrections": [],
        },
    )
    independent_pass = make_record(
        "controlled-review-receipt-v1",
        {
            "role": "CONTROLLED_REVIEW_BLIND_PASS",
            "method": "Separate sealed-input pass checking target and no-plan safety semantics",
            "input_hashes": [
                construction_review["record_id"],
                *[sha256_file(path) for path in fixture_files],
            ],
            "decision": "ACCEPTED_PUBLIC_SYNTHETIC_LABELS",
            "disagreements": [],
            "corrections": [],
        },
    )
    label_definitions = [
        ("public-label-exact-symbol", "trace-public-exact-symbol", "symbol", []),
        ("public-label-message-region", "trace-public-message-region", "region", []),
        (
            "public-label-hard-negative",
            "trace-public-hard-negative",
            "symbol",
            ["tests/reproduce.sh"],
        ),
    ]
    labels = []
    for label_id, group_id, kind, negatives in label_definitions:
        target: dict[str, object] = {"kind": kind, "path": "src/archive.sh"}
        if kind == "symbol":
            target["symbol"] = "unsafe_join"
        if kind == "region":
            target["region"] = {"start_line": 4, "end_line": 4}
        labels.append(
            make_record(
                "label-set-v1",
                {
                    "label_set_id": label_id,
                    "group_id": group_id,
                    "targets": [target],
                    "matching_rule": "FIRST_ACCEPTED_EXACT_KIND_WITH_ANY_LINE_OVERLAP",
                    "review_receipt_ids": [
                        construction_review["record_id"],
                        independent_pass["record_id"],
                    ],
                    "corrections": [],
                    "hard_negative_paths": negatives,
                    "reproduction": {
                        "plan_state": "INTENTIONALLY_ABSENT",
                        "expected_outcome": "INSUFFICIENT_EVIDENCE",
                    },
                },
            )
        )
    groups = [
        group(
            group_id="trace-public-exact-symbol",
            finding="tests/data/manual-finding.json",
            label_set_id="public-label-exact-symbol",
            case_class="positive",
            origin="constructed",
            rights_id=rights["record_id"],
            target_kind="symbol",
            review_receipt_ids=[construction_review["record_id"], independent_pass["record_id"]],
        ),
        group(
            group_id="trace-public-message-region",
            finding="eval/public-fixtures/inputs/message-only.json",
            label_set_id="public-label-message-region",
            case_class="safety_control",
            origin="transformed",
            rights_id=rights["record_id"],
            target_kind="region",
            review_receipt_ids=[construction_review["record_id"], independent_pass["record_id"]],
        ),
        group(
            group_id="trace-public-hard-negative",
            finding="eval/public-fixtures/inputs/constructed-hard-negative.json",
            label_set_id="public-label-hard-negative",
            case_class="hard_negative",
            origin="constructed",
            rights_id=rights["record_id"],
            target_kind="symbol",
            review_receipt_ids=[construction_review["record_id"], independent_pass["record_id"]],
        ),
    ]
    split = make_record(
        "split-manifest-v1",
        {
            "partitions": {
                "public_regression": [REPOSITORY_ID],
                "future_training_candidate": [],
                "development": [],
                "qualification": [],
                "frozen_holdback": [],
            },
            "repositories": {REPOSITORY_ID: "public_regression"},
            "locked": True,
            "independence_method": (
                "origin, tree, lineage, family, shared-history, and content-fingerprint audit"
            ),
        },
    )
    snapshot = make_record(
        "registry-snapshot-v1",
        {
            "repositories": [rights["record_id"]],
            "groups": [item["record_id"] for item in groups],
            "split_manifest_id": split["record_id"],
            "exposure_log_ids": [],
        },
    )
    metric = make_record(
        "metric-specification-v1",
        {
            "cutoffs": [1, 5, 10, 20],
            "k_max": 20,
            "region_overlap": "ANY_ONE_BASED_LINE_OVERLAP",
            "denominators": {
                "principal_recall": "all file-eligible scheduled groups",
                "conditional_recall": "labelled-target file-indexable groups",
                "symbol_recall": "symbol-eligible groups",
                "region_hit_rate": "region-eligible groups",
            },
            "aggregation": ["GROUP_MICRO", "REPOSITORY_MACRO"],
            "integrity_floors": {
                "unauthorised_access": 0,
                "holdback_exposure": 0,
                "false_confirmations": 0,
                "manifest_verification_rate": 1,
                "same_host_identity_rate": 1,
            },
        },
    )
    configuration = make_record(
        "evaluator-configuration-v1",
        {
            "runtime": {
                "release": "v0.1.0",
                "version": "0.1.0",
                "release_commit": "04bee651f6347ec3b4b5d3a941029ef8f6bfc48d",
                "source_revision": "8f7c235333ab7e270d6dce320481ebb28960a212",
                "artifact_sha256": RUNTIME_SHA256,
            },
            "mode": "public-fixture",
            "limits": {
                "case_timeout_seconds": 60,
                "subprocess_output_bytes": 1048576,
                "case_disk_bytes": 67108864,
                "file_count": 100000,
                "memory_bytes": 1073741824,
            },
            "offline": True,
            "k_max": 20,
            "metric_spec_id": metric["record_id"],
        },
    )
    output.mkdir(parents=True, exist_ok=True)
    write_registry(output / "runner-registry.json", [rights, split, snapshot, *groups])
    write_registry(output / "labels.json", [construction_review, independent_pass, *labels])
    dump_json(output / "metric-specification.json", metric)
    dump_json(output / "configuration.json", configuration)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "eval" / "public-fixtures" / "v0.2")
    arguments = parser.parse_args()
    build(arguments.output)
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
