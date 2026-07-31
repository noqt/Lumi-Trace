# SPDX-License-Identifier: Apache-2.0
"""Write the append-only final V0.4 private status and work-ledger extension."""

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

from trace_eval.canonical import dump_json, load_json, stable_id  # noqa: E402
from trace_eval.errors import PolicyError  # noqa: E402

from scripts.run_v0_4_experiments import _active_final_authority_paths  # noqa: E402


def _require_private_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.drive.casefold() != "g:" or not resolved.is_dir():
        raise ValueError("governed private G: root is unavailable")
    return resolved


def _write_once(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise PolicyError(f"V0_4_APPEND_ONLY_STATUS_EXISTS:{path.name}")
    dump_json(path, value)


def _closure(
    qualification: dict[str, Any],
    qualification_lock: dict[str, Any],
    *,
    trained: bool,
) -> str:
    selected = qualification_lock["selected_candidate"]
    passed = qualification["selected_result"]["all_gates_passed"]
    if passed and selected["kind"] == "TRACE_001_LINEAR":
        return "TRACE_001_VALIDATED / CONTROLLED_PILOT_READY"
    if passed:
        return "DETERMINISTIC_GENERALISATION_QUALIFIED / CONTROLLED_PILOT_READY"
    if trained:
        return "NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE"
    return "CORPUS_ASSURANCE_IN_PROGRESS / CONTINUE_ACQUISITION"


def record_status(private_root: Path) -> dict[str, Any]:
    private_root = _require_private_root(private_root)
    corpus = load_json(private_root / "disclosure-safe" / "corpus-aggregate-final.json")
    _gates_path, readiness_path = _active_final_authority_paths(private_root)
    readiness = load_json(readiness_path)
    qualification_lock = load_json(private_root / "manifests" / "qualification-lock.json")
    qualification = load_json(private_root / "manifests" / "qualification-result.json")
    budget = load_json(private_root / "manifests" / "qualification-budget-after.json")
    bootstrap_ledger = load_json(private_root / "ledgers" / "work-ledger.json")
    trained = (private_root / "manifests" / "trace-001-training-receipt.json").is_file()
    closure_state = _closure(
        qualification,
        qualification_lock,
        trained=trained,
    )
    qualification_passed = bool(qualification["selected_result"]["all_gates_passed"])
    status = {
        "schema_version": "lumi-trace-v0.4-current-status-v1",
        "supersedes_status_id": load_json(private_root / "current-status.json")["status_id"],
        "state": closure_state,
        "completed": [
            "V0.3.2 source and public seal verification",
            "F:/G: storage-boundary verification",
            "V0.4 assurance contract implementation and regression tests",
            "governed item-level acquisition, audit, and terminalization",
            "family-disjoint corpus and partition sealing",
            "development baseline and metric locking",
            "Section 17 training-readiness decision",
            "grouped model-selection comparison",
            "single-use qualification consumption",
        ],
        "current_blockers": (
            []
            if qualification_passed
            else ["the selected candidate did not pass every locked qualification gate"]
        ),
        "next": (
            "Prepare the controlled customer-owned shadow pilot for user review."
            if qualification_passed
            else (
                "Retain the deterministic route and source a new independent "
                "qualification partition before any new claim."
            )
        ),
        "boundaries": {
            "training": "COMPLETED_PRIVATE_EXPERIMENT"
            if trained
            else "NOT_RUN_GATE_DECISION_RETAINED",
            "qualification": "CONSUMED_SINGLE_USE",
            "protected_holdback": "SEALED_UNOPENED",
            "publication": "NO_GO_PENDING_USER_REVIEW",
            "weights": "PRIVATE_NOT_PUBLICATION_AUTHORISED" if trained else "NONE",
        },
        "corpus_aggregate_id": corpus["aggregate_id"],
        "training_readiness_id": readiness["record_id"],
        "qualification_result_id": qualification["result_id"],
        "qualification_budget_id": budget["budget_id"],
        "training_started": trained,
        "weights_downloaded": False,
        "qualification_consumed": True,
        "holdback_opened": False,
    }
    status["status_id"] = stable_id("v0.4-current-status", status)
    ledger = {
        "schema_version": "lumi-trace-v0.4-work-ledger-extension-v1",
        "supersedes_ledger_id": bootstrap_ledger["ledger_id"],
        "entries": [
            {
                "sequence": 2,
                "event": "CORPUS_ASSURANCE_AND_PARTITION_SEAL",
                "decision": "PASSED",
                "evidence_ids": [
                    corpus["aggregate_id"],
                    corpus["partition_seal_id"],
                    corpus["training_manifest_id"],
                ],
                "boundaries_changed": False,
            },
            {
                "sequence": 3,
                "event": "DEVELOPMENT_AND_CANDIDATE_LOCK",
                "decision": "LOCKED",
                "evidence_ids": [
                    qualification_lock["candidate_lock_id"],
                ],
                "boundaries_changed": False,
            },
            {
                "sequence": 4,
                "event": "TRACE_001_ENTRY_GATE",
                "decision": readiness["payload"]["recommendation"],
                "evidence_ids": [readiness["record_id"]],
                "boundaries_changed": trained,
            },
            {
                "sequence": 5,
                "event": "SINGLE_USE_QUALIFICATION",
                "decision": "PASSED" if qualification_passed else "NOT_QUALIFIED",
                "evidence_ids": [
                    qualification_lock["qualification_lock_id"],
                    qualification["result_id"],
                    budget["budget_id"],
                ],
                "boundaries_changed": True,
            },
            {
                "sequence": 6,
                "event": "V0_4_CLOSURE",
                "decision": closure_state,
                "evidence_ids": [status["status_id"]],
                "boundaries_changed": False,
            },
        ],
    }
    ledger["ledger_id"] = stable_id("v0.4-work-ledger-extension", ledger)
    _write_once(
        private_root / "manifests" / "current-status-final.json",
        status,
    )
    _write_once(
        private_root / "ledgers" / "work-ledger-final.json",
        ledger,
    )
    return {
        "status_id": status["status_id"],
        "ledger_id": ledger["ledger_id"],
        "closure_state": closure_state,
        "training_started": trained,
        "qualification_consumed": True,
        "holdback_opened": False,
        "publication": "NO_GO_PENDING_USER_REVIEW",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    try:
        result = record_status(parser.parse_args().private_root)
    except (KeyError, OSError, PolicyError, ValueError) as exc:
        print(f"record-v0.4-status: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
