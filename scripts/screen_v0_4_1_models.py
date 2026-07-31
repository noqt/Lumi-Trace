# SPDX-License-Identifier: Apache-2.0
"""Screen private V0.4.1 models on sealed engineering-development rankings."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from lumi_trace.canonical import load_json as product_load_json
from lumi_trace.learned_ranker import rank_with_model, verify_model_artifact
from lumi_trace.localization import (
    V041_EVIDENCE_RUNTIME_IDENTITY as RUNTIME_IDENTITY,
)
from lumi_trace.localization import (
    verify_raw_localization,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL_SRC = PROJECT_ROOT / "eval" / "src"
if str(EVAL_SRC) not in sys.path:
    sys.path.insert(0, str(EVAL_SRC))

from trace_eval.baselines import aggregate_v04, score_v04_group  # noqa: E402
from trace_eval.canonical import dump_json, load_json, stable_id  # noqa: E402
from trace_eval.errors import ContractError, PolicyError  # noqa: E402
from trace_eval.integrity_v041 import verify_scoring_labels  # noqa: E402

TIMESTAMP = "2026-07-26T00:00:00Z"
BASE_RANKER = "role-aware-sparse-v0.4.1.3"
MATERIAL_GAIN = 0.03
MAXIMUM_REGRESSION = 0.01


def _root(path: Path, drive: str) -> Path:
    resolved = path.resolve(strict=True)
    if resolved.drive.casefold() != drive.casefold() or not resolved.is_dir():
        raise ValueError(f"governed root must remain on {drive}")
    return resolved


def _raw_by_group(work_root: Path) -> dict[str, tuple[dict, dict]]:
    raw_root = work_root / "builder" / "raw" / "engineering-development" / BASE_RANKER
    request_root = work_root / "builder" / "requests" / "engineering-development"
    result: dict[str, tuple[dict, dict]] = {}
    for path in sorted(raw_root.glob("*.json")):
        raw = product_load_json(path)
        if raw.get("runtime_identity") != RUNTIME_IDENTITY:
            continue
        verify_raw_localization(raw)
        request_path = request_root / path.name
        if not request_path.is_file():
            raise ContractError("screening request is missing")
        group_token = path.name.split(".", 1)[0]
        if group_token in result:
            raise ContractError("multiple current base rankings exist for a group")
        result[group_token] = (raw, product_load_json(request_path))
    return result


def _metric_row(
    raw: dict,
    labels: dict,
    ranking: list[dict],
) -> tuple[dict, bool, bool, bool, bool]:
    inventory = raw["candidate_inventory"]
    target_paths = {item["path"] for item in labels["targets"]}
    target_symbols = {
        (item["path"], item["symbol"]) for item in labels["targets"] if item.get("symbol")
    }
    hard_paths = set(labels["hard_negative_paths"])
    file_ids = {item["candidate_id"] for item in inventory if item["path"] in target_paths}
    role_ids = {
        item["candidate_id"]
        for item in inventory
        if (item["path"], item.get("symbol")) in target_symbols
    }
    hard_ids = {item["candidate_id"] for item in inventory if item["path"] in hard_paths}
    row = score_v04_group(
        [{"candidate_id": item["candidate_id"]} for item in ranking],
        file_target_candidate_ids=file_ids,
        role_target_candidate_ids=role_ids,
        hard_negative_candidate_ids=hard_ids,
        family_id=labels["family_id"],
    )
    positions = {item["candidate_id"]: position for position, item in enumerate(ranking, 1)}
    first_role = min(
        (positions[item] for item in role_ids if item in positions),
        default=None,
    )
    return (
        row,
        bool(file_ids),
        bool(role_ids),
        bool(first_role is not None and first_role <= 5),
        bool(first_role is not None and first_role <= 10),
    )


def _aggregate(
    rows: list[tuple[dict, bool, bool, bool, bool]],
    *,
    scheduled: list[tuple[str, str, bool]],
) -> dict:
    by_group = {row[0]["group_token"]: row for row in rows}
    scored = []
    file_indexable = 0
    role_indexable = 0
    role5 = 0
    role10 = 0
    for group_token, family_id, has_hard_negative in scheduled:
        item = by_group.get(group_token)
        if item is None:
            scored.append(
                {
                    "family_id": family_id,
                    "candidate_count": 0,
                    "valid_attempt": False,
                    "target_indexable": False,
                    "file_recall_at_5": False,
                    "file_recall_at_10": False,
                    "file_recall_at_20": False,
                    "location_role_recall_at_20": False,
                    "reciprocal_rank": 0.0,
                    "no_relevant_candidate": True,
                    "has_hard_negative": has_hard_negative,
                    "hard_negative_outrank": has_hard_negative,
                    "wrong_location_role_top_one": False,
                    "disposition_emitted": False,
                    "false_supported_disposition": False,
                    "false_vulnerability_safe_control": False,
                    "unsafe_non_abstention": False,
                }
            )
            continue
        row, file_ok, role_ok, at5, at10 = item[1:]
        scored.append(row)
        file_indexable += file_ok
        role_indexable += role_ok
        role5 += at5
        role10 += at10
    aggregate = aggregate_v04(scored)
    denominator = len(scheduled)
    aggregate["file_target_indexability"] = file_indexable / denominator
    aggregate["role_target_indexability"] = role_indexable / denominator
    aggregate["location_role_correct_recall_at_5"] = role5 / denominator
    aggregate["location_role_correct_recall_at_10"] = role10 / denominator
    return aggregate


def screen(args: argparse.Namespace) -> dict:
    private_root = _root(args.private_root, "G:")
    work_root = _root(args.work_root, "F:")
    predecessor_root = _root(args.predecessor_root, "G:")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", args.run) is None:
        raise ValueError("run must be a lowercase safe token")
    partition = load_json(
        predecessor_root / "partitions" / "engineering-development" / "manifest-final.json"
    )
    cards = {
        card["record_id"]: card
        for path in sorted(
            (predecessor_root / "manifests" / "audit-cards" / "engineering-development").glob(
                "*.json"
            )
        )
        for card in [load_json(path)]
    }
    receipts = {
        receipt["group_audit_card_id"]: receipt
        for path in sorted(
            (predecessor_root / "runs" / "private" / "intake" / "engineering-development").glob(
                "*.json"
            )
        )
        for receipt in [load_json(path)]
    }
    scheduled = []
    for card_id in partition["audit_card_ids"]:
        card = cards[card_id]
        receipt = receipts[card_id]
        scheduled.append(
            (
                receipt["candidate_id"].split(":", 1)[1][:24],
                card["payload"]["family_id"],
                bool(receipt["hard_negative_paths"]),
            )
        )
    raw_by_group = _raw_by_group(work_root)
    model_paths = []
    for value in args.model:
        name, separator, raw_path = value.partition("=")
        if not separator or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name) is None:
            raise ValueError("--model must use safe-name=F:/path/model.json")
        path = Path(raw_path).resolve(strict=True)
        if path.drive.casefold() != "f:" or work_root not in path.parents:
            raise ValueError("screening model must remain under the F: work root")
        model_paths.append((name, path))
    results = []
    label_root = private_root / "scorer" / "labels" / "engineering-development"
    for name, path in model_paths:
        model = verify_model_artifact(product_load_json(path))
        rows = []
        for group_token, (raw, request) in sorted(raw_by_group.items()):
            label_path = label_root / f"{group_token}.json"
            if not label_path.is_file():
                continue
            labels = verify_scoring_labels(load_json(label_path))
            ranking = rank_with_model(
                request["finding"],
                raw["candidates"],
                model,
            )
            row = _metric_row(raw, labels, ranking)
            rows.append(
                (
                    {"group_token": group_token},
                    *row,
                )
            )
        metrics = _aggregate(rows, scheduled=scheduled)
        results.append(
            {
                "candidate_name": name,
                "model_artifact_id": model["artifact_id"],
                "active_parameters": model["active_parameters"],
                "artifact_size_bytes": path.stat().st_size,
                "metrics": metrics,
            }
        )
    reference = results[0]
    reference_metrics = reference["metrics"]
    material_challengers = []
    for candidate in results[1:]:
        metrics = candidate["metrics"]
        materially_better = (
            metrics["file_recall_at_5"] >= reference_metrics["file_recall_at_5"] + MATERIAL_GAIN
            or metrics["location_role_correct_recall_at_20"]
            >= reference_metrics["location_role_correct_recall_at_20"] + MATERIAL_GAIN
            or metrics["hard_negative_outrank"]
            <= reference_metrics["hard_negative_outrank"] - MATERIAL_GAIN
        )
        no_material_regression = (
            metrics["file_recall_at_20"]
            >= reference_metrics["file_recall_at_20"] - MAXIMUM_REGRESSION
            and metrics["location_role_correct_recall_at_20"]
            >= reference_metrics["location_role_correct_recall_at_20"] - MAXIMUM_REGRESSION
            and metrics["hard_negative_outrank"]
            <= reference_metrics["hard_negative_outrank"] + MAXIMUM_REGRESSION
            and metrics["wrong_location_role_top_one"]
            <= reference_metrics["wrong_location_role_top_one"] + MAXIMUM_REGRESSION
            and metrics["repository_family_macro_recall_at_20"]
            >= reference_metrics["repository_family_macro_recall_at_20"] - MAXIMUM_REGRESSION
        )
        if materially_better and no_material_regression:
            material_challengers.append(candidate)
    selected = max(
        material_challengers,
        key=lambda item: (
            item["metrics"]["location_role_correct_recall_at_20"],
            item["metrics"]["file_recall_at_5"],
            -item["metrics"]["hard_negative_outrank"],
            -item["active_parameters"],
            item["model_artifact_id"],
        ),
        default=reference,
    )
    selection_reason = (
        "MATERIAL_DEVELOPMENT_GAIN_WITHOUT_MATERIAL_REGRESSION"
        if material_challengers
        else "NO_MATERIAL_CHALLENGER_GAIN_RETAIN_SMALLER_REFERENCE"
    )
    value = {
        "schema_version": "lumi-trace-v0.4.1-private-model-screen-v1",
        "run": args.run,
        "runtime_identity": RUNTIME_IDENTITY,
        "base_ranker": BASE_RANKER,
        "partition": "ENGINEERING_DEVELOPMENT",
        "scheduled_group_count": len(scheduled),
        "completed_base_ranking_count": len(raw_by_group),
        "evaluator_only_screen": True,
        "product_feature_and_rank_function_used": True,
        "model_selection_eligible": False,
        "qualification_eligible": False,
        "development_selection_policy": {
            "reference_candidate": reference["candidate_name"],
            "material_gain_minimum": MATERIAL_GAIN,
            "maximum_regression": MAXIMUM_REGRESSION,
            "fresh_model_selection_claim": False,
        },
        "development_recommendation": {
            "candidate_name": selected["candidate_name"],
            "model_artifact_id": selected["model_artifact_id"],
            "reason": selection_reason,
            "qualification_authorised": False,
        },
        "results": results,
        "created_at": TIMESTAMP,
    }
    value["screen_id"] = stable_id("v0.4.1-private-model-screen", value)
    output = private_root / "manifests" / f"model-screen-{args.run}.json"
    if output.exists() and load_json(output) != value:
        raise ContractError("append-only model screen differs")
    dump_json(output, value)
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--model", action="append", required=True)
    result.add_argument("--run", required=True)
    result.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--predecessor-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4"),
    )
    return result


def main() -> int:
    try:
        value = screen(parser().parse_args())
    except (ContractError, PolicyError, OSError, ValueError) as exc:
        print(f"screen-v0.4.1-models: {exc}", file=sys.stderr)
        return 2
    print(value["screen_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
