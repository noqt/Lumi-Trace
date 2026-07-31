# SPDX-License-Identifier: Apache-2.0
"""Label-separated scoring with explicit denominators and repository-macro aggregation."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .canonical import dump_json, load_json
from .contracts import make_record, validate_record
from .errors import ContractError
from .package import seal_package, verify_package
from .policy import FAILURE_CODES, verify_public_document
from .registry import load_registry, records_by_schema
from .runner import load_run_package

_DENOMINATORS = {
    "principal_recall": "all file-eligible scheduled groups",
    "conditional_recall": "labelled-target file-indexable groups",
    "symbol_recall": "symbol-eligible groups",
    "region_hit_rate": "region-eligible groups",
}


def _validate_metric_spec(metric_spec: dict[str, Any]) -> None:
    validate_record(metric_spec)
    if metric_spec["schema_version"] != "metric-specification-v1":
        raise ContractError("metric specification has the wrong schema")
    payload = metric_spec["payload"]
    if payload["denominators"] != _DENOMINATORS:
        raise ContractError("metric denominators differ from the locked V0.2 definitions")
    if payload["aggregation"] != ["GROUP_MICRO", "REPOSITORY_MACRO"]:
        raise ContractError("metric aggregation differs from the locked V0.2 definition")
    floors = payload["integrity_floors"]
    if any(
        floors.get(name) != value
        for name, value in {
            "unauthorised_access": 0,
            "holdback_exposure": 0,
            "false_confirmations": 0,
            "manifest_verification_rate": 1,
            "same_host_identity_rate": 1,
        }.items()
    ):
        raise ContractError("metric integrity floors were weakened")


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def _region_hit(candidate: dict[str, Any], target: dict[str, Any]) -> bool:
    if candidate.get("path") != target.get("path") or not isinstance(candidate.get("region"), dict):
        return False
    expected = target.get("region")
    if not isinstance(expected, dict):
        return False
    observed = candidate["region"]
    return int(observed["start_line"]) <= int(expected["end_line"]) and int(
        expected["start_line"]
    ) <= int(observed["end_line"])


def _first_rank(
    candidates: list[dict[str, Any]], targets: list[dict[str, Any]], kind: str
) -> int | None:
    matches: list[int] = []
    for candidate in candidates:
        for target in targets:
            matched = False
            if kind == "file":
                matched = candidate.get("path") == target.get("path")
            elif kind == "symbol" and target.get("kind") == "symbol":
                symbol = (
                    candidate.get("symbol") if isinstance(candidate.get("symbol"), dict) else {}
                )
                matched = (
                    candidate.get("path") == target.get("path")
                    and candidate.get("kind") == "symbol"
                    and target.get("symbol") in {symbol.get("name"), symbol.get("qualified_name")}
                )
            elif kind == "region" and target.get("kind") == "region":
                matched = _region_hit(candidate, target)
            if matched:
                matches.append(int(candidate["rank"]))
    return min(matches) if matches else None


def _target_hit(candidate: dict[str, Any], target: dict[str, Any]) -> bool:
    kind = target.get("kind")
    if kind == "file":
        return candidate.get("path") == target.get("path")
    if kind == "symbol":
        symbol = candidate.get("symbol") if isinstance(candidate.get("symbol"), dict) else {}
        return (
            candidate.get("path") == target.get("path")
            and candidate.get("kind") == "symbol"
            and target.get("symbol") in {symbol.get("name"), symbol.get("qualified_name")}
        )
    return kind == "region" and _region_hit(candidate, target)


def _target_coverage(
    candidates: list[dict[str, Any]], targets: list[dict[str, Any]]
) -> dict[str, int | float | None]:
    hits = sum(
        any(_target_hit(candidate, target) for candidate in candidates) for target in targets
    )
    return _ratio(hits, len(targets))


def _indexability(index: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
    files = {item["path"]: item for item in index.get("files", []) if isinstance(item, dict)}
    file_targets = [
        target for target in targets if target.get("kind") in {"file", "symbol", "region"}
    ]
    symbol_targets = [target for target in targets if target.get("kind") == "symbol"]
    file_indexable = bool(file_targets) and all(
        target.get("path") in files and files[target["path"]].get("content_indexed") is True
        for target in file_targets
    )
    symbol_indexable = bool(symbol_targets) and all(
        any(
            symbol.get("name") == target.get("symbol")
            or symbol.get("qualified_name") == target.get("symbol")
            for symbol in files.get(target.get("path"), {}).get("symbols", [])
            if isinstance(symbol, dict)
        )
        for target in symbol_targets
    )
    return {
        "file_eligible": bool(file_targets),
        "file_indexable": file_indexable,
        "symbol_eligible": bool(symbol_targets),
        "symbol_indexable": symbol_indexable,
        "region_eligible": any(target.get("kind") == "region" for target in targets),
    }


def _load_case_outputs(
    run_root: Path, attempt: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    suffix = attempt["payload"]["group_id"].rsplit(":", 1)[-1]
    package = run_root / "raw" / suffix / "evidence-package"
    candidates = load_json(package / "candidates.json")
    index = load_json(package / "repository-index.json")
    bundle = load_json(package / "evidence-bundle.json")
    if not all(isinstance(item, dict) for item in (candidates, index, bundle)):
        raise ContractError("Lumi Trace raw case output contains a non-object")
    return candidates, index, bundle


def verify_labels(labels: dict[str, Any]) -> dict[str, Any]:
    label_sets = records_by_schema(labels, "label-set-v1")
    reviews = records_by_schema(labels, "controlled-review-receipt-v1")
    review_ids = {record["record_id"] for record in reviews}
    semantic_ids: set[str] = set()
    for record in label_sets:
        validate_record(record)
        payload = record["payload"]
        if payload["label_set_id"] in semantic_ids:
            raise ContractError("label registry contains duplicate label_set_id")
        semantic_ids.add(payload["label_set_id"])
        if not payload["review_receipt_ids"] or not set(payload["review_receipt_ids"]).issubset(
            review_ids
        ):
            raise ContractError("label set has no valid controlled-review receipt")
        targets = payload["targets"]
        if not isinstance(targets, list) or any(
            not isinstance(target, dict) or target.get("kind") not in {"file", "symbol", "region"}
            for target in targets
        ):
            raise ContractError("label targets are malformed")
        corrections = payload["corrections"]
        if not isinstance(corrections, list) or any(
            not isinstance(item, dict) or set(item) != {"decision", "input_hash", "sequence"}
            for item in corrections
        ):
            raise ContractError("label correction history is malformed")
        if [item["sequence"] for item in corrections] != list(range(1, len(corrections) + 1)):
            raise ContractError("label corrections are not append-only and contiguous")
    return {"valid": True, "label_sets": len(label_sets), "reviews": len(reviews)}


def score_run(
    *,
    run_root: Path,
    registry_path: Path,
    labels_path: Path,
    metric_spec_path: Path,
    output: Path,
) -> dict[str, Any]:
    if output.exists():
        raise ContractError("scored output already exists")
    run_record, attempts, run_manifest = load_run_package(run_root)
    registry = load_registry(registry_path)
    labels = load_registry(labels_path)
    verify_labels(labels)
    metric_spec = load_json(metric_spec_path)
    if not isinstance(metric_spec, dict):
        raise ContractError("metric specification must be an object")
    _validate_metric_spec(metric_spec)
    groups = {
        record["record_id"]: record
        for record in records_by_schema(registry, "candidate-ranking-group-v1")
    }
    label_sets = {
        record["payload"]["label_set_id"]: record
        for record in records_by_schema(labels, "label-set-v1")
    }
    k_max = int(metric_spec["payload"]["k_max"])
    output.mkdir(parents=True)
    cases_root = output / "case-results"
    cases_root.mkdir()
    case_records: list[dict[str, Any]] = []
    for attempt in attempts:
        attempt_payload = attempt["payload"]
        group = groups.get(attempt_payload["group_id"])
        if group is None:
            raise ContractError("attempt references a group outside the sealed registry")
        label = label_sets.get(group["payload"]["label_set_id"])
        if label is None:
            raise ContractError("scheduled group has no sealed evaluator label")
        label_payload = label["payload"]
        targets = label_payload["targets"]
        failure_codes = list(attempt_payload["failure_codes"])
        ranking = {
            "file_first_rank": None,
            "symbol_first_rank": None,
            "region_first_rank": None,
            "hard_negative_first_rank": None,
            "hard_negative_outranked": False,
            "candidate_count": 0,
            "target_coverage": _ratio(0, len(targets)),
            "score_reason_counts": {},
        }
        indexability = {
            "file_eligible": bool(targets),
            "file_indexable": False,
            "symbol_eligible": False,
            "symbol_indexable": False,
            "region_eligible": False,
        }
        reproduction = {
            "expected": label_payload.get("reproduction", {}).get("expected_outcome"),
            "observed": None,
            "false_confirmation": False,
        }
        if attempt_payload["status"] == "COMPLETED":
            candidates_document, index, bundle = _load_case_outputs(run_root, attempt)
            candidates = [
                item
                for item in candidates_document.get("candidates", [])
                if isinstance(item, dict) and int(item.get("rank", k_max + 1)) <= k_max
            ]
            reason_counts = Counter(
                reason.get("code", "UNKNOWN")
                for candidate in candidates
                for reason in candidate.get("score_reasons", [])
                if isinstance(reason, dict)
            )
            indexability = _indexability(index, targets)
            ranking.update(
                {
                    "file_first_rank": _first_rank(candidates, targets, "file"),
                    "symbol_first_rank": _first_rank(candidates, targets, "symbol"),
                    "region_first_rank": _first_rank(candidates, targets, "region"),
                    "candidate_count": len(candidates),
                    "target_coverage": _target_coverage(candidates, targets),
                    "score_reason_counts": dict(sorted(reason_counts.items())),
                }
            )
            negatives = set(label_payload.get("hard_negative_paths", []))
            negative_ranks = [
                int(item["rank"]) for item in candidates if item.get("path") in negatives
            ]
            ranking["hard_negative_first_rank"] = min(negative_ranks) if negative_ranks else None
            relevant = ranking["file_first_rank"]
            ranking["hard_negative_outranked"] = bool(
                negative_ranks and (relevant is None or min(negative_ranks) < relevant)
            )
            outcome = bundle.get("classification", {}).get("outcome")
            reproduction["observed"] = outcome
            reproduction["false_confirmation"] = (
                outcome == "CONFIRMED" and reproduction["expected"] != "CONFIRMED"
            )
            if reproduction["false_confirmation"]:
                failure_codes.append("FALSE_CONFIRMATION")
            if indexability["file_eligible"] and not indexability["file_indexable"]:
                failure_codes.append("TARGET_NOT_INDEXABLE")
            elif indexability["file_eligible"] and ranking["file_first_rank"] is None:
                failure_codes.append("TARGET_NOT_GENERATED")
            elif ranking["file_first_rank"] is not None and ranking["file_first_rank"] > k_max:
                failure_codes.append("TARGET_RANKED_BELOW_CUTOFF")
            if ranking["hard_negative_outranked"]:
                failure_codes.append("HARD_NEGATIVE_OUTRANKED_TARGET")
        failure_codes = sorted(set(failure_codes))
        if any(code not in FAILURE_CODES for code in failure_codes):
            raise ContractError("case result contains an unknown failure code")
        case = make_record(
            "case-result-v1",
            {
                "group_id": group["record_id"],
                "attempt_id": attempt["record_id"],
                "label_set_id": label["record_id"],
                "indexability": indexability,
                "ranking": ranking,
                "reproduction": reproduction,
                "failure_codes": failure_codes,
                "repository_id": group["payload"]["repository_id"],
                "taxonomy": group["payload"]["taxonomy"],
                "case_class": group["payload"]["case_class"],
                "stage": attempt_payload["stage"],
            },
            observations={
                "attempt": attempt.get("observations", {}),
                "runtime_telemetry": bundle.get("telemetry", {})
                if attempt_payload["status"] == "COMPLETED"
                else {},
            },
        )
        case_records.append(case)
        dump_json(cases_root / f"{case['record_id'].rsplit(':', 1)[-1]}.json", case)
    aggregate = aggregate_metrics(case_records, metric_spec, run_record["payload"]["run_id"])
    dump_json(output / "aggregate-metrics.json", aggregate)
    dump_json(output / "metric-specification.json", metric_spec)
    resource_summary = {
        "schema_version": "trace-eval-resource-summary-v1",
        "run_id": run_record["payload"]["run_id"],
        "identity_excluded": True,
        "groups": [
            {
                "group_id": case["payload"]["group_id"],
                "attempt": case.get("observations", {}).get("attempt", {}),
                "runtime_telemetry": case.get("observations", {}).get("runtime_telemetry", {}),
            }
            for case in sorted(case_records, key=lambda item: item["record_id"])
        ],
    }
    dump_json(output / "resource-summary.json", resource_summary)
    report = {
        "schema_version": "trace-eval-public-summary-v1",
        "run_id": run_record["payload"]["run_id"],
        "run_package_id": run_manifest["package_id"],
        "aggregate_id": aggregate["record_id"],
        "group_count": len(case_records),
        "micro": aggregate["payload"]["micro"],
        "repository_macro": aggregate["payload"]["repository_macro"],
        "failure_counts": aggregate["payload"]["failures"],
        "controlled_review": True,
    }
    verify_public_document(report)
    dump_json(output / "public-summary.json", report)
    manifest = seal_package(output)
    return {"aggregate": aggregate, "manifest": manifest, "cases": case_records}


def aggregate_metrics(
    cases: list[dict[str, Any]], metric_spec: dict[str, Any], run_id: str
) -> dict[str, Any]:
    _validate_metric_spec(metric_spec)
    cases = sorted(cases, key=lambda case: case["record_id"])
    cutoffs = [int(value) for value in metric_spec["payload"]["cutoffs"]]
    if cutoffs != sorted(set(cutoffs)) or cutoffs[-1] != int(metric_spec["payload"]["k_max"]):
        raise ContractError("metric cutoffs must be unique, sorted, and end at K_max")
    payloads = [validate_record(case)["payload"] for case in cases]
    file_eligible = [item for item in payloads if item["indexability"]["file_eligible"]]
    file_indexable = [item for item in file_eligible if item["indexability"]["file_indexable"]]
    symbol_eligible = [item for item in payloads if item["indexability"]["symbol_eligible"]]
    region_eligible = [item for item in payloads if item["indexability"]["region_eligible"]]
    hard_negatives = [item for item in payloads if item["case_class"] == "hard_negative"]
    ranks = [item["ranking"]["file_first_rank"] for item in file_eligible]
    rank_distribution = Counter(str(rank) if rank is not None else "NONE" for rank in ranks)
    target_hits = sum(item["ranking"]["target_coverage"]["numerator"] for item in payloads)
    target_total = sum(item["ranking"]["target_coverage"]["denominator"] for item in payloads)
    reproduction_eligible = [
        item for item in payloads if item["reproduction"]["expected"] is not None
    ]
    reproductions_agree = sum(
        item["reproduction"]["observed"] == item["reproduction"]["expected"]
        for item in reproduction_eligible
    )
    safe_abstentions = sum(
        item["reproduction"]["expected"] != "CONFIRMED"
        and item["reproduction"]["observed"] in {"UNSUPPORTED", "INSUFFICIENT_EVIDENCE"}
        for item in reproduction_eligible
    )
    reason_counts = Counter(
        reason
        for item in payloads
        for reason, count in item["ranking"]["score_reason_counts"].items()
        for _ in range(count)
    )
    micro: dict[str, Any] = {
        "group_count": len(payloads),
        "snapshot_materialisation": _ratio(
            sum(item["stage"] == "COMPLETE" for item in payloads), len(payloads)
        ),
        "file_indexability": _ratio(len(file_indexable), len(file_eligible)),
        "file_recall_end_to_end": {},
        "file_recall_indexable_only": {},
        "symbol_recall": {},
        "region_hit_rate": {},
        "hard_negative_outrank": _ratio(
            sum(bool(item["ranking"]["hard_negative_outranked"]) for item in hard_negatives),
            len(hard_negatives),
        ),
        "mean_reciprocal_rank": {
            "sum_reciprocal_rank": sum(1 / rank for rank in ranks if rank is not None),
            "denominator": len(file_eligible),
            "mean": (
                sum(1 / rank for rank in ranks if rank is not None) / len(file_eligible)
                if file_eligible
                else None
            ),
        },
        "first_relevant_rank_distribution": dict(sorted(rank_distribution.items())),
        "no_relevant_candidate": _ratio(sum(rank is None for rank in ranks), len(ranks)),
        "accepted_target_coverage": _ratio(target_hits, target_total),
        "score_reason_distribution": dict(sorted(reason_counts.items())),
        "reproduction": {
            "agreement": _ratio(reproductions_agree, len(reproduction_eligible)),
            "safe_abstention": _ratio(safe_abstentions, len(reproduction_eligible)),
        },
        "false_confirmations": {
            "count": sum(bool(item["reproduction"]["false_confirmation"]) for item in payloads),
            "rate": _ratio(
                sum(bool(item["reproduction"]["false_confirmation"]) for item in payloads),
                len(payloads),
            ),
        },
    }
    for cutoff in cutoffs:
        key = str(cutoff)
        micro["file_recall_end_to_end"][key] = _ratio(
            sum(
                item["ranking"]["file_first_rank"] is not None
                and item["ranking"]["file_first_rank"] <= cutoff
                for item in file_eligible
            ),
            len(file_eligible),
        )
        micro["file_recall_indexable_only"][key] = _ratio(
            sum(
                item["ranking"]["file_first_rank"] is not None
                and item["ranking"]["file_first_rank"] <= cutoff
                for item in file_indexable
            ),
            len(file_indexable),
        )
        micro["symbol_recall"][key] = _ratio(
            sum(
                item["ranking"]["symbol_first_rank"] is not None
                and item["ranking"]["symbol_first_rank"] <= cutoff
                for item in symbol_eligible
            ),
            len(symbol_eligible),
        )
        micro["region_hit_rate"][key] = _ratio(
            sum(
                item["ranking"]["region_first_rank"] is not None
                and item["ranking"]["region_first_rank"] <= cutoff
                for item in region_eligible
            ),
            len(region_eligible),
        )
    by_repository: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in file_eligible:
        by_repository[item["repository_id"]].append(item)
    macro: dict[str, Any] = {"repository_count": len(by_repository), "file_recall": {}}
    for cutoff in cutoffs:
        per_repository = [
            sum(
                item["ranking"]["file_first_rank"] is not None
                and item["ranking"]["file_first_rank"] <= cutoff
                for item in values
            )
            / len(values)
            for values in by_repository.values()
        ]
        macro["file_recall"][str(cutoff)] = {
            "repositories": len(per_repository),
            "mean": sum(per_repository) / len(per_repository) if per_repository else None,
        }
    strata: dict[str, dict[str, int]] = defaultdict(lambda: {"groups": 0, "file_hits_at_k_max": 0})
    for item in payloads:
        taxonomy = item.get("taxonomy", {})
        for dimension in (
            "repository_family",
            "language",
            "cwe",
            "finding_format",
            "target_kind",
            "repository_size_band",
            "origin",
            "label_source",
            "hard_negative_family",
            "environment",
        ):
            key = f"{dimension}={taxonomy.get(dimension, 'UNKNOWN')}"
            strata[key]["groups"] += 1
            if (
                item["ranking"]["file_first_rank"] is not None
                and item["ranking"]["file_first_rank"] <= cutoffs[-1]
            ):
                strata[key]["file_hits_at_k_max"] += 1
    failures = dict(
        sorted(Counter(code for item in payloads for code in item["failure_codes"]).items())
    )
    resource_rows = [
        case.get("observations", {}) for case in cases if isinstance(case.get("observations"), dict)
    ]
    return make_record(
        "aggregate-metrics-v1",
        {
            "run_id": run_id,
            "metric_spec_id": metric_spec["record_id"],
            "case_result_ids": [case["record_id"] for case in cases],
            "micro": micro,
            "repository_macro": macro,
            "strata": dict(sorted(strata.items())),
            "failures": failures,
        },
        observations={"resources": resource_rows},
    )


def verify_scored_package(path: Path) -> dict[str, Any]:
    manifest = verify_package(path)
    aggregate = load_json(path / "aggregate-metrics.json")
    metric_spec = load_json(path / "metric-specification.json")
    if not isinstance(aggregate, dict) or not isinstance(metric_spec, dict):
        raise ContractError("aggregate metrics must be an object")
    validate_record(aggregate)
    validate_record(metric_spec)
    cases = []
    for case_path in sorted((path / "case-results").glob("*.json")):
        case = load_json(case_path)
        if not isinstance(case, dict):
            raise ContractError("case result must be an object")
        cases.append(validate_record(case))
    if sorted(aggregate["payload"]["case_result_ids"]) != sorted(
        case["record_id"] for case in cases
    ):
        raise ContractError("aggregate case identities do not match retained case results")
    recomputed = aggregate_metrics(cases, metric_spec, aggregate["payload"]["run_id"])
    if recomputed["record_id"] != aggregate["record_id"]:
        raise ContractError("aggregate metrics do not reproduce from retained case results")
    return manifest
