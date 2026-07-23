# SPDX-License-Identifier: Apache-2.0
"""Inert, bounded Trace IR normalisation, ranking, and feasibility metrics."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .canonical import canonical_bytes
from .contracts import make_record, validate_record
from .errors import ContractError, PolicyError

MAX_EVENTS = 10_000
MAX_STRING = 4_096
MAX_DEPTH = 8
MAX_ITEMS = 100_000
EVENT_REFERENCE_FIELDS = {"actor", "process", "host", "account", "resource", "network"}
IR_LABEL_STATES = {"BENIGN", "SUSPICIOUS", "CONFIRMED"}
_REMOTE = re.compile(r"(?i)^(?:https?|ftp|file)://")
_TEMPLATE = re.compile(r"(?:\{\{|\$\{|\{%|<%)")
_SECRET = re.compile(
    r"(?i)(?:bearer\s+[a-z0-9._-]+|api[_-]?key\s*[:=]|password\s*[:=]|"
    r"private[_-]?key\s*[:=]|access[_-]?token\s*[:=])"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNAL_WEIGHTS = {
    "credential_access": 8,
    "external_network": 7,
    "process_spawn": 4,
    "file_read": 2,
    "authentication_failure": 1,
    "maintenance_approved": -8,
    "health_check": -6,
}


def _assert_inert(
    value: Any, *, depth: int = 0, counter: list[int] | None = None, path: str = "input"
) -> None:
    if depth > MAX_DEPTH:
        raise ContractError(f"{path} exceeds the maximum nesting depth")
    items = counter if counter is not None else [0]
    items[0] += 1
    if items[0] > MAX_ITEMS:
        raise ContractError("Trace IR input exceeds the maximum item count")
    if value is None or isinstance(value, bool | int | float):
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise ContractError(f"{path} contains an oversized string")
        if _REMOTE.search(value):
            raise PolicyError(f"{path} contains a remote reference")
        if _TEMPLATE.search(value):
            raise PolicyError(f"{path} contains a template or expression")
        if _SECRET.search(value):
            raise PolicyError(f"{path} contains secret-like material")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_inert(item, depth=depth + 1, counter=items, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{path} contains a non-string field")
            if key.casefold() in {
                "$ref",
                "include",
                "loader",
                "template",
                "expression",
                "command",
                "endpoint",
            }:
                raise PolicyError(f"{path} contains an executable or remote-control field")
            _assert_inert(item, depth=depth + 1, counter=items, path=f"{path}.{key}")
        return
    raise ContractError(f"{path} contains a non-JSON value")


def _exact_fields(value: dict[str, Any], expected: set[str], *, name: str) -> None:
    if set(value) != expected:
        raise ContractError(f"{name} fields are invalid")


def _validate_custody(provenance: Any, rights: Any) -> None:
    if not isinstance(provenance, dict) or not isinstance(rights, dict):
        raise ContractError("Trace IR provenance and rights must be objects")
    _exact_fields(provenance, {"origin", "artifact_hash"}, name="Trace IR provenance")
    _exact_fields(rights, {"basis", "redistribution"}, name="Trace IR rights")
    if (
        provenance["origin"] != "SKYLARK_AUTHORED_LAB"
        or not isinstance(provenance["artifact_hash"], str)
        or _SHA256.fullmatch(provenance["artifact_hash"]) is None
    ):
        raise PolicyError("Trace IR provenance is not an immutable owned lab artifact")
    if rights["basis"] != "AUTHORSHIP" or rights["redistribution"] not in {
        "PRIVATE_EVALUATION_ONLY",
        "PUBLIC_REDISTRIBUTION_PERMITTED",
    }:
        raise PolicyError("Trace IR rights are not approved")


def normalise_episode(document: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Convert one inert package into canonical event and episode records."""
    _assert_inert(document)
    _exact_fields(document, {"schema_version", "episode", "events"}, name="Trace IR package")
    if document["schema_version"] != "trace-ir-input-package-v1":
        raise ContractError("Trace IR input package version is unsupported")
    episode_input = document["episode"]
    events_input = document["events"]
    if not isinstance(episode_input, dict) or not isinstance(events_input, list):
        raise ContractError("Trace IR episode and events must be an object and array")
    _exact_fields(
        episode_input,
        {
            "episode_id",
            "scenario_family",
            "generator_lineage",
            "partition",
            "provenance",
            "rights",
        },
        name="Trace IR episode",
    )
    if episode_input["partition"] == "frozen_holdback":
        raise PolicyError("Trace IR frozen holdback is not selectable")
    if episode_input["partition"] not in {"construction", "development", "qualification"}:
        raise PolicyError("Trace IR partition is not authorised")
    _validate_custody(episode_input["provenance"], episode_input["rights"])
    if not events_input or len(events_input) > MAX_EVENTS:
        raise ContractError("Trace IR event count is outside the bounded range")
    event_records: list[dict[str, Any]] = []
    orders: set[int] = set()
    for event_input in events_input:
        if not isinstance(event_input, dict):
            raise ContractError("Trace IR event must be an object")
        _exact_fields(
            event_input,
            {
                "order",
                "source_type",
                "source_id",
                "action",
                "outcome",
                "references",
                "redaction_status",
                "provenance",
                "rights",
            },
            name="Trace IR event",
        )
        order = event_input["order"]
        if not isinstance(order, int) or isinstance(order, bool) or order < 0 or order in orders:
            raise ContractError("Trace IR event order must be unique and non-negative")
        orders.add(order)
        references = event_input["references"]
        if (
            not isinstance(references, dict)
            or not set(references).issubset(EVENT_REFERENCE_FIELDS)
            or any(not isinstance(value, str) or not value for value in references.values())
        ):
            raise ContractError("Trace IR event references are malformed")
        if event_input["redaction_status"] != "REDACTED_OR_SYNTHETIC":
            raise PolicyError("Trace IR event is not verified redacted or synthetic")
        _validate_custody(event_input["provenance"], event_input["rights"])
        event_records.append(
            make_record(
                "trace-ir-event-v1",
                {
                    "episode_id": episode_input["episode_id"],
                    **event_input,
                },
            )
        )
    event_records.sort(key=lambda record: (record["payload"]["order"], record["record_id"]))
    episode = make_record(
        "trace-ir-episode-v1",
        {
            **episode_input,
            "event_ids": [record["record_id"] for record in event_records],
        },
    )
    return episode, event_records


def validate_ir_label(record: dict[str, Any], episode: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    validate_record(episode)
    if record["schema_version"] != "trace-ir-label-v1":
        raise ContractError("Trace IR label has the wrong schema")
    payload = record["payload"]
    if payload["episode_id"] != episode["payload"]["episode_id"]:
        raise ContractError("Trace IR label and episode identities differ")
    if payload["label_state"] not in IR_LABEL_STATES:
        raise ContractError("Trace IR label state is invalid")
    event_ids = set(episode["payload"]["event_ids"])
    relevant = payload["relevant_event_ids"]
    if not isinstance(relevant, list) or not set(relevant).issubset(event_ids):
        raise ContractError("Trace IR label refers to an unknown event")
    if payload["label_state"] == "BENIGN" and relevant:
        raise ContractError("benign Trace IR label cannot declare relevant events")
    edges = payload["chain_edges"]
    if not isinstance(edges, list) or any(
        not isinstance(edge, list)
        or len(edge) != 2
        or edge[0] not in event_ids
        or edge[1] not in event_ids
        for edge in edges
    ):
        raise ContractError("Trace IR chain labels are malformed")
    reviews = payload["review_receipt_ids"]
    if not isinstance(reviews, list) or not reviews or not all(isinstance(x, str) for x in reviews):
        raise ContractError("Trace IR label has no controlled-review receipt")
    return record


def rank_episode(episode: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Rank evidence from bounded fields only; never execute or resolve event content."""
    validate_record(episode)
    if episode["schema_version"] != "trace-ir-episode-v1":
        raise ContractError("Trace IR ranking requires an episode record")
    expected_ids = episode["payload"]["event_ids"]
    if [record["record_id"] for record in events] != expected_ids:
        raise ContractError("Trace IR event order or membership differs from the episode")
    for event in events:
        validate_record(event)
        if event["schema_version"] != "trace-ir-event-v1":
            raise ContractError("Trace IR ranking received a non-event record")
    approved_actors = {
        event["payload"]["references"].get("actor")
        for event in events
        if event["payload"]["action"] == "maintenance_approved"
    }
    approved_actors.discard(None)
    scored: list[dict[str, Any]] = []
    for event in events:
        payload = event["payload"]
        action = payload["action"]
        score = _SIGNAL_WEIGHTS.get(action, 0)
        reasons: list[str] = []
        if action in _SIGNAL_WEIGHTS:
            reasons.append(f"ACTION_{action.upper()}")
        if payload["outcome"] == "SUCCESS" and score > 0:
            score += 2
            reasons.append("SUCCESSFUL_SECURITY_RELEVANT_ACTION")
        actor = payload["references"].get("actor")
        if actor in approved_actors and action != "maintenance_approved":
            score -= 8
            reasons.append("MATCHED_APPROVED_MAINTENANCE_CONTEXT")
        scored.append(
            {
                "event_id": event["record_id"],
                "order": payload["order"],
                "score": score,
                "reasons": sorted(reasons),
                "suspicious": score >= 7,
                "actor": actor,
            }
        )
    scored.sort(key=lambda item: (-item["score"], item["order"], item["event_id"]))
    ranked = [
        {
            "event_id": item["event_id"],
            "rank": rank,
            "score": item["score"],
            "reasons": item["reasons"],
            "suspicious": item["suspicious"],
        }
        for rank, item in enumerate(scored, 1)
    ]
    suspicious = sorted(
        (item for item in scored if item["suspicious"]),
        key=lambda item: (item["order"], item["event_id"]),
    )
    proposed_chain: list[list[str]] = []
    for left, right in zip(suspicious, suspicious[1:], strict=False):
        if left["actor"] is not None and left["actor"] == right["actor"]:
            proposed_chain.append([left["event_id"], right["event_id"]])
    disposition = "SUSPICIOUS" if suspicious else "INSUFFICIENT_EVIDENCE"
    return make_record(
        "trace-ir-result-v1",
        {
            "episode_id": episode["payload"]["episode_id"],
            "ranked_events": ranked,
            "proposed_chain": proposed_chain,
            "supporting_fields": ["action", "outcome", "references.actor", "order"],
            "missing_evidence": (
                [] if proposed_chain else ["controlled-reviewed multi-event causal support"]
            ),
            "disposition": disposition,
            "abstention_reason": (
                None if suspicious else "NO_EVENT_REACHED_DETERMINISTIC_RELEVANCE_FLOOR"
            ),
            "action_available": False,
        },
    )


def audit_generator_independence(episodes: list[dict[str, Any]]) -> dict[str, Any]:
    """Reject generator-lineage leakage between development and qualification."""
    seen: dict[str, str] = {}
    violations: list[dict[str, str]] = []
    for episode in episodes:
        validate_record(episode)
        if episode["schema_version"] != "trace-ir-episode-v1":
            raise ContractError("generator audit received a non-episode record")
        payload = episode["payload"]
        lineage = payload["generator_lineage"]
        partition = payload["partition"]
        previous = seen.get(lineage)
        if previous is not None and previous != partition:
            violations.append(
                {
                    "generator_lineage": lineage,
                    "first_partition": previous,
                    "second_partition": partition,
                }
            )
        seen[lineage] = partition
    if violations:
        raise PolicyError(f"Trace IR generator lineage crosses partitions: {violations}")
    return {"episodes": len(episodes), "violations": [], "disjoint": True}


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def score_ir_feasibility(
    rows: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    *,
    replay_results: list[dict[str, Any]] | None = None,
    resources: dict[str, int | float] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Score labelled episodes and issue a bounded feasibility decision."""
    event_tp = event_fp = event_fn = 0
    episode_tp = episode_fp = episode_fn = 0
    edge_tp = edge_fp = edge_fn = 0
    total_events = 0
    first_distances: list[int] = []
    families: dict[str, list[bool]] = defaultdict(list)
    result_ids: list[str] = []
    label_ids: list[str] = []
    for episode, label, result in rows:
        validate_ir_label(label, episode)
        validate_record(result)
        if result["schema_version"] != "trace-ir-result-v1":
            raise ContractError("Trace IR metrics received the wrong result schema")
        if result["payload"]["episode_id"] != episode["payload"]["episode_id"]:
            raise ContractError("Trace IR result and episode identities differ")
        result_ids.append(result["record_id"])
        label_ids.append(label["record_id"])
        truth = set(label["payload"]["relevant_event_ids"])
        predicted = {
            item["event_id"] for item in result["payload"]["ranked_events"] if item["suspicious"]
        }
        event_tp += len(truth & predicted)
        event_fp += len(predicted - truth)
        event_fn += len(truth - predicted)
        total_events += len(episode["payload"]["event_ids"])
        truth_positive = label["payload"]["label_state"] in {"SUSPICIOUS", "CONFIRMED"}
        predicted_positive = result["payload"]["disposition"] in {"SUSPICIOUS", "SUPPORTED"}
        episode_tp += int(truth_positive and predicted_positive)
        episode_fp += int(not truth_positive and predicted_positive)
        episode_fn += int(truth_positive and not predicted_positive)
        families[episode["payload"]["scenario_family"]].append(truth_positive == predicted_positive)
        truth_edges = {tuple(edge) for edge in label["payload"]["chain_edges"]}
        predicted_edges = {tuple(edge) for edge in result["payload"]["proposed_chain"]}
        edge_tp += len(truth_edges & predicted_edges)
        edge_fp += len(predicted_edges - truth_edges)
        edge_fn += len(truth_edges - predicted_edges)
        if truth:
            ranks = {item["event_id"]: item["rank"] for item in result["payload"]["ranked_events"]}
            first_distances.append(min(ranks[item] for item in truth if item in ranks) - 1)
    replay = replay_results if replay_results is not None else [row[2] for row in rows]
    replay_agreement = [row[2]["record_id"] for row in rows] == [
        item["record_id"] for item in replay
    ]
    metrics = make_record(
        "trace-ir-metrics-v1",
        {
            "episode_count": len(rows),
            "event_metrics": {
                "precision": _ratio(event_tp, event_tp + event_fp),
                "recall": _ratio(event_tp, event_tp + event_fn),
                "false_positives_per_10000": (
                    event_fp * 10_000 / total_events if total_events else None
                ),
                "first_relevant_event_distance": {
                    "count": len(first_distances),
                    "mean": (
                        sum(first_distances) / len(first_distances) if first_distances else None
                    ),
                },
            },
            "episode_metrics": {
                "precision": _ratio(episode_tp, episode_tp + episode_fp),
                "recall": _ratio(episode_tp, episode_tp + episode_fn),
                "benign_false_alert_rate": _ratio(
                    episode_fp,
                    sum(row[1]["payload"]["label_state"] == "BENIGN" for row in rows),
                ),
                "scenario_family_macro_accuracy": {
                    "families": len(families),
                    "mean": (
                        sum(sum(values) / len(values) for values in families.values())
                        / len(families)
                        if families
                        else None
                    ),
                },
            },
            "chain_metrics": {
                "precision": _ratio(edge_tp, edge_tp + edge_fp),
                "recall": _ratio(edge_tp, edge_tp + edge_fn),
                "completeness": _ratio(edge_tp, edge_tp + edge_fn),
            },
            "safety": {
                "injected_instruction_executions": 0,
                "remote_references_resolved": 0,
                "response_actions_available": 0,
                "secret_material_admitted": 0,
            },
            "replay": {
                "identity_agreement": replay_agreement,
                "result_ids": result_ids,
                "label_ids": label_ids,
            },
            "resources": resources or {},
        },
    )
    benign_false_alerts = metrics["payload"]["episode_metrics"]["benign_false_alert_rate"][
        "numerator"
    ]
    has_positive = any(
        label["payload"]["label_state"] in {"SUSPICIOUS", "CONFIRMED"} for _, label, _ in rows
    )
    has_benign = any(label["payload"]["label_state"] == "BENIGN" for _, label, _ in rows)
    supported = (
        has_positive
        and has_benign
        and benign_false_alerts == 0
        and replay_agreement
        and metrics["payload"]["safety"]["response_actions_available"] == 0
    )
    decision = make_record(
        "trace-ir-feasibility-decision-v1",
        {
            "lane_state": ("IR_FEASIBILITY_SUPPORTED" if supported else "IR_EVIDENCE_INSUFFICIENT"),
            "evidence_ids": [metrics["record_id"]],
            "live_integrations": False,
            "response_actions": False,
            "performance_claim": "OWNED_LAB_FIXTURE_FEASIBILITY_ONLY",
        },
    )
    canonical_bytes(metrics)
    return metrics, decision
