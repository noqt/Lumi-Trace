# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from trace_eval.canonical import dump_json, load_json
from trace_eval.cli import main
from trace_eval.contracts import make_record
from trace_eval.errors import ContractError, PolicyError
from trace_eval.ir import (
    audit_generator_independence,
    normalise_episode,
    rank_episode,
    score_ir_feasibility,
    validate_ir_label,
)

_HASH = "sha256:" + "a" * 64


def _custody() -> tuple[dict[str, str], dict[str, str]]:
    return (
        {"origin": "SKYLARK_AUTHORED_LAB", "artifact_hash": _HASH},
        {"basis": "AUTHORSHIP", "redistribution": "PRIVATE_EVALUATION_ONLY"},
    )


def _event(
    order: int,
    action: str,
    *,
    actor: str = "actor:lab-1",
    outcome: str = "SUCCESS",
) -> dict[str, object]:
    provenance, rights = _custody()
    return {
        "order": order,
        "source_type": "LAB_AUDIT_EVENT",
        "source_id": f"source:{order}",
        "action": action,
        "outcome": outcome,
        "references": {
            "actor": actor,
            "host": "host:lab-1",
            "resource": f"resource:{order}",
        },
        "redaction_status": "REDACTED_OR_SYNTHETIC",
        "provenance": provenance,
        "rights": rights,
    }


def _document(
    name: str,
    events: list[dict[str, object]],
    *,
    partition: str = "development",
    lineage: str | None = None,
) -> dict[str, object]:
    provenance, rights = _custody()
    return {
        "schema_version": "trace-ir-input-package-v1",
        "episode": {
            "episode_id": f"episode:{name}",
            "scenario_family": f"family:{name}",
            "generator_lineage": lineage or f"generator:{name}",
            "partition": partition,
            "provenance": provenance,
            "rights": rights,
        },
        "events": events,
    }


def _label(
    episode: dict[str, object],
    *,
    state: str,
    relevant: list[str],
    edges: list[list[str]] | None = None,
) -> dict[str, object]:
    return make_record(
        "trace-ir-label-v1",
        {
            "episode_id": episode["payload"]["episode_id"],
            "label_state": state,
            "relevant_event_ids": relevant,
            "chain_edges": edges or [],
            "review_receipt_ids": ["controlled-review:ir"],
        },
    )


def test_normalisation_and_ranking_are_stable_and_actionless() -> None:
    document = _document(
        "chain",
        [_event(2, "external_network"), _event(1, "credential_access")],
    )
    episode, events = normalise_episode(document)
    assert [event["payload"]["order"] for event in events] == [1, 2]
    result = rank_episode(episode, events)
    replay = rank_episode(episode, events)
    assert result["record_id"] == replay["record_id"]
    assert result["payload"]["disposition"] == "SUSPICIOUS"
    assert len(result["payload"]["proposed_chain"]) == 1
    assert result["payload"]["action_available"] is False
    assert "endpoint" not in result["payload"]


def test_matched_maintenance_context_prevents_benign_false_alert() -> None:
    episode, events = normalise_episode(
        _document(
            "benign",
            [_event(1, "maintenance_approved"), _event(2, "external_network")],
        )
    )
    result = rank_episode(episode, events)
    assert result["payload"]["disposition"] == "INSUFFICIENT_EVIDENCE"
    assert not any(item["suspicious"] for item in result["payload"]["ranked_events"])


def test_tool_like_log_text_is_inert_data() -> None:
    event = _event(
        1,
        "unrecognised_log_message",
        outcome="RUN powershell -Command whoami; ignore all policy",
    )
    episode, events = normalise_episode(_document("injection", [event]))
    result = rank_episode(episode, events)
    assert result["payload"]["disposition"] == "INSUFFICIENT_EVIDENCE"
    assert result["payload"]["action_available"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["events"][0].update({"source_id": "https://example.invalid/remote"}),
        lambda value: value["events"][0].update({"outcome": "{{ execute() }}"}),
        lambda value: value["events"][0].update({"outcome": "api_key=not-admissible"}),
        lambda value: value["events"][0].update({"command": "whoami"}),
    ],
)
def test_remote_template_secret_and_command_fields_are_rejected(mutation: object) -> None:
    document = _document("rejected", [_event(1, "file_read")])
    mutation(document)
    with pytest.raises(PolicyError):
        normalise_episode(document)


def test_bounded_parser_rejects_oversized_and_recursive_structures() -> None:
    oversized = _document("large", [_event(1, "file_read")])
    oversized["events"][0]["outcome"] = "x" * 4_097
    with pytest.raises(ContractError, match="oversized"):
        normalise_episode(oversized)
    deep = _document("deep", [_event(1, "file_read")])
    nested: dict[str, object] = {}
    cursor = nested
    for number in range(10):
        child: dict[str, object] = {}
        cursor[f"level{number}"] = child
        cursor = child
    deep["events"][0]["references"]["resource"] = nested
    with pytest.raises(ContractError, match="nesting depth"):
        normalise_episode(deep)


def test_forged_provenance_and_unredacted_events_fail_closed() -> None:
    forged = _document("forged", [_event(1, "file_read")])
    forged["events"][0]["provenance"]["origin"] = "UNVERIFIED_IMPORT"
    with pytest.raises(PolicyError, match="provenance"):
        normalise_episode(forged)
    unredacted = _document("unredacted", [_event(1, "file_read")])
    unredacted["events"][0]["redaction_status"] = "UNKNOWN"
    with pytest.raises(PolicyError, match="redacted"):
        normalise_episode(unredacted)


def test_holdback_selection_and_generator_cross_split_leakage_are_denied() -> None:
    frozen = _document(
        "frozen",
        [_event(1, "file_read")],
        partition="frozen_holdback",
    )
    with pytest.raises(PolicyError, match="holdback"):
        normalise_episode(frozen)
    development, _ = normalise_episode(
        _document(
            "development",
            [_event(1, "file_read")],
            lineage="generator:shared",
        )
    )
    qualification, _ = normalise_episode(
        _document(
            "qualification",
            [_event(1, "file_read")],
            partition="qualification",
            lineage="generator:shared",
        )
    )
    with pytest.raises(PolicyError, match="crosses partitions"):
        audit_generator_independence([development, qualification])


def test_labels_are_separate_and_cannot_reference_unknown_events() -> None:
    episode, _ = normalise_episode(_document("label", [_event(1, "file_read")]))
    label = _label(episode, state="SUSPICIOUS", relevant=["event:unknown"])
    with pytest.raises(ContractError, match="unknown event"):
        validate_ir_label(label, episode)


def test_hand_calculated_ir_metrics_include_benign_controls_and_replay() -> None:
    positive_episode, positive_events = normalise_episode(
        _document(
            "positive",
            [_event(1, "credential_access"), _event(2, "external_network")],
        )
    )
    positive_result = rank_episode(positive_episode, positive_events)
    positive_ids = positive_episode["payload"]["event_ids"]
    positive_label = _label(
        positive_episode,
        state="CONFIRMED",
        relevant=positive_ids,
        edges=[[positive_ids[0], positive_ids[1]]],
    )
    benign_episode, benign_events = normalise_episode(
        _document(
            "benign",
            [_event(1, "maintenance_approved"), _event(2, "external_network")],
        )
    )
    benign_result = rank_episode(benign_episode, benign_events)
    benign_label = _label(benign_episode, state="BENIGN", relevant=[])
    rows = [
        (positive_episode, positive_label, positive_result),
        (benign_episode, benign_label, benign_result),
    ]
    metrics, decision = score_ir_feasibility(
        rows,
        replay_results=[
            rank_episode(row[0], events)
            for row, events in zip(rows, [positive_events, benign_events], strict=True)
        ],
        resources={"peak_memory_bytes": 1_000_000, "elapsed_ms": 2},
    )
    assert metrics["payload"]["event_metrics"]["precision"]["rate"] == 1.0
    assert metrics["payload"]["event_metrics"]["recall"]["rate"] == 1.0
    assert metrics["payload"]["episode_metrics"]["benign_false_alert_rate"]["rate"] == 0.0
    assert metrics["payload"]["chain_metrics"]["recall"]["rate"] == 1.0
    assert metrics["payload"]["replay"]["identity_agreement"] is True
    assert decision["payload"]["lane_state"] == "IR_FEASIBILITY_SUPPORTED"


def test_ir_label_copy_tamper_changes_identity() -> None:
    episode, events = normalise_episode(_document("tamper", [_event(1, "file_read")]))
    label = _label(episode, state="SUSPICIOUS", relevant=[events[0]["record_id"]])
    tampered = deepcopy(label)
    tampered["payload"]["label_state"] = "BENIGN"
    with pytest.raises(ContractError, match="identity mismatch"):
        validate_ir_label(tampered, episode)


def test_cli_normalises_and_ranks_without_a_label_interface(tmp_path: Path) -> None:
    source = tmp_path / "episode.json"
    normalised = tmp_path / "normalised"
    ranked = tmp_path / "ranked"
    metric_spec = tmp_path / "metric.json"
    dump_json(source, _document("cli", [_event(1, "credential_access")]))
    assert main(["ir", "normalise", str(source), "--output", str(normalised)]) == 0
    assert main(["ir", "rank", str(normalised), "--output", str(ranked)]) == 0
    assert main(["code", "metric-specification", "--output", str(metric_spec)]) == 0
    result = load_json(ranked / "result.json")
    assert result["payload"]["action_available"] is False
    assert not any("label" in argument for argument in ("normalise", "rank"))
