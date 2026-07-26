# SPDX-License-Identifier: Apache-2.0
"""Bounded, deterministic product support for a local learned ranker.

The artifact is a JSON-only sparse integer linear model.  This module contains
no training entry point, network path, tokenizer, remote code, or executable
serialization format.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .canonical import stable_id
from .errors import InputError, IntegrityError

MODEL_SCHEMA = "lumi-trace-localization-linear-ranker-v0.4.1"
FEATURE_CONTRACT = "label-blind-hashed-role-features-v0.4.1.1"
ALGORITHM = "FAMILY_BALANCED_PAIRWISE_INTEGER_PERCEPTRON"
DIMENSIONS = 16_384
BASE_RANKER = "role-aware-sparse-v0.4.1.3"
LEARNED_RANKER = "learned-role-hybrid-v0.4.1.3"
LEARNED_SUPPORT = 1_000
LEARNED_MULTIPLIER = 8

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]{1,63}")
_COMPONENT_SCALES = {
    "BM25": 1250,
    "PATH": 1050,
    "BASENAME": 1550,
    "SYMBOL": 2200,
    "CONTENT": 375,
    "DESCRIPTION": 275,
    "DANGEROUS_CONTEXT": 700,
    "SYMBOL_CANDIDATE": 750,
    "ROLE": 1300,
    "PATH_DEPTH": 45,
    "REPORTED_PATH": 100_000,
    "REPORTED_SYMBOL": 80_000,
}
_CATEGORY_TRIGGERS = {
    "AUTHORIZATION": {
        "access",
        "auth",
        "authentication",
        "authorization",
        "authorisation",
        "credential",
        "permission",
        "privilege",
        "unauthenticated",
        "unauthorized",
        "unauthorised",
    },
    "XSS": {"cross", "html", "scripting", "xss"},
    "CSRF": {"csrf", "forgery"},
    "PATH_TRAVERSAL": {"directory", "path", "traversal"},
    "CODE_EXECUTION": {"command", "execution", "injection", "rce", "shell"},
    "DENIAL_OF_SERVICE": {"denial", "dos", "exhaustion", "resource"},
    "DESERIALIZATION": {"deserialize", "deserialization", "pickle", "yaml"},
    "NETWORK_REDIRECT": {"redirect", "ssrf"},
    "TRANSPORT_IDENTITY": {
        "certificate",
        "host",
        "key",
        "ssh",
        "ssl",
        "tls",
        "verification",
    },
    "ARCHIVE_UPLOAD": {"archive", "extract", "upload"},
}


def _tokens(values: str | Sequence[str]) -> list[str]:
    text = values if isinstance(values, str) else " ".join(values)
    return [match.group(0).casefold() for match in _TOKEN.finditer(text)]


def finding_tokens(finding: Mapping[str, Any]) -> list[str]:
    """Project only normalized-finding fields available to real inference."""

    values = [
        str(finding["rule"]["id"]),
        str(finding["rule"]["name"]),
        *[str(item) for item in finding["rule"].get("cwes", [])],
        *[str(item) for item in finding["rule"].get("tags", [])],
        str(finding["message"]["title"]),
        str(finding["message"]["text"]),
        *[str(item) for item in finding.get("keywords", [])],
    ]
    for location in finding.get("locations", []):
        values.append(str(location["path"]))
        if location.get("symbol"):
            values.append(str(location["symbol"]))
    return list(dict.fromkeys(_tokens(values)))[:128]


def semantic_categories(finding: Mapping[str, Any]) -> list[str]:
    observed = set(finding_tokens(finding))
    categories = [
        category for category, triggers in sorted(_CATEGORY_TRIGGERS.items()) if observed & triggers
    ]
    return categories or ["GENERAL"]


def _bucket(label: str) -> int:
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    return 64 + int.from_bytes(digest[:8], "big") % (DIMENSIONS - 64)


def _add(vector: dict[int, int], index: int, value: int = 1) -> None:
    if value:
        vector[index] = max(-64, min(64, vector.get(index, 0) + value))


def feature_vector(
    finding: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[tuple[int, int], ...]:
    """Build a sparse, bounded feature vector from inference-visible fields."""

    required = {
        "candidate_id",
        "kind",
        "path",
        "symbol",
        "region",
        "role",
        "integer_score",
        "score_components",
        "rank",
    }
    if (
        not isinstance(candidate, Mapping)
        or set(candidate) != required
        or candidate["kind"] not in {"file", "symbol"}
        or candidate["role"]
        not in {"implementation", "wrapper", "test", "fixture", "generated", "vendor"}
        or not isinstance(candidate["score_components"], Mapping)
    ):
        raise InputError("learned ranker candidate feature contract is invalid")
    vector: dict[int, int] = {0: 1}
    kind_index = {"symbol": 1, "file": 2}[str(candidate["kind"])]
    role_index = {
        "implementation": 3,
        "wrapper": 4,
        "test": 5,
        "fixture": 6,
        "generated": 7,
        "vendor": 8,
    }[str(candidate["role"])]
    _add(vector, kind_index)
    _add(vector, role_index)
    path_tokens = list(dict.fromkeys(_tokens(str(candidate["path"]))))[:24]
    symbol_tokens = list(dict.fromkeys(_tokens(str(candidate.get("symbol") or ""))))[:16]
    _add(vector, 9, max(0, 16 - len(str(candidate["path"]).split("/"))))
    _add(vector, 10, min(16, len(path_tokens)))
    _add(vector, 11, min(16, len(symbol_tokens)))
    _add(vector, 12, max(-32, min(32, int(candidate["integer_score"]) // 10_000)))
    for offset, (name, scale) in enumerate(sorted(_COMPONENT_SCALES.items()), start=16):
        value = candidate["score_components"].get(name, 0)
        if not isinstance(value, int) or isinstance(value, bool):
            raise InputError("learned ranker score component is invalid")
        _add(vector, offset, max(-32, min(32, round(value / scale))))
    query_tokens = set(finding_tokens(finding))
    categories = semantic_categories(finding)
    for token in path_tokens:
        _add(vector, _bucket(f"PATH:{token}"))
        if token in query_tokens:
            _add(vector, _bucket(f"QUERY_PATH:{token}"), 2)
        for category in categories:
            _add(vector, _bucket(f"{category}:PATH:{token}"))
    for token in symbol_tokens:
        _add(vector, _bucket(f"SYMBOL:{token}"))
        if token in query_tokens:
            _add(vector, _bucket(f"QUERY_SYMBOL:{token}"), 3)
        for category in categories:
            _add(vector, _bucket(f"{category}:SYMBOL:{token}"))
    for category in categories:
        _add(vector, _bucket(f"CATEGORY:{category}"))
        _add(vector, _bucket(f"{category}:ROLE:{candidate['role']}"))
        _add(vector, _bucket(f"{category}:KIND:{candidate['kind']}"))
    return tuple(sorted(vector.items()))


def verify_model_artifact(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "algorithm",
        "feature_contract",
        "dimensions",
        "base_ranker",
        "weights",
        "active_parameters",
        "training_manifest_id",
        "training_data_id",
        "training_config",
        "completed_epochs",
        "pair_updates",
        "family_balanced",
        "foundation_model",
        "tokenizer",
        "remote_code",
        "hosted_service",
        "cpu_inference",
        "artifact_id",
    }
    weights = value.get("weights")
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != MODEL_SCHEMA
        or value.get("algorithm") != ALGORITHM
        or value.get("feature_contract") != FEATURE_CONTRACT
        or value.get("dimensions") != DIMENSIONS
        or value.get("base_ranker") != BASE_RANKER
        or not isinstance(weights, list)
        or not 1 <= len(weights) <= DIMENSIONS
        or value.get("active_parameters") != len(weights)
        or not isinstance(value.get("training_manifest_id"), str)
        or not value["training_manifest_id"]
        or not isinstance(value.get("training_data_id"), str)
        or not value["training_data_id"]
        or not isinstance(value.get("training_config"), dict)
        or not isinstance(value.get("completed_epochs"), int)
        or not 1 <= value["completed_epochs"] <= 128
        or not isinstance(value.get("pair_updates"), int)
        or value["pair_updates"] < 1
        or value.get("family_balanced") is not True
        or value.get("foundation_model") is not None
        or value.get("tokenizer") is not None
        or value.get("remote_code") is not False
        or value.get("hosted_service") is not False
        or value.get("cpu_inference") is not True
    ):
        raise IntegrityError("learned ranker artifact contract is invalid")
    previous = -1
    for item in weights:
        if (
            not isinstance(item, dict)
            or set(item) != {"index", "weight"}
            or not isinstance(item["index"], int)
            or not 0 <= item["index"] < DIMENSIONS
            or item["index"] <= previous
            or not isinstance(item["weight"], int)
            or isinstance(item["weight"], bool)
            or not -1_000_000 <= item["weight"] <= 1_000_000
            or item["weight"] == 0
        ):
            raise IntegrityError("learned ranker artifact weight is invalid")
        previous = item["index"]
    expected = stable_id(
        "lumi-trace-localization-model",
        value,
        omit_keys=("artifact_id",),
    )
    if value.get("artifact_id") != expected:
        raise IntegrityError("learned ranker artifact identity mismatch")
    return dict(value)


def rank_with_model(
    finding: Mapping[str, Any],
    candidates: list[dict[str, Any]],
    artifact: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Hybrid-rank a deterministic support set with exact integer semantics."""

    verified = verify_model_artifact(artifact)
    if len(candidates) > LEARNED_SUPPORT:
        raise InputError("learned ranker support exceeds its trained candidate window")
    weights = {item["index"]: item["weight"] for item in verified["weights"]}
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        vector = feature_vector(finding, candidate)
        learned_score = sum(weights.get(index, 0) * value for index, value in vector)
        learned_contribution = learned_score * LEARNED_MULTIPLIER
        ranked.append(
            {
                **candidate,
                "integer_score": candidate["integer_score"] + learned_contribution,
                "score_components": {
                    **candidate["score_components"],
                    "LEARNED_INTEGER_LINEAR": learned_score,
                    "LEARNED_HYBRID_CONTRIBUTION": learned_contribution,
                },
            }
        )
    ranked.sort(
        key=lambda item: (
            -item["integer_score"],
            -item["score_components"].get("BM25", 0),
            item["path"],
            item["region"]["start_line"],
            item["candidate_id"],
        )
    )
    for position, candidate in enumerate(ranked, start=1):
        candidate["rank"] = position
    return ranked
