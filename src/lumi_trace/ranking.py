# SPDX-License-Identifier: Apache-2.0
"""Transparent deterministic candidate-retrieval baseline."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .canonical import stable_id
from .errors import IntegrityError
from .findings import validate_normalized_finding
from .indexing import tokenize, verify_repository_index
from .localization import (
    CANDIDATE_ALGORITHM as PRODUCT_CANDIDATE_ALGORITHM,
)
from .localization import (
    CANDIDATE_TRUNCATION_ABSTENTION,
    FINDING_GUIDED_SCORE_COMPONENTS,
    NO_SIGNAL_ABSTENTION,
    RUNTIME_IDENTITY,
    verify_raw_localization,
)
from .localization import DEFAULT_RANKER as PRODUCT_RANKING_ALGORITHM

RANKING_ALGORITHM = "deterministic-candidate-ranking-v2"
SUPPORTED_RANKING_ALGORITHMS = frozenset({RANKING_ALGORITHM, PRODUCT_RANKING_ALGORITHM})
SCORE_REASON_MATCH_LIMIT = 20
MAX_CANDIDATES_PER_PATH = 2
PRODUCT_ROLES = frozenset({"implementation", "wrapper", "test", "fixture", "generated", "vendor"})
QUERY_STOP_TERMS = {
    "advisory",
    "allow",
    "allows",
    "an",
    "and",
    "are",
    "arbitrary",
    "as",
    "at",
    "attack",
    "attacker",
    "be",
    "before",
    "by",
    "can",
    "code",
    "could",
    "corpus",
    "does",
    "execution",
    "for",
    "from",
    "has",
    "have",
    "if",
    "in",
    "into",
    "is",
    "issue",
    "it",
    "its",
    "may",
    "natural",
    "not",
    "of",
    "on",
    "or",
    "other",
    "potential",
    "possible",
    "public",
    "security",
    "that",
    "the",
    "their",
    "them",
    "then",
    "this",
    "to",
    "under",
    "used",
    "using",
    "vulnerability",
    "vulnerable",
    "when",
    "where",
    "which",
    "will",
    "with",
    "without",
}


def _terms(values: list[str]) -> set[str]:
    return {
        term
        for value in values
        for term in tokenize(value)
        if len(term) > 1 and term not in QUERY_STOP_TERMS
    }


def _query(finding: dict[str, object]) -> dict[str, object]:
    rule = finding["rule"]
    message = finding["message"]
    locations = finding.get("locations", [])
    identifier_values = [str(rule.get("id", ""))]
    identifier_values.extend(map(str, rule.get("cwes", [])))
    identifier_values.extend(map(str, rule.get("tags", [])))
    message_values = [
        str(rule.get("name", "")),
        str(message.get("title", "")),
        str(message.get("text", "")),
    ]
    message_values.extend(map(str, finding.get("keywords", [])))
    reported_paths: set[str] = set()
    reported_symbols: set[str] = set()
    regions: dict[str, list[dict[str, int]]] = {}
    for location in locations:
        path = str(location["path"])
        reported_paths.add(path)
        identifier_values.append(path)
        if location.get("symbol"):
            symbol = str(location["symbol"])
            reported_symbols.add(symbol.casefold())
            identifier_values.append(symbol)
        regions.setdefault(path, []).append(location["region"])
    return {
        "identifier_terms": _terms(identifier_values),
        "message_terms": _terms(message_values),
        "reported_paths": reported_paths,
        "reported_symbols": reported_symbols,
        "regions": regions,
    }


def _reason(code: str, points: int, matches: list[str] | None = None) -> dict[str, object]:
    value: dict[str, object] = {"code": code, "points": points}
    if matches:
        canonical_matches = sorted(set(matches))
        if len(canonical_matches) > SCORE_REASON_MATCH_LIMIT:
            raise ValueError(
                f"score reason matches exceed the canonical limit of {SCORE_REASON_MATCH_LIMIT}"
            )
        value["matches"] = canonical_matches
    return value


def _base_file_score(
    file: dict[str, Any], query: dict[str, Any]
) -> tuple[int, list[dict[str, object]]]:
    path = str(file["path"])
    reasons: list[dict[str, object]] = []
    score = 0
    if path in query["reported_paths"]:
        score += 10_000
        reasons.append(_reason("EXACT_REPORTED_PATH", 10_000))

    path_terms = set(tokenize(path))
    basename_terms = set(tokenize(PurePosixPath(path).stem))
    basename_matches = sorted(basename_terms & query["identifier_terms"])
    if basename_matches:
        points = min(len(basename_matches), 2) * 3_000
        score += points
        reasons.append(_reason("PATH_BASENAME_MATCH", points, basename_matches[:2]))
    path_matches = sorted((path_terms - basename_terms) & query["identifier_terms"])
    if path_matches:
        points = min(len(path_matches), 4) * 500
        score += points
        reasons.append(_reason("PATH_TOKEN_MATCH", points, path_matches[:4]))
    message_basename_matches = sorted(basename_terms & query["message_terms"])
    if message_basename_matches:
        points = min(len(message_basename_matches), 2) * 1_500
        score += points
        reasons.append(
            _reason(
                "MESSAGE_PATH_BASENAME_MATCH",
                points,
                message_basename_matches[:2],
            )
        )
    message_path_matches = sorted((path_terms - basename_terms) & query["message_terms"])
    if message_path_matches:
        points = min(len(message_path_matches), 4) * 250
        score += points
        reasons.append(_reason("MESSAGE_PATH_TOKEN_MATCH", points, message_path_matches[:4]))

    file_tokens = set(file.get("tokens", {}))
    identifier_matches = sorted(file_tokens & query["identifier_terms"])
    if identifier_matches:
        points = min(len(identifier_matches), 10) * 400
        score += points
        reasons.append(_reason("IDENTIFIER_CONTENT_MATCH", points, identifier_matches[:10]))
    message_matches = sorted(file_tokens & query["message_terms"])
    if message_matches:
        points = min(len(message_matches), 20) * 100
        score += points
        reasons.append(_reason("MESSAGE_CONTENT_MATCH", points, message_matches[:20]))

    test_markers = {"test", "tests", "spec", "specs"}
    if path_terms & test_markers and path not in query["reported_paths"]:
        score -= 500
        reasons.append(_reason("TEST_PATH_PENALTY", -500))
    return score, reasons


def _region_overlap(symbol: dict[str, Any], regions: list[dict[str, int]]) -> bool:
    start = int(symbol["start_line"])
    end = int(symbol["end_line"])
    return any(
        start <= int(region["end_line"]) and end >= int(region["start_line"]) for region in regions
    )


def _candidate(
    *,
    kind: str,
    path: str,
    region: dict[str, int],
    score: int,
    reasons: list[dict[str, object]],
    symbol: dict[str, object] | None = None,
) -> dict[str, object]:
    identity: dict[str, object] = {"kind": kind, "path": path, "region": region}
    candidate: dict[str, object] = {
        **identity,
        "integer_score": score,
        "score_reasons": reasons,
    }
    if symbol is not None:
        projected = {
            "name": symbol["name"],
            "qualified_name": symbol["qualified_name"],
            "kind": symbol["kind"],
            "extractor": symbol["extractor"],
        }
        candidate["symbol"] = projected
        identity["symbol"] = projected
    candidate["candidate_id"] = stable_id("candidate", identity)
    return candidate


def rank_candidates(
    finding: dict[str, object], index: dict[str, object], *, top_k: int = 20
) -> dict[str, object]:
    """Rank file and symbol locations with integer scores and stable ties."""

    validate_normalized_finding(finding)
    verify_repository_index(index)
    if top_k < 1 or top_k > 1_000:
        raise ValueError("top_k must be between 1 and 1000")
    query = _query(finding)
    candidates: list[dict[str, object]] = []

    for file in index.get("files", []):
        path = str(file["path"])
        score, reasons = _base_file_score(file, query)
        end_line = max(1, int(file.get("line_count", 1)))
        candidates.append(
            _candidate(
                kind="file",
                path=path,
                region={"start_line": 1, "start_column": 1, "end_line": end_line, "end_column": 1},
                score=score,
                reasons=reasons,
            )
        )

        for symbol in file.get("symbols", []):
            symbol_score = score
            symbol_reasons = list(reasons)
            names = {str(symbol["name"]).casefold(), str(symbol["qualified_name"]).casefold()}
            if names & query["reported_symbols"]:
                symbol_score += 8_000
                symbol_reasons.append(_reason("EXACT_REPORTED_SYMBOL", 8_000))
            if _region_overlap(symbol, query["regions"].get(path, [])):
                symbol_score += 7_000
                symbol_reasons.append(_reason("REPORTED_REGION_OVERLAP", 7_000))
            symbol_matches = sorted(set(symbol.get("tokens", [])) & query["identifier_terms"])
            if symbol_matches:
                points = min(len(symbol_matches), 4) * 2_000
                symbol_score += points
                symbol_reasons.append(_reason("SYMBOL_TOKEN_MATCH", points, symbol_matches[:4]))
            symbol_message_matches = sorted(set(symbol.get("tokens", [])) & query["message_terms"])
            if symbol_message_matches:
                points = min(len(symbol_message_matches), 4) * 750
                symbol_score += points
                symbol_reasons.append(
                    _reason(
                        "SYMBOL_MESSAGE_TOKEN_MATCH",
                        points,
                        symbol_message_matches[:4],
                    )
                )
            candidates.append(
                _candidate(
                    kind="symbol",
                    path=path,
                    region={
                        "start_line": int(symbol["start_line"]),
                        "start_column": 1,
                        "end_line": int(symbol["end_line"]),
                        "end_column": 1,
                    },
                    score=symbol_score,
                    reasons=symbol_reasons,
                    symbol=symbol,
                )
            )

    candidates.sort(
        key=lambda item: (
            -int(item["integer_score"]),
            str(item["path"]),
            int(item["region"]["start_line"]),  # type: ignore[index]
            int(item["region"]["end_line"]),  # type: ignore[index]
            str(item.get("kind", "")),
            str((item.get("symbol") or {}).get("qualified_name", "")),
            str(item["candidate_id"]),
        )
    )
    selected: list[dict[str, object]] = []
    candidates_per_path: dict[str, int] = {}
    for candidate in candidates:
        path = str(candidate["path"])
        if candidates_per_path.get(path, 0) >= MAX_CANDIDATES_PER_PATH:
            continue
        candidates_per_path[path] = candidates_per_path.get(path, 0) + 1
        selected.append(candidate)
        if len(selected) == top_k:
            break
    for rank, candidate in enumerate(selected, start=1):
        candidate["rank"] = rank
    result: dict[str, object] = {
        "schema_version": "candidate-set-v1",
        "algorithm": RANKING_ALGORITHM,
        "finding_id": finding["finding_id"],
        "index_id": index["index_id"],
        "top_k": top_k,
        "candidate_count_considered": len(candidates),
        "candidates": selected,
        "confidence_is_not_probability": True,
    }
    result["candidate_set_id"] = stable_id("candidate-set", result)
    return result


def project_localization_candidates(
    finding: dict[str, object],
    index: dict[str, object],
    raw_localization: dict[str, object],
    *,
    top_k: int,
) -> dict[str, object]:
    """Project the frozen product localizer into the public candidate contract."""

    validate_normalized_finding(finding)
    verify_repository_index(index)
    verified = verify_raw_localization(raw_localization)
    repository = verified.get("repository")
    if (
        verified.get("runtime_identity") != RUNTIME_IDENTITY
        or verified.get("ranker") != PRODUCT_RANKING_ALGORITHM
        or verified.get("candidate_algorithm") != PRODUCT_CANDIDATE_ALGORITHM
        or verified.get("model_artifact_id") is not None
        or not isinstance(repository, dict)
        or repository.get("manifest_id") != index["repository"]["manifest_id"]
    ):
        raise IntegrityError("product localization output does not match the frozen trace contract")
    if top_k < 1 or top_k > 1_000:
        raise ValueError("top_k must be between 1 and 1000")

    raw_abstention = verified["abstention"]
    if not isinstance(raw_abstention, dict):
        raise IntegrityError("product localization abstention is unavailable")
    abstention = {
        "abstained": raw_abstention["abstained"],
        "reason": raw_abstention["reason"],
    }
    projected: list[dict[str, object]] = []
    if not abstention["abstained"]:
        for raw_candidate in verified["candidates"][:top_k]:
            if not isinstance(raw_candidate, dict):
                raise IntegrityError("product localization candidate is invalid")
            role = str(raw_candidate["role"])
            components = raw_candidate["score_components"]
            if role not in PRODUCT_ROLES or not isinstance(components, dict):
                raise IntegrityError("product localization score basis is invalid")
            reasons = [
                _reason(
                    f"ROLE_{role.upper()}" if code == "ROLE" else str(code),
                    int(points),
                )
                for code, points in sorted(components.items())
                if isinstance(points, int) and not isinstance(points, bool) and points != 0
            ]
            raw_region = raw_candidate["region"]
            if not isinstance(raw_region, dict):
                raise IntegrityError("product localization candidate region is invalid")
            symbol = None
            if raw_candidate["kind"] == "symbol":
                qualified_name = str(raw_candidate["symbol"])
                symbol = {
                    "name": qualified_name.rsplit(".", 1)[-1],
                    "qualified_name": qualified_name,
                    "kind": "python-symbol",
                    "extractor": "python-ast-v1",
                }
            candidate = _candidate(
                kind=str(raw_candidate["kind"]),
                path=str(raw_candidate["path"]),
                region={
                    "start_line": int(raw_region["start_line"]),
                    "start_column": 1,
                    "end_line": int(raw_region["end_line"]),
                    "end_column": 1,
                },
                score=int(raw_candidate["integer_score"]),
                reasons=reasons,
                symbol=symbol,
            )
            candidate["role"] = role
            projected.append(candidate)
        for rank, candidate in enumerate(projected, start=1):
            candidate["rank"] = rank

    confidence_descriptor = (
        "ABSTAINED" if abstention["abstained"] else "FINDING_GUIDED_SIGNAL_PRESENT"
    )
    ranking_identity = {
        "algorithm": PRODUCT_RANKING_ALGORITHM,
        "candidate_algorithm": PRODUCT_CANDIDATE_ALGORITHM,
        "finding_id": finding["finding_id"],
        "index_id": index["index_id"],
        "candidate_ids": [candidate["candidate_id"] for candidate in projected],
        "abstention": abstention,
    }
    result: dict[str, object] = {
        "schema_version": "candidate-set-v1",
        "algorithm": PRODUCT_RANKING_ALGORITHM,
        "candidate_algorithm": PRODUCT_CANDIDATE_ALGORITHM,
        "ranking_id": stable_id("ranking", ranking_identity),
        "finding_id": finding["finding_id"],
        "index_id": index["index_id"],
        "top_k": top_k,
        "candidate_count_considered": verified["candidate_count_ranked"],
        "candidates": projected,
        "abstention": abstention,
        "confidence_descriptor": confidence_descriptor,
        "confidence_is_not_probability": True,
    }
    result["candidate_set_id"] = stable_id("candidate-set", result)
    verify_candidate_set(result)
    return result


def verify_ranked_candidates(candidates: object, *, require_role: bool = False) -> None:
    """Verify a ranked candidate projection and each content identity."""

    if not isinstance(candidates, list) or len(candidates) > 1_000:
        raise IntegrityError("ranked candidates must be a bounded array")
    for rank, candidate in enumerate(candidates, start=1):
        required_candidate = {
            "kind",
            "path",
            "region",
            "integer_score",
            "score_reasons",
            "candidate_id",
            "rank",
        }
        if (
            not isinstance(candidate, dict)
            or not required_candidate.issubset(candidate)
            or set(candidate) - required_candidate - {"symbol", "role"}
            or candidate.get("rank") != rank
            or candidate.get("kind") not in {"file", "symbol"}
            or not isinstance(candidate.get("integer_score"), int)
            or isinstance(candidate.get("integer_score"), bool)
            or not isinstance(candidate.get("score_reasons"), list)
        ):
            raise IntegrityError("ranked candidate structure is invalid")
        role = candidate.get("role")
        if require_role and role not in PRODUCT_ROLES:
            raise IntegrityError("product ranked candidate role is invalid")
        if not require_role and role is not None and role not in PRODUCT_ROLES:
            raise IntegrityError("ranked candidate role is invalid")
        path = candidate.get("path")
        parsed = PurePosixPath(path) if isinstance(path, str) else None
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or "\x00" in path
            or parsed is None
            or parsed.is_absolute()
            or ".." in parsed.parts
            or parsed.as_posix() != path
            or re.match(r"^[A-Za-z]:", path)
        ):
            raise IntegrityError("ranked candidate path is unsafe")
        region = candidate.get("region")
        if (
            not isinstance(region, dict)
            or set(region)
            != {
                "start_line",
                "start_column",
                "end_line",
                "end_column",
            }
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 1
                for value in region.values()
            )
        ):
            raise IntegrityError("ranked candidate region is invalid")
        if (region["end_line"], region["end_column"]) < (
            region["start_line"],
            region["start_column"],
        ):
            raise IntegrityError("ranked candidate region ends before it starts")
        reasons = candidate["score_reasons"]
        if len(reasons) > 64:
            raise IntegrityError("ranked candidate score reasons exceed the bound")
        for reason in reasons:
            if (
                not isinstance(reason, dict)
                or set(reason) - {"code", "points", "matches"}
                or not {"code", "points"}.issubset(reason)
                or not isinstance(reason.get("code"), str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]*", reason["code"]) is None
                or not isinstance(reason.get("points"), int)
                or isinstance(reason.get("points"), bool)
                or "matches" in reason
                and (
                    not isinstance(reason["matches"], list)
                    or not reason["matches"]
                    or len(reason["matches"]) > SCORE_REASON_MATCH_LIMIT
                    or any(not isinstance(item, str) or not item for item in reason["matches"])
                    or reason["matches"] != sorted(set(reason["matches"]))
                )
            ):
                raise IntegrityError("ranked candidate score reason is invalid")
        identity = {"kind": candidate["kind"], "path": path, "region": region}
        if candidate["kind"] == "symbol":
            symbol = candidate.get("symbol")
            if (
                not isinstance(symbol, dict)
                or set(symbol) != {"name", "qualified_name", "kind", "extractor"}
                or any(not isinstance(value, str) or not value for value in symbol.values())
            ):
                raise IntegrityError("ranked candidate symbol is invalid")
            identity["symbol"] = symbol
        elif "symbol" in candidate:
            raise IntegrityError("file candidate must not contain symbol metadata")
        if candidate.get("candidate_id") != stable_id("candidate", identity):
            raise IntegrityError("ranked candidate identity mismatch")


def verify_candidate_set(candidate_set: dict[str, object]) -> None:
    """Verify the schema marker and canonical self-identity of ranked candidates."""

    if (
        not isinstance(candidate_set, dict)
        or candidate_set.get("schema_version") != "candidate-set-v1"
    ):
        raise IntegrityError("candidate set must use candidate-set-v1")
    base_fields = {
        "schema_version",
        "algorithm",
        "finding_id",
        "index_id",
        "top_k",
        "candidate_count_considered",
        "candidates",
        "confidence_is_not_probability",
        "candidate_set_id",
    }
    product_fields = {
        "candidate_algorithm",
        "ranking_id",
        "abstention",
        "confidence_descriptor",
    }
    algorithm = candidate_set.get("algorithm")
    expected_fields = (
        base_fields | product_fields if algorithm == PRODUCT_RANKING_ALGORITHM else base_fields
    )
    if set(candidate_set) != expected_fields or algorithm not in SUPPORTED_RANKING_ALGORITHMS:
        raise IntegrityError("candidate set fields or algorithm are invalid")
    if (
        not isinstance(candidate_set.get("top_k"), int)
        or isinstance(candidate_set.get("top_k"), bool)
        or not 1 <= candidate_set["top_k"] <= 1_000
        or not isinstance(candidate_set.get("candidate_count_considered"), int)
        or isinstance(candidate_set.get("candidate_count_considered"), bool)
        or candidate_set["candidate_count_considered"] < 0
        or candidate_set.get("confidence_is_not_probability") is not True
    ):
        raise IntegrityError("candidate set summary values are invalid")
    candidates = candidate_set.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > candidate_set["top_k"]:
        raise IntegrityError("candidate set candidates are invalid")
    require_role = algorithm == PRODUCT_RANKING_ALGORITHM
    verify_ranked_candidates(candidates, require_role=require_role)
    if require_role:
        abstention = candidate_set.get("abstention")
        if (
            candidate_set.get("candidate_algorithm") != PRODUCT_CANDIDATE_ALGORITHM
            or not isinstance(abstention, dict)
            or set(abstention) != {"abstained", "reason"}
            or not isinstance(abstention.get("abstained"), bool)
            or (
                abstention["abstained"]
                and abstention.get("reason")
                not in {NO_SIGNAL_ABSTENTION, CANDIDATE_TRUNCATION_ABSTENTION}
            )
            or (not abstention["abstained"] and abstention.get("reason") is not None)
            or (abstention["abstained"] and candidates)
            or (not abstention["abstained"] and not candidates)
            or candidate_set.get("confidence_descriptor")
            != ("ABSTAINED" if abstention.get("abstained") else "FINDING_GUIDED_SIGNAL_PRESENT")
        ):
            raise IntegrityError("product candidate set abstention or confidence is invalid")
        if candidates:
            first_reasons = candidates[0]["score_reasons"]
            guided_score = sum(
                reason["points"]
                for reason in first_reasons
                if reason["code"] in FINDING_GUIDED_SCORE_COMPONENTS
            )
            if guided_score <= 0:
                raise IntegrityError("product candidate set has no positive finding-guided signal")
        ranking_identity = {
            "algorithm": PRODUCT_RANKING_ALGORITHM,
            "candidate_algorithm": PRODUCT_CANDIDATE_ALGORITHM,
            "finding_id": candidate_set["finding_id"],
            "index_id": candidate_set["index_id"],
            "candidate_ids": [candidate["candidate_id"] for candidate in candidates],
            "abstention": abstention,
        }
        if candidate_set.get("ranking_id") != stable_id("ranking", ranking_identity):
            raise IntegrityError("product candidate ranking identity mismatch")
    expected = stable_id("candidate-set", candidate_set, omit_keys=("candidate_set_id",))
    if candidate_set.get("candidate_set_id") != expected:
        raise IntegrityError("candidate set identity mismatch")
