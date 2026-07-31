# SPDX-License-Identifier: Apache-2.0
"""Deterministic, label-blind candidate feature construction for V0.4."""

from __future__ import annotations

import ast
import math
import warnings
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from .baselines import tokens
from .canonical import stable_id
from .corpus import is_python_harness, is_python_production
from .errors import PolicyError
from .trace001 import FEATURE_NAMES

CANDIDATE_GENERATION_ALGORITHM = "v0.4-label-blind-python-candidates-v5-idf-hybrid"
CANDIDATE_CACHE_TOKEN = "pathq6"


def _symbols(source: str) -> list[dict[str, Any]]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, SyntaxWarning, ValueError, RecursionError):
        return []
    lines = source.splitlines()
    result: list[dict[str, Any]] = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        name = getattr(node, "name", None)
        qualified = (*parents, name) if isinstance(name, str) else parents
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            start = int(getattr(node, "lineno", 0))
            end = int(getattr(node, "end_lineno", start))
            result.append(
                {
                    "symbol": ".".join(qualified),
                    "start_line": start,
                    "end_line": end,
                    "content": "\n".join(lines[max(0, start - 1) : end]),
                }
            )
        for child in ast.iter_child_nodes(node):
            visit(child, qualified)

    visit(tree, ())
    return result


def _overlap(query: Counter[str], values: list[str]) -> float:
    return float(sum((query & Counter(value.casefold() for value in values)).values()))


def _candidate(
    *,
    path: str,
    source: str,
    symbol: str | None,
    start_line: int,
    end_line: int,
    query: Counter[str],
    description: Counter[str],
) -> dict[str, Any]:
    path_values = tokens(PurePosixPath(path).as_posix().replace("/", " "))
    symbol_values = tokens(symbol or "")
    source_tokens = tokens(source[:65_536])
    query_terms = set(query) | set(description)
    matched_content = list(dict.fromkeys(token for token in source_tokens if token in query_terms))
    other_content = list(
        dict.fromkeys(token for token in source_tokens if token not in query_terms)
    )
    content_values = (matched_content + other_content)[:256]
    harness = is_python_harness(path)
    production = is_python_production(path)
    feature_values = {
        "path_overlap": _overlap(query, path_values),
        "symbol_overlap": _overlap(query, symbol_values),
        "content_overlap": _overlap(query, content_values),
        "description_overlap": _overlap(description, content_values),
        "symbol_present": float(symbol is not None),
        "production_path": float(production),
        "harness_indicator": float(harness),
        "path_depth_inverse": 1.0 / max(1, len(PurePosixPath(path).parts)),
    }
    if tuple(feature_values) != FEATURE_NAMES or not all(
        math.isfinite(value) for value in feature_values.values()
    ):
        raise PolicyError("V0_4_DERIVED_FEATURE_CONTRACT_REJECTED")
    identity = {
        "kind": "symbol" if symbol is not None else "file",
        "path": path,
        "symbol": symbol,
        "start_line": start_line,
        "end_line": end_line,
    }
    return {
        "candidate_id": stable_id("v0.4-feature-candidate", identity),
        **identity,
        "path_tokens": path_values,
        "symbol_tokens": symbol_values,
        "content_tokens": content_values,
        "features": feature_values,
        "selection_score": (
            3 * feature_values["symbol_overlap"]
            + 2 * feature_values["path_overlap"]
            + feature_values["content_overlap"]
        ),
    }


def _apply_corpus_frequency_selection(
    candidates: list[dict[str, Any]],
    *,
    query: Counter[str],
) -> None:
    """Downweight repository-wide vocabulary before applying the hard cap."""

    document_frequency: Counter[str] = Counter()
    for candidate in candidates:
        document_frequency.update(
            {
                *candidate["path_tokens"],
                *candidate["symbol_tokens"],
                *candidate["content_tokens"],
            }
        )
    document_count = len(candidates)
    for candidate in candidates:
        frequencies = Counter(candidate["content_tokens"])
        frequencies.update(token for token in candidate["path_tokens"] for _ in range(3))
        frequencies.update(token for token in candidate["symbol_tokens"] for _ in range(4))
        score = 0.0
        for token, query_frequency in query.items():
            frequency = frequencies[token]
            if not frequency:
                continue
            inverse_frequency = math.log(
                1
                + (document_count - document_frequency[token] + 0.5)
                / (document_frequency[token] + 0.5)
            )
            score += query_frequency * inverse_frequency * (1.0 + math.log(frequency))
        if not math.isfinite(score):
            raise PolicyError("V0_4_CANDIDATE_SELECTION_SCORE_REJECTED")
        candidate["selection_score"] = score


def build_candidate_features(
    finding: dict[str, Any],
    files: list[dict[str, str]],
    *,
    maximum_candidates: int = 2_000,
) -> list[dict[str, Any]]:
    """Build bounded candidates without receiving or consulting labels."""

    if not 1 <= maximum_candidates <= 100_000:
        raise PolicyError("V0_4_CANDIDATE_BOUND_REJECTED")
    query = Counter(
        tokens(
            [
                str(finding.get("advisory_identifier", "")),
                *[str(value) for value in finding.get("aliases", [])],
                *[str(value) for value in finding.get("packages", [])],
                str(finding.get("summary", "")),
                str(finding.get("description", "")),
            ]
        )
    )
    description = Counter(
        tokens(
            [
                str(finding.get("summary", "")),
                str(finding.get("description", "")),
            ]
        )
    )
    seen_paths: set[str] = set()
    file_candidates: list[dict[str, Any]] = []
    symbol_candidates: list[dict[str, Any]] = []
    for item in sorted(files, key=lambda value: value.get("path", "")):
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "source"}
            or not isinstance(item["path"], str)
            or not isinstance(item["source"], str)
            or item["path"] in seen_paths
            or not item["path"].casefold().endswith(".py")
        ):
            raise PolicyError("V0_4_FEATURE_FILE_CONTRACT_REJECTED")
        seen_paths.add(item["path"])
        if len(item["source"].encode("utf-8")) > 2 * 1024 * 1024:
            continue
        file_candidates.append(
            _candidate(
                path=item["path"],
                source=item["source"],
                symbol=None,
                start_line=1,
                end_line=max(1, len(item["source"].splitlines())),
                query=query,
                description=description,
            )
        )
        for symbol in _symbols(item["source"]):
            symbol_candidates.append(
                _candidate(
                    path=item["path"],
                    source=symbol["content"],
                    symbol=symbol["symbol"],
                    start_line=symbol["start_line"],
                    end_line=symbol["end_line"],
                    query=query,
                    description=description,
                )
            )

    _apply_corpus_frequency_selection(
        [*file_candidates, *symbol_candidates],
        query=query,
    )

    def selection_key(item: dict[str, Any]) -> tuple[float, str]:
        return (-item["selection_score"], item["candidate_id"])

    # File candidates are the minimum unit of finding-guided localisation.
    # Keep every file when it fits. For larger trees, reserve three quarters
    # of the budget for query-aware files, then use half of the remaining
    # budget to rescue distinct uncovered paths through their strongest
    # symbol. Fill the balance with the strongest symbols overall. This
    # remains label-blind while avoiding both symbol crowding and all-file
    # starvation of useful location-role evidence.
    ordered_files = sorted(file_candidates, key=selection_key)
    if len(ordered_files) <= maximum_candidates:
        selected_files = ordered_files
        remaining = maximum_candidates - len(selected_files)
        selected_symbols = sorted(symbol_candidates, key=selection_key)[:remaining]
    else:
        file_budget = max(1, (maximum_candidates * 3) // 4)
        selected_files = ordered_files[:file_budget]
        selected_paths = {candidate["path"] for candidate in selected_files}
        remaining = maximum_candidates - len(selected_files)
        rescue_budget = remaining // 2
        best_uncovered_by_path: dict[str, dict[str, Any]] = {}
        for candidate in sorted(symbol_candidates, key=selection_key):
            if candidate["path"] not in selected_paths:
                best_uncovered_by_path.setdefault(candidate["path"], candidate)
        rescued = sorted(best_uncovered_by_path.values(), key=selection_key)[:rescue_budget]
        rescued_ids = {candidate["candidate_id"] for candidate in rescued}
        strongest = [
            candidate
            for candidate in sorted(symbol_candidates, key=selection_key)
            if candidate["candidate_id"] not in rescued_ids
        ][: remaining - len(rescued)]
        selected_symbols = [*rescued, *strongest]
    return sorted((*selected_files, *selected_symbols), key=selection_key)


def apply_private_labels(
    candidates: list[dict[str, Any]],
    *,
    targets: list[dict[str, Any]],
    hard_negative_paths: list[str],
) -> dict[str, Any]:
    """Apply labels only after the candidate set has been identity-sealed."""

    file_targets: set[str] = set()
    role_targets: set[str] = set()
    hard_negatives: set[str] = set()
    target_paths = {target["path"] for target in targets}
    target_symbols = {
        (target["path"], target["symbol"]) for target in targets if target.get("symbol")
    }
    hard_paths = set(hard_negative_paths)
    for candidate in candidates:
        if candidate["path"] in target_paths:
            file_targets.add(candidate["candidate_id"])
        if (candidate["path"], candidate["symbol"]) in target_symbols:
            role_targets.add(candidate["candidate_id"])
        if candidate["path"] in hard_paths:
            hard_negatives.add(candidate["candidate_id"])
    return {
        "candidate_set_id": stable_id(
            "v0.4-feature-candidate-set",
            [
                {
                    "candidate_id": item["candidate_id"],
                    "features": item["features"],
                }
                for item in candidates
            ],
        ),
        "file_target_candidate_ids": sorted(file_targets),
        "role_target_candidate_ids": sorted(role_targets),
        "hard_negative_candidate_ids": sorted(hard_negatives),
        "file_target_present": target_paths <= {candidate["path"] for candidate in candidates},
        "role_target_present": target_symbols
        <= {
            (candidate["path"], candidate["symbol"])
            for candidate in candidates
            if candidate["symbol"]
        },
    }


def baseline_candidate_projection(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "path_tokens": candidate["path_tokens"],
        "symbol_tokens": candidate["symbol_tokens"],
        "content_tokens": candidate["content_tokens"],
    }


def training_candidate_projection(
    candidate: dict[str, Any], *, target_ids: set[str]
) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "features": candidate["features"],
        "target": candidate["candidate_id"] in target_ids,
    }
