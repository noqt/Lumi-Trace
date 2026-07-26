# SPDX-License-Identifier: Apache-2.0
"""Inert Python fixing-change analysis for controlled V0.4 label passes."""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass
from typing import Any

from .canonical import sha256_bytes, stable_id
from .errors import PolicyError

_DIFF_HUNK = re.compile(
    r"^@@ -(?P<old_start>[0-9]+)(?:,(?P<old_count>[0-9]+))? "
    r"\+(?P<new_start>[0-9]+)(?:,(?P<new_count>[0-9]+))? @@"
)
_NON_PRODUCTION_PARTS = frozenset(
    {
        ".github",
        "benchmark",
        "benchmarks",
        "ci",
        "doc",
        "docs",
        "example",
        "examples",
        "script",
        "scripts",
        "test",
        "testing",
        "tests",
    }
)


@dataclass(frozen=True)
class PythonChange:
    """Bounded decoded blobs and inert patch text for one changed Python path."""

    path: str
    parent_source: str
    fixed_source: str
    patch: str


@dataclass(frozen=True)
class SymbolRegion:
    qualified_name: str
    start_line: int
    end_line: int
    body_hash: str


def is_python_production(path: str) -> bool:
    parts = [part.casefold() for part in path.split("/")]
    return path.casefold().endswith(".py") and not any(
        part in _NON_PRODUCTION_PARTS or part.startswith("test_") or part.endswith("_test.py")
        for part in parts
    )


def is_python_harness(path: str) -> bool:
    parts = [part.casefold() for part in path.split("/")]
    return path.casefold().endswith(".py") and any(
        part in {"test", "testing", "tests"}
        or part.startswith("test_")
        or part.endswith("_test.py")
        for part in parts
    )


def old_regions(patch: str) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for line in patch.splitlines():
        match = _DIFF_HUNK.match(line)
        if match is None:
            continue
        start = int(match.group("old_start"))
        count = int(match.group("old_count") or "1")
        if count == 0:
            result.append((max(1, start), max(1, start)))
        else:
            result.append((start, start + count - 1))
    return result


def _symbols(source: str) -> list[SymbolRegion]:
    if len(source.encode("utf-8")) > 2 * 1024 * 1024:
        raise PolicyError("PYTHON_BLOB_SIZE_LIMIT")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, SyntaxWarning, ValueError, RecursionError) as exc:
        raise PolicyError("PYTHON_AST_REJECTED") from exc
    lines = source.splitlines(keepends=True)
    result: list[SymbolRegion] = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        name = getattr(node, "name", None)
        qualified = (*parents, name) if isinstance(name, str) else parents
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            start = int(getattr(node, "lineno", 0))
            end = int(getattr(node, "end_lineno", start))
            body = "".join(lines[max(0, start - 1) : end]).encode("utf-8")
            result.append(
                SymbolRegion(
                    qualified_name=".".join(qualified),
                    start_line=start,
                    end_line=end,
                    body_hash=sha256_bytes(body),
                )
            )
        for child in ast.iter_child_nodes(node):
            visit(child, qualified)

    visit(tree, ())
    return result


def _overlaps(symbol: SymbolRegion, regions: list[tuple[int, int]]) -> bool:
    return any(
        symbol.start_line <= region_end and region_start <= symbol.end_line
        for region_start, region_end in regions
    )


def _target(path: str, symbol: SymbolRegion, region: tuple[int, int]) -> dict[str, Any]:
    path_identity = stable_id("target-file", path)
    symbol_identity = stable_id(
        "target-symbol",
        {"file_identity": path_identity, "qualified_name": symbol.qualified_name},
    )
    region_identity = stable_id(
        "target-region",
        {
            "file_identity": path_identity,
            "start_line": region[0],
            "end_line": region[1],
        },
    )
    return {
        "file_identity": path_identity,
        "symbol_identity": symbol_identity,
        "region_identity": region_identity,
        "role": "VULNERABLE_IMPLEMENTATION",
        "private_mapping": {
            "path": path,
            "symbol": symbol.qualified_name,
            "region": {"start_line": region[0], "end_line": region[1]},
            "symbol_region": {
                "start_line": symbol.start_line,
                "end_line": symbol.end_line,
            },
        },
    }


def blind_label_pass_one(changes: list[PythonChange]) -> list[dict[str, Any]]:
    """Diff-first pass: map each old-side hunk to its smallest enclosing symbol."""

    targets: list[dict[str, Any]] = []
    for change in sorted(changes, key=lambda item: item.path):
        regions = old_regions(change.patch)
        symbols = _symbols(change.parent_source)
        candidates = [
            (symbol.end_line - symbol.start_line, symbol, region)
            for region in regions
            for symbol in symbols
            if symbol.start_line <= region[0] <= symbol.end_line
        ]
        if candidates:
            _, symbol, region = min(
                candidates,
                key=lambda item: (
                    item[0],
                    item[1].qualified_name,
                    item[2][0],
                    item[2][1],
                ),
            )
            targets.append(_target(change.path, symbol, region))
    return targets


def blind_label_pass_two(changes: list[PythonChange]) -> list[dict[str, Any]]:
    """AST-first pass: identify modified symbols, then independently bind hunks."""

    targets: list[dict[str, Any]] = []
    for change in sorted(changes, key=lambda item: item.path):
        regions = old_regions(change.patch)
        parent_symbols = _symbols(change.parent_source)
        fixed_by_name = {symbol.qualified_name: symbol for symbol in _symbols(change.fixed_source)}
        modified = [
            symbol
            for symbol in parent_symbols
            if symbol.qualified_name in fixed_by_name
            and symbol.body_hash != fixed_by_name[symbol.qualified_name].body_hash
            and _overlaps(symbol, regions)
        ]
        if modified:
            symbol = min(
                modified,
                key=lambda item: (
                    item.end_line - item.start_line,
                    item.qualified_name,
                ),
            )
            overlapping = [
                region for region in regions if symbol.start_line <= region[0] <= symbol.end_line
            ]
            if overlapping:
                targets.append(_target(change.path, symbol, min(overlapping)))
    return targets


def public_targets(targets: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Remove private path/symbol mappings from a canonical blind-pass target."""

    return [
        {
            "file_identity": target["file_identity"],
            "symbol_identity": target["symbol_identity"],
            "region_identity": target["region_identity"],
            "role": target["role"],
        }
        for target in targets
    ]


def blind_passes_agree(first: list[dict[str, Any]], second: list[dict[str, Any]]) -> bool:
    return public_targets(first) == public_targets(second)
