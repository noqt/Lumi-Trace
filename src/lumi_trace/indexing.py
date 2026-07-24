# SPDX-License-Identifier: Apache-2.0
"""Deterministic text and symbol indexing for repository snapshots."""

from __future__ import annotations

import ast
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from .canonical import stable_id
from .errors import IntegrityError, UnsupportedError
from .repository import repository_manifest

INDEX_ALGORITHM = "deterministic-lexical-index-v2"
DEFAULT_MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_UNIQUE_TOKENS = 50_000
MAX_SYMBOLS_PER_FILE = 5_000
MAX_INDEX_FILE_RECORDS = 25_000
MAX_TOTAL_TOKEN_ENTRIES = 250_000
MAX_TOTAL_SYMBOLS = 50_000
MAX_SYMBOL_TOKENS = 16
MAX_SYMBOL_NAME_CHARS = 256
MAX_QUALIFIED_SYMBOL_CHARS = 1_024
MAX_PYTHON_AST_NODES = 200_000
MAX_INDEX_JSON_BYTES = 60 * 1024 * 1024
MAX_INDEX_JSON_ITEMS = 900_000

LANGUAGE_BY_SUFFIX = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".ts": "typescript",
    ".tsx": "typescript",
}

TEXT_SUFFIXES = set(LANGUAGE_BY_SUFFIX) | {
    ".cfg",
    ".conf",
    ".css",
    ".graphql",
    ".html",
    ".ini",
    ".json",
    ".md",
    ".rst",
    ".sh",
    ".sql",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]{1,63}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_REPOSITORY_ID = re.compile(r"repository:[0-9a-f]{64}")
_INDEX_ID = re.compile(r"index:[0-9a-f]{64}")
_CAMEL_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")


def tokenize(value: str) -> list[str]:
    """Split prose, paths, snake case, and camel case into stable terms."""

    expanded = _CAMEL_2.sub(r"\1 \2", value)
    expanded = _CAMEL_1.sub(r"\1 \2", expanded)
    return [match.group(0).lower() for match in _WORD.finditer(expanded)]


def _language(path: str) -> str:
    return LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower(), "text")


def _index_priority(path: str) -> int:
    """Allocate global index budgets to implementation source before observations."""

    parsed = PurePosixPath(path)
    parts = {part.casefold() for part in parsed.parts}
    stem = parsed.stem.casefold()
    source = parsed.suffix.casefold() in LANGUAGE_BY_SUFFIX
    test_or_harness = bool(parts & {"test", "tests", "testing", "spec", "specs"}) or (
        stem.startswith(("test_", "spec_")) or stem.endswith(("_test", "_spec"))
    )
    documentation_or_example = bool(
        parts
        & {
            "doc",
            "docs",
            "documentation",
            "example",
            "examples",
            "demo",
            "demos",
            "benchmark",
            "benchmarks",
        }
    )
    localisation = parsed.suffix.casefold() in {".mo", ".po", ".pot"} or bool(
        parts & {"i18n", "l10n", "locale", "locales", "translations"}
    )
    if source and not (test_or_harness or documentation_or_example):
        return 0
    if source:
        return 1
    if localisation or documentation_or_example:
        return 3
    return 2


def _looks_text(path: str, data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    suffix = Path(path).suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return True
    if not data:
        return True
    sample = data[:8192]
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) < 0.02


class _PythonTraversalLimit(Exception):
    """Internal signal used to stop a bounded AST walk."""


class _PythonSymbolLimit(Exception):
    """Internal signal used after another symbol exceeds the output cap."""


class _PythonSymbols(ast.NodeVisitor):
    def __init__(self, *, max_symbols: int) -> None:
        self.symbols: list[dict[str, object]] = []
        self.scope: list[str] = []
        self.max_symbols = max_symbols
        self.node_count = 0

    def visit(self, node: ast.AST) -> object:  # type: ignore[override]
        self.node_count += 1
        if self.node_count > MAX_PYTHON_AST_NODES:
            raise _PythonTraversalLimit
        return super().visit(node)

    def _add(self, node: ast.AST, name: str, kind: str) -> None:
        if len(self.symbols) >= self.max_symbols:
            raise _PythonSymbolLimit
        qualified = ".".join([*self.scope, name])
        if len(name) > MAX_SYMBOL_NAME_CHARS or len(qualified) > MAX_QUALIFIED_SYMBOL_CHARS:
            raise _PythonTraversalLimit
        self.symbols.append(
            {
                "name": name,
                "qualified_name": qualified,
                "kind": kind,
                "start_line": int(getattr(node, "lineno", 1)),
                "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                "tokens": sorted(set(tokenize(qualified)))[:MAX_SYMBOL_TOKENS],
                "extractor": "python-ast-v1",
            }
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._add(node, node.name, "class")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        kind = "method" if self.scope else "function"
        self._add(node, node.name, kind)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        kind = "method" if self.scope else "function"
        self._add(node, node.name, kind)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def _python_symbols(
    text: str, *, max_symbols: int = MAX_SYMBOLS_PER_FILE
) -> tuple[list[dict[str, object]], str | None, bool]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], "syntax_error", False
    except RecursionError:
        return [], "complexity_limit", False
    visitor = _PythonSymbols(max_symbols=max_symbols)
    try:
        visitor.visit(tree)
    except _PythonSymbolLimit:
        return visitor.symbols, None, True
    except (_PythonTraversalLimit, RecursionError):
        return visitor.symbols, "complexity_limit", False
    return visitor.symbols, None, False


_LEXICAL_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "javascript": (
        ("class", re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)")),
        (
            "function",
            re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        ),
        (
            "function",
            re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*=>"),
        ),
    ),
    "typescript": (
        ("class", re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)")),
        ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)")),
        (
            "function",
            re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        ),
        (
            "function",
            re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*=>"),
        ),
    ),
    "go": (
        (
            "function",
            re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        ),
        ("type", re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+")),
    ),
    "rust": (
        ("function", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)")),
        ("struct", re.compile(r"^\s*(?:pub\s+)?struct\s+(\w+)")),
        ("enum", re.compile(r"^\s*(?:pub\s+)?enum\s+(\w+)")),
        ("trait", re.compile(r"^\s*(?:pub\s+)?trait\s+(\w+)")),
    ),
    "java": (
        (
            "type",
            re.compile(
                r"^\s*(?:public\s+|protected\s+|private\s+)?(?:class|interface|enum)\s+(\w+)"
            ),
        ),
        (
            "method",
            re.compile(
                r"^\s*(?:public|protected|private|static|final|synchronized|native|abstract|\s)+"
                r"[\w<>\[\],.?]+\s+(\w+)\s*\([^;]*\)\s*(?:throws\s+[^\{]+)?\{?"
            ),
        ),
    ),
    "ruby": (
        ("class", re.compile(r"^\s*class\s+([A-Za-z_][\w:]*)")),
        ("module", re.compile(r"^\s*module\s+([A-Za-z_][\w:]*)")),
        ("function", re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_][\w!?=]*)")),
    ),
    "php": (
        ("class", re.compile(r"^\s*(?:final\s+|abstract\s+)?class\s+(\w+)", re.I)),
        (
            "function",
            re.compile(r"^\s*(?:public\s+|private\s+|protected\s+)?function\s+(\w+)", re.I),
        ),
    ),
    "c": (
        (
            "function",
            re.compile(r"^\s*(?:[A-Za-z_]\w*[\s*]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"),
        ),
    ),
    "cpp": (
        (
            "function",
            re.compile(r"^\s*(?:[A-Za-z_]\w*[\s:*&<>]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"),
        ),
        ("type", re.compile(r"^\s*(?:class|struct)\s+(\w+)")),
    ),
    "shell": (
        ("function", re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")),
        ("function", re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ),
}


def _lexical_symbols(
    text: str, language: str, *, max_symbols: int = MAX_SYMBOLS_PER_FILE
) -> tuple[list[dict[str, object]], bool]:
    patterns = _LEXICAL_PATTERNS.get(language, ())
    symbols: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            if len(symbols) >= max_symbols:
                return symbols, True
            name = match.group(1)
            if len(name) > MAX_SYMBOL_NAME_CHARS:
                return symbols, True
            symbols.append(
                {
                    "name": name,
                    "qualified_name": name,
                    "kind": kind,
                    "start_line": line_number,
                    "end_line": line_number,
                    "tokens": sorted(set(tokenize(name)))[:MAX_SYMBOL_TOKENS],
                    "extractor": "lexical-v1",
                }
            )
            break
    return symbols, False


def _bounded_token_counts(
    values: Iterable[str], *, max_entries: int = MAX_UNIQUE_TOKENS
) -> tuple[dict[str, int], bool]:
    counts = Counter(values)
    limited = len(counts) > max_entries
    selected = sorted(counts, key=lambda term: (-counts[term], term))[:max_entries]
    return {term: min(counts[term], 255) for term in sorted(selected)}, limited


def build_repository_index(
    root: Path,
    repository_identity: dict[str, object],
    *,
    max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES,
) -> dict[str, object]:
    """Build a deterministic file/token/symbol index from a snapshot."""

    if (
        not isinstance(max_text_bytes, int)
        or isinstance(max_text_bytes, bool)
        or not 1 <= max_text_bytes <= DEFAULT_MAX_TEXT_BYTES
    ):
        raise ValueError(f"max_text_bytes must be between 1 and {DEFAULT_MAX_TEXT_BYTES}")
    manifest, _ = repository_manifest(root)
    if len(manifest) > MAX_INDEX_FILE_RECORDS:
        raise UnsupportedError(
            f"repository exceeds index file-record limit of {MAX_INDEX_FILE_RECORDS}"
        )
    files: list[dict[str, object]] = []
    symbol_count = 0
    token_entry_count = 0
    global_token_limit_reached = False
    global_symbol_limit_reached = False
    exclusions = Counter()

    processing_order = sorted(
        manifest,
        key=lambda item: (
            _index_priority(str(item["path"])),
            str(item["path"]).encode("utf-8"),
        ),
    )
    for source_record in processing_order:
        path = str(source_record["path"])
        size = int(source_record["size_bytes"])
        record: dict[str, object] = {
            "path": path,
            "sha256": source_record["sha256"],
            "size_bytes": size,
            "language": _language(path),
            "content_indexed": False,
            "tokens": {},
            "symbols": [],
        }
        if size > max_text_bytes:
            record["exclusion_reason"] = "oversized"
            exclusions["oversized"] += 1
            files.append(record)
            continue
        data = (root / Path(path)).read_bytes()
        if not _looks_text(path, data):
            record["exclusion_reason"] = "binary"
            exclusions["binary"] += 1
            files.append(record)
            continue
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            record["exclusion_reason"] = "unsupported_encoding"
            exclusions["unsupported_encoding"] += 1
            files.append(record)
            continue

        language = str(record["language"])
        token_budget = min(
            MAX_UNIQUE_TOKENS,
            max(0, MAX_TOTAL_TOKEN_ENTRIES - token_entry_count),
        )
        tokens, token_limit = _bounded_token_counts(
            [*tokenize(path), *tokenize(text)], max_entries=token_budget
        )
        if token_limit and token_budget < MAX_UNIQUE_TOKENS:
            global_token_limit_reached = True
        token_entry_count += len(tokens)

        symbol_budget = min(
            MAX_SYMBOLS_PER_FILE,
            max(0, MAX_TOTAL_SYMBOLS - symbol_count),
        )
        if language == "python":
            symbols, parse_issue, symbol_limit = _python_symbols(text, max_symbols=symbol_budget)
            if parse_issue:
                record["symbol_extraction_issue"] = parse_issue
        else:
            symbols, symbol_limit = _lexical_symbols(text, language, max_symbols=symbol_budget)
        if symbol_limit and symbol_budget < MAX_SYMBOLS_PER_FILE:
            global_symbol_limit_reached = True
        symbols.sort(
            key=lambda symbol: (
                int(symbol["start_line"]),
                int(symbol["end_line"]),
                str(symbol["kind"]),
                str(symbol["qualified_name"]),
            )
        )
        record.update(
            {
                "content_indexed": True,
                "line_count": len(text.splitlines()),
                "tokens": tokens,
                "token_limit_reached": token_limit,
                "symbols": symbols,
                "symbol_limit_reached": symbol_limit,
            }
        )
        symbol_count += len(symbols)
        files.append(record)

    files.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    payload: dict[str, object] = {
        "schema_version": "repository-index-v1",
        "algorithm": INDEX_ALGORITHM,
        "repository": repository_identity,
        "file_count": len(files),
        "indexed_text_file_count": sum(bool(item["content_indexed"]) for item in files),
        "symbol_count": symbol_count,
        "exclusions": dict(sorted(exclusions.items())),
        "global_limit_reached": {
            "token_entries": global_token_limit_reached,
            "symbols": global_symbol_limit_reached,
        },
        "limits": {
            "max_text_bytes": max_text_bytes,
            "max_unique_tokens_per_file": MAX_UNIQUE_TOKENS,
            "max_symbols_per_file": MAX_SYMBOLS_PER_FILE,
            "max_index_file_records": MAX_INDEX_FILE_RECORDS,
            "max_total_token_entries": MAX_TOTAL_TOKEN_ENTRIES,
            "max_total_symbols": MAX_TOTAL_SYMBOLS,
            "max_symbol_tokens": MAX_SYMBOL_TOKENS,
            "max_symbol_name_chars": MAX_SYMBOL_NAME_CHARS,
            "max_qualified_symbol_chars": MAX_QUALIFIED_SYMBOL_CHARS,
            "max_python_ast_nodes": MAX_PYTHON_AST_NODES,
            "max_index_json_bytes": MAX_INDEX_JSON_BYTES,
            "max_index_json_items": MAX_INDEX_JSON_ITEMS,
        },
        "files": files,
    }
    payload["index_id"] = stable_id("index", payload)
    if _serialized_index_size(payload) > MAX_INDEX_JSON_BYTES:
        raise UnsupportedError(
            f"repository index exceeds JSON artifact limit of {MAX_INDEX_JSON_BYTES} bytes"
        )
    if _index_json_item_count(payload) > MAX_INDEX_JSON_ITEMS:
        raise UnsupportedError(
            f"repository index exceeds JSON item limit of {MAX_INDEX_JSON_ITEMS}"
        )
    return payload


def _serialized_index_size(index: dict[str, object]) -> int:
    """Measure the exact human-readable representation emitted by ``dump_json``."""

    return len(
        (
            json.dumps(index, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    )


def _index_json_item_count(index: object) -> int:
    """Count JSON value nodes exactly as the evaluator's bounded loader does."""

    count = 0
    pending = [index]
    while pending:
        value = pending.pop()
        count += 1
        if count > MAX_INDEX_JSON_ITEMS:
            return count
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return count


def verify_repository_identity(repository: dict[str, object]) -> None:
    """Verify the public immutable-repository identity projection."""

    if not isinstance(repository, dict) or set(repository) not in (
        {"repository_id", "manifest_id", "algorithm", "source_kind", "file_count", "total_bytes"},
        {
            "repository_id",
            "manifest_id",
            "algorithm",
            "source_kind",
            "file_count",
            "total_bytes",
            "archive_sha256",
        },
    ):
        raise IntegrityError("repository identity structure is invalid")
    if repository.get("algorithm") != "lumi-tree-sha256-v1" or repository.get(
        "source_kind"
    ) not in {"directory", "archive"}:
        raise IntegrityError("repository identity values are invalid")
    if (
        not isinstance(repository.get("repository_id"), str)
        or _REPOSITORY_ID.fullmatch(repository["repository_id"]) is None
        or not isinstance(repository.get("manifest_id"), str)
        or _SHA256.fullmatch(repository["manifest_id"]) is None
        or not _nonnegative_index_integer(repository.get("file_count"))
        or not _nonnegative_index_integer(repository.get("total_bytes"))
        or (
            repository["source_kind"] == "archive"
            and (
                not isinstance(repository.get("archive_sha256"), str)
                or _SHA256.fullmatch(repository["archive_sha256"]) is None
            )
        )
        or (repository["source_kind"] == "directory" and "archive_sha256" in repository)
    ):
        raise IntegrityError("repository identity fields are invalid")


def verify_repository_index(index: dict[str, object]) -> None:
    """Verify the schema marker and canonical self-identity of an index."""

    if not isinstance(index, dict) or index.get("schema_version") != "repository-index-v1":
        raise IntegrityError("index must use repository-index-v1")
    required = {
        "schema_version",
        "algorithm",
        "repository",
        "file_count",
        "indexed_text_file_count",
        "symbol_count",
        "exclusions",
        "global_limit_reached",
        "limits",
        "files",
        "index_id",
    }
    if set(index) != required or index.get("algorithm") != INDEX_ALGORITHM:
        raise IntegrityError("repository index fields or algorithm are invalid")
    repository = index.get("repository")
    if not isinstance(repository, dict):
        raise IntegrityError("repository index identity structure is invalid")
    verify_repository_identity(repository)
    for summary_field in (
        "file_count",
        "indexed_text_file_count",
        "symbol_count",
    ):
        if not _nonnegative_index_integer(index.get(summary_field)):
            raise IntegrityError("repository index summary values are invalid")
    exclusions = index.get("exclusions")
    if (
        not isinstance(exclusions, dict)
        or set(exclusions) - {"oversized", "binary", "unsupported_encoding"}
        or any(not _nonnegative_index_integer(item) for item in exclusions.values())
    ):
        raise IntegrityError("repository index exclusions are invalid")
    limits = index.get("limits")
    expected_limit_fields = {
        "max_text_bytes",
        "max_unique_tokens_per_file",
        "max_symbols_per_file",
        "max_index_file_records",
        "max_total_token_entries",
        "max_total_symbols",
        "max_symbol_tokens",
        "max_symbol_name_chars",
        "max_qualified_symbol_chars",
        "max_python_ast_nodes",
        "max_index_json_bytes",
        "max_index_json_items",
    }
    if (
        not isinstance(limits, dict)
        or set(limits) != expected_limit_fields
        or any(not _positive_index_integer(item) for item in limits.values())
        or limits["max_text_bytes"] > DEFAULT_MAX_TEXT_BYTES
        or limits["max_unique_tokens_per_file"] != MAX_UNIQUE_TOKENS
        or limits["max_symbols_per_file"] != MAX_SYMBOLS_PER_FILE
        or limits["max_index_file_records"] != MAX_INDEX_FILE_RECORDS
        or limits["max_total_token_entries"] != MAX_TOTAL_TOKEN_ENTRIES
        or limits["max_total_symbols"] != MAX_TOTAL_SYMBOLS
        or limits["max_symbol_tokens"] != MAX_SYMBOL_TOKENS
        or limits["max_symbol_name_chars"] != MAX_SYMBOL_NAME_CHARS
        or limits["max_qualified_symbol_chars"] != MAX_QUALIFIED_SYMBOL_CHARS
        or limits["max_python_ast_nodes"] != MAX_PYTHON_AST_NODES
        or limits["max_index_json_bytes"] != MAX_INDEX_JSON_BYTES
        or limits["max_index_json_items"] != MAX_INDEX_JSON_ITEMS
    ):
        raise IntegrityError("repository index limits are invalid")
    global_limit_reached = index.get("global_limit_reached")
    if (
        not isinstance(global_limit_reached, dict)
        or set(global_limit_reached) != {"token_entries", "symbols"}
        or any(not isinstance(item, bool) for item in global_limit_reached.values())
    ):
        raise IntegrityError("repository index global-limit status is invalid")
    files = index.get("files")
    if not isinstance(files, list) or len(files) > MAX_INDEX_FILE_RECORDS:
        raise IntegrityError("repository index files must be an array")
    paths: list[str] = []
    collision_keys: set[str] = set()
    indexed_count = 0
    symbol_count = 0
    total_bytes = 0
    actual_exclusions = Counter()
    file_required = {
        "path",
        "sha256",
        "size_bytes",
        "language",
        "content_indexed",
        "tokens",
        "symbols",
    }
    file_optional = {
        "exclusion_reason",
        "line_count",
        "token_limit_reached",
        "symbol_limit_reached",
        "symbol_extraction_issue",
    }
    for record in files:
        if (
            not isinstance(record, dict)
            or not file_required.issubset(record)
            or set(record) - file_required - file_optional
        ):
            raise IntegrityError("repository index file record is invalid")
        path = record.get("path")
        if not isinstance(path, str) or not _safe_index_path(path):
            raise IntegrityError("repository index file path is unsafe")
        paths.append(path)
        collision_key = unicodedata.normalize("NFC", path).casefold()
        if collision_key in collision_keys:
            raise IntegrityError("repository index file paths collide by case or Unicode")
        collision_keys.add(collision_key)
        if (
            not isinstance(record.get("content_indexed"), bool)
            or not isinstance(record.get("symbols"), list)
            or not isinstance(record.get("tokens"), dict)
        ):
            raise IntegrityError("repository index file content metadata is invalid")
        size = record.get("size_bytes")
        sha256 = record.get("sha256")
        if (
            not _nonnegative_index_integer(size)
            or not isinstance(sha256, str)
            or _SHA256.fullmatch(sha256) is None
            or record.get("language") not in {*LANGUAGE_BY_SUFFIX.values(), "text"}
        ):
            raise IntegrityError("repository index file identity is invalid")
        total_bytes += size
        indexed_count += int(record["content_indexed"])
        if record["content_indexed"]:
            if (
                not _nonnegative_index_integer(record.get("line_count"))
                or not isinstance(record.get("token_limit_reached"), bool)
                or not isinstance(record.get("symbol_limit_reached"), bool)
                or "exclusion_reason" in record
            ):
                raise IntegrityError("repository indexed-file metadata is invalid")
        elif (
            record.get("exclusion_reason") not in {"oversized", "binary", "unsupported_encoding"}
            or any(
                key in record
                for key in (
                    "line_count",
                    "token_limit_reached",
                    "symbol_limit_reached",
                    "symbol_extraction_issue",
                )
            )
            or record["tokens"]
            or record["symbols"]
        ):
            raise IntegrityError("repository excluded-file metadata is invalid")
        if not record["content_indexed"]:
            actual_exclusions[str(record["exclusion_reason"])] += 1
        extraction_issue = record.get("symbol_extraction_issue")
        if extraction_issue is not None and extraction_issue not in (
            "syntax_error",
            "complexity_limit",
        ):
            raise IntegrityError("repository index symbol-extraction issue is invalid")
        if len(record["tokens"]) > MAX_UNIQUE_TOKENS:
            raise IntegrityError("repository index per-file token limit is exceeded")
        for token, count in record["tokens"].items():
            if (
                not isinstance(token, str)
                or _WORD.fullmatch(token) is None
                or not _positive_index_integer(count)
                or count > 255
            ):
                raise IntegrityError("repository index token data is invalid")
        if len(record["symbols"]) > MAX_SYMBOLS_PER_FILE:
            raise IntegrityError("repository index per-file symbol limit is exceeded")
        for symbol in record["symbols"]:
            symbol_required = {
                "name",
                "qualified_name",
                "kind",
                "start_line",
                "end_line",
                "tokens",
                "extractor",
            }
            if not isinstance(symbol, dict) or set(symbol) != symbol_required:
                raise IntegrityError("repository index symbol record is invalid")
            if any(
                not isinstance(symbol.get(key), str) or not symbol[key]
                for key in ("name", "qualified_name", "kind", "extractor")
            ) or not isinstance(symbol.get("tokens"), list):
                raise IntegrityError("repository index symbol values are invalid")
            if (
                len(symbol["name"]) > MAX_SYMBOL_NAME_CHARS
                or len(symbol["qualified_name"]) > MAX_QUALIFIED_SYMBOL_CHARS
            ):
                raise IntegrityError("repository index symbol-name limit is exceeded")
            start_line = symbol.get("start_line")
            end_line = symbol.get("end_line")
            if (
                not _positive_index_integer(start_line)
                or not _positive_index_integer(end_line)
                or end_line < start_line
                or end_line > record["line_count"]
                or symbol.get("extractor") not in {"python-ast-v1", "lexical-v1"}
            ):
                raise IntegrityError("repository index symbol location is invalid")
            symbol_tokens = symbol["tokens"]
            if len(symbol_tokens) > MAX_SYMBOL_TOKENS or any(
                not isinstance(token, str) or _WORD.fullmatch(token) is None
                for token in symbol_tokens
            ):
                raise IntegrityError("repository index symbol tokens are invalid")
            if symbol_tokens != sorted(set(symbol_tokens)):
                raise IntegrityError("repository index symbol tokens are not unique and sorted")
        symbol_count += len(record["symbols"])
    token_entry_count = sum(len(record["tokens"]) for record in files)
    if token_entry_count > MAX_TOTAL_TOKEN_ENTRIES or symbol_count > MAX_TOTAL_SYMBOLS:
        raise IntegrityError("repository index global output budget is exceeded")
    if exclusions != dict(sorted(actual_exclusions.items())):
        raise IntegrityError("repository index exclusion summary is inconsistent")
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(paths) != len(
        set(paths)
    ):
        raise IntegrityError("repository index paths are not unique and sorted")
    for key, actual in (
        ("file_count", len(files)),
        ("indexed_text_file_count", indexed_count),
        ("symbol_count", symbol_count),
    ):
        if index.get(key) != actual:
            raise IntegrityError(f"repository index {key} is inconsistent")
    if repository.get("file_count") != len(files) or repository.get("total_bytes") != total_bytes:
        raise IntegrityError("repository index summary does not match its files")
    expected = stable_id("index", index, omit_keys=("index_id",))
    if (
        not isinstance(index.get("index_id"), str)
        or _INDEX_ID.fullmatch(index["index_id"]) is None
        or index["index_id"] != expected
    ):
        raise IntegrityError("repository index identity mismatch")
    if _serialized_index_size(index) > MAX_INDEX_JSON_BYTES:
        raise IntegrityError("repository index JSON artifact limit is exceeded")
    if _index_json_item_count(index) > MAX_INDEX_JSON_ITEMS:
        raise IntegrityError("repository index JSON item limit is exceeded")


def _safe_index_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and "\\" not in value
        and "\x00" not in value
        and unicodedata.normalize("NFC", value) == value
        and not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == value
        and re.match(r"^[A-Za-z]:", value) is None
    )


def _positive_index_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _nonnegative_index_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
