# SPDX-License-Identifier: Apache-2.0
"""Label-blind, product-runtime vulnerability localisation.

The builder in this module deliberately accepts a narrow inference request and
an immutable local repository snapshot.  Scoring labels, fixed revisions,
partition state, and evaluation outcomes are not part of either interface.
"""

from __future__ import annotations

import ast
import math
import re
import sys
import time
import tracemalloc
import warnings
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import (
    canonical_json_bytes,
    canonical_sha256,
    is_printable_ascii,
    sha256_bytes,
    sha256_file,
    stable_id,
)
from .errors import InputError, IntegrityError
from .findings import validate_normalized_finding
from .learned_ranker import (
    BASE_RANKER,
    LEARNED_RANKER,
    LEARNED_SUPPORT,
    rank_with_model,
    verify_model_artifact,
)
from .python_symbols import (
    scan_python_declarations,
    split_python_lines,
    supported_python_runtime,
)
from .repository import RepositoryLimits, RepositoryWorkspace

REQUEST_SCHEMA = "localization-inference-request-v0.4.1"
RAW_OUTPUT_SCHEMA = "localization-raw-ranking-v0.4.1"
ACCESS_POLICY_SCHEMA = "localization-builder-access-policy-v0.4.1"
QUARANTINE_POLICY = "target-agnostic-source-quarantine-v0.4.1.1"
V041_EVIDENCE_CANDIDATE_ALGORITHM = "label-blind-python-role-candidates-v0.4.1.5"
STEP1_DEFECTIVE_CANDIDATE_ALGORITHM = V041_EVIDENCE_CANDIDATE_ALGORITHM
STEP1_AST_CANDIDATE_ALGORITHM = "label-blind-python-role-candidates-v0.4.1.6"
STEP1_CANDIDATE_ALGORITHM = "label-blind-python-role-candidates-v0.4.1.7"
CANDIDATE_ALGORITHM = STEP1_CANDIDATE_ALGORITHM
V041_EVIDENCE_DEFAULT_RANKER = "role-aware-sparse-v0.4.1.1"
STEP1_DEFAULT_RANKER = BASE_RANKER
V05_DEFAULT_RANKER = "role-aware-sparse-v0.5.0.2"
V06_DEFAULT_RANKER = "role-aware-sparse-v0.6.0.1"
DEFAULT_RANKER = V06_DEFAULT_RANKER
V041_EVIDENCE_RUNTIME_IDENTITY = "lumi-trace-runtime-v0.4.1-pre-release.8"
STEP1_DEFECTIVE_RUNTIME_IDENTITY = "lumi-trace-runtime-v0.4.1-pre-release.9"
STEP1_AST_RUNTIME_IDENTITY = "lumi-trace-runtime-v0.4.1-pre-release.10"
STEP1_RUNTIME_IDENTITY = "lumi-trace-runtime-v0.4.1-pre-release.11"
RUNTIME_IDENTITY = STEP1_RUNTIME_IDENTITY
SUPERSEDED_STEP1_RUNTIME_IDENTITIES = frozenset(
    {STEP1_DEFECTIVE_RUNTIME_IDENTITY, STEP1_AST_RUNTIME_IDENTITY}
)
STEP1_RUNTIME_IDENTITIES = frozenset({*SUPERSEDED_STEP1_RUNTIME_IDENTITIES, STEP1_RUNTIME_IDENTITY})
SUPPORTED_RUNTIME_IDENTITIES = frozenset(
    {V041_EVIDENCE_RUNTIME_IDENTITY, *STEP1_RUNTIME_IDENTITIES}
)
RUNTIME_CANDIDATE_ALGORITHMS = {
    V041_EVIDENCE_RUNTIME_IDENTITY: V041_EVIDENCE_CANDIDATE_ALGORITHM,
    STEP1_DEFECTIVE_RUNTIME_IDENTITY: STEP1_DEFECTIVE_CANDIDATE_ALGORITHM,
    STEP1_AST_RUNTIME_IDENTITY: STEP1_AST_CANDIDATE_ALGORITHM,
    STEP1_RUNTIME_IDENTITY: STEP1_CANDIDATE_ALGORITHM,
}
PYTHON_AST_FEATURE_VERSION = (3, 11)
V041_EVIDENCE_PYTHON_VERSION = (3, 12)
STEP1_MAXIMUM_CANDIDATES = 100_000
STEP1_MAXIMUM_PYTHON_SOURCE_LINES = 200_000
NO_SIGNAL_ABSTENTION = "NO_POSITIVE_FINDING_GUIDED_SIGNAL"
CANDIDATE_TRUNCATION_ABSTENTION = "CANDIDATE_GENERATION_TRUNCATED"

FINDING_GUIDED_SCORE_COMPONENTS = frozenset(
    {
        "BM25",
        "PATH",
        "BASENAME",
        "SYMBOL",
        "CONTENT",
        "DESCRIPTION",
        "REPORTED_PATH",
        "REPORTED_SYMBOL",
    }
)

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]{1,63}")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
_CANDIDATE_ID = re.compile(r"^localization-candidate:[0-9a-f]{64}$")
_FORBIDDEN_FIELD_FRAGMENTS = {
    "accepted_target",
    "candidate_target",
    "fixed_diff",
    "fixed_revision",
    "holdback",
    "label",
    "outcome",
    "partition",
    "private_target",
    "qualification",
    "reviewer_conclusion",
    "safe_revision",
    "scoring",
    "target_path",
    "target_region",
    "target_symbol",
    "vulnerable_fixed",
}
_IGNORED_PARTS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    "__pycache__",
    "bower_components",
    "dist",
    "node_modules",
}
_VENDOR_PARTS = {
    "_vendor",
    "extern",
    "external",
    "site-packages",
    "third_party",
    "third-party",
    "vendor",
    "vendored",
}
_TEST_PARTS = {"spec", "specs", "test", "tests"}
_FIXTURE_PARTS = {"fixture", "fixtures", "testdata", "test-data"}
_GENERATED_PARTS = {"generated", "migrations"}
_WRAPPER_PARTS = {"demo", "demos", "example", "examples", "script", "scripts", "tools"}
_HIGH_CONFIDENCE_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b"),
)
_DANGEROUS_CALL_TERMS = {
    "compile",
    "deserialize",
    "eval",
    "exec",
    "extract",
    "load",
    "loads",
    "open",
    "parse",
    "pickle",
    "redirect",
    "render",
    "request",
    "run",
    "shell",
    "subprocess",
    "system",
    "template",
    "unpack",
    "url",
    "validate",
    "yaml",
}
_VULNERABILITY_SEMANTIC_EXPANSIONS = (
    (
        {
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
        {
            "access",
            "auth",
            "authorize",
            "credential",
            "decorator",
            "login",
            "middleware",
            "permission",
            "policy",
            "session",
            "token",
            "validate",
        },
    ),
    (
        {"cross", "html", "scripting", "xss"},
        {
            "escape",
            "html",
            "markup",
            "render",
            "response",
            "safe",
            "sanitize",
            "template",
        },
    ),
    (
        {"csrf", "forgery"},
        {
            "cookie",
            "csrf",
            "form",
            "origin",
            "referer",
            "request",
            "session",
            "token",
            "validate",
        },
    ),
    (
        {"directory", "path", "traversal"},
        {
            "directory",
            "extract",
            "file",
            "filename",
            "join",
            "normalize",
            "path",
            "resolve",
            "static",
        },
    ),
    (
        {"command", "execution", "injection", "rce", "shell"},
        {
            "argument",
            "cli",
            "command",
            "exec",
            "execute",
            "popen",
            "quote",
            "shell",
            "spawn",
            "subprocess",
            "system",
        },
    ),
    (
        {"dos", "exhaustion", "resource"},
        {
            "header",
            "length",
            "limit",
            "loop",
            "parse",
            "size",
            "timeout",
            "validate",
        },
    ),
    (
        {"deserialize", "deserialization", "pickle", "yaml"},
        {
            "deserialize",
            "load",
            "loads",
            "object",
            "parse",
            "pickle",
            "unpack",
            "yaml",
        },
    ),
    (
        {"redirect", "ssrf"},
        {
            "fetch",
            "host",
            "http",
            "location",
            "origin",
            "proxy",
            "redirect",
            "request",
            "scheme",
            "uri",
            "url",
        },
    ),
    (
        {"certificate", "host", "key", "ssh", "ssl", "tls", "verification"},
        {
            "certificate",
            "connect",
            "fingerprint",
            "host",
            "key",
            "known",
            "ssh",
            "ssl",
            "tls",
            "verify",
        },
    ),
    (
        {"archive", "extract", "upload"},
        {
            "archive",
            "extract",
            "file",
            "filename",
            "mime",
            "path",
            "unpack",
            "upload",
        },
    ),
)

_RANKER_PROFILES: dict[str, dict[str, int]] = {
    "role-aware-sparse-v0.4.1.1": {
        "bm25": 1000,
        "path": 900,
        "basename": 1250,
        "symbol": 1550,
        "content": 325,
        "description": 225,
        "dangerous": 350,
        "symbol_candidate": 425,
        "implementation": 900,
        "wrapper": -600,
        "test": -2600,
        "fixture": -3200,
        "generated": -2800,
        "vendor": -3500,
        "path_depth": 35,
    },
    "role-aware-sparse-v0.4.1.2": {
        "bm25": 1100,
        "path": 1000,
        "basename": 1450,
        "symbol": 1850,
        "content": 350,
        "description": 250,
        "dangerous": 525,
        "symbol_candidate": 600,
        "implementation": 1100,
        "wrapper": -750,
        "test": -3600,
        "fixture": -4200,
        "generated": -3600,
        "vendor": -4500,
        "path_depth": 40,
    },
    "role-aware-sparse-v0.4.1.3": {
        "bm25": 1250,
        "path": 1050,
        "basename": 1550,
        "symbol": 2200,
        "content": 375,
        "description": 275,
        "dangerous": 700,
        "symbol_candidate": 750,
        "implementation": 1300,
        "wrapper": -900,
        "test": -4400,
        "fixture": -5000,
        "generated": -4400,
        "vendor": -5200,
        "path_depth": 45,
    },
    "structured-role-sparse-v0.4.1.4": {
        "bm25": 1250,
        "path": 1050,
        "basename": 1550,
        "symbol": 2200,
        "content": 375,
        "description": 275,
        "dangerous": 700,
        "symbol_candidate": 1050,
        "implementation": 1300,
        "wrapper": -900,
        "test": -4400,
        "fixture": -5000,
        "generated": -4400,
        "vendor": -5200,
        "path_depth": 45,
    },
    # V0.5 development candidate.  The historical V0.4 profiles above remain
    # unchanged so the released wheel can be replayed as a true comparator.
    # These additions use only the candidate's local source and the supplied
    # finding: they do not use case labels, fixed revisions, or network data.
    "role-aware-sparse-v0.5.0.2": {
        "bm25": 1250,
        "path": 1050,
        "basename": 1550,
        "symbol": 2200,
        "content": 375,
        "description": 275,
        "dangerous": 700,
        "symbol_candidate": 750,
        "implementation": 1300,
        "wrapper": -900,
        "test": -4400,
        "fixture": -5000,
        "generated": -4400,
        "vendor": -5200,
        "path_depth": 45,
        "role_precision_divisor": 2,
    },
    # V0.6 preserves V0.5's label-blind local scoring exactly.  Its product
    # change is a versioned unique-path projection of this raw ranking, which
    # keeps V0.5 evidence and replay semantics available unchanged.
    "role-aware-sparse-v0.6.0.1": {
        "bm25": 1250,
        "path": 1050,
        "basename": 1550,
        "symbol": 2200,
        "content": 375,
        "description": 275,
        "dangerous": 700,
        "symbol_candidate": 750,
        "implementation": 1300,
        "wrapper": -900,
        "test": -4400,
        "fixture": -5000,
        "generated": -4400,
        "vendor": -5200,
        "path_depth": 45,
        "role_precision_divisor": 2,
    },
}


def _tokens(value: str | Sequence[str]) -> list[str]:
    text = value if isinstance(value, str) else " ".join(value)
    return [match.group(0).casefold() for match in _TOKEN.finditer(text)]


def _contains_forbidden_field(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(fragment in normalized for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
                return True
            if _contains_forbidden_field(child):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_field(item) for item in value)
    return False


def _candidate_algorithm_for_runtime(runtime_identity: str) -> str:
    try:
        return RUNTIME_CANDIDATE_ALGORITHMS[runtime_identity]
    except KeyError as exc:
        raise InputError("unsupported localization runtime identity") from exc


def _project_finding(
    finding: Mapping[str, Any],
    *,
    runtime_identity: str,
) -> dict[str, Any]:
    """Construct the allowed finding view instead of deleting forbidden keys."""

    source_fields = [
        "kind",
        "input_sha256",
        "sarif_run_index",
        "sarif_result_index",
    ]
    if runtime_identity in STEP1_RUNTIME_IDENTITIES:
        source_fields[2:2] = ["tool_name", "tool_version"]
    projected = {
        "schema_version": finding.get("schema_version"),
        "source": {
            key: finding.get("source", {}).get(key)
            for key in source_fields
            if key in finding.get("source", {})
        },
        "rule": {
            "id": finding.get("rule", {}).get("id"),
            "name": finding.get("rule", {}).get("name"),
            "cwes": list(finding.get("rule", {}).get("cwes", [])),
            "tags": list(finding.get("rule", {}).get("tags", [])),
        },
        "message": {
            "title": finding.get("message", {}).get("title"),
            "text": finding.get("message", {}).get("text"),
        },
        "severity": {
            "normalized": finding.get("severity", {}).get("normalized"),
            "original": finding.get("severity", {}).get("original"),
        },
        "locations": [
            {key: location[key] for key in ("path", "symbol", "region") if key in location}
            for location in finding.get("locations", [])
        ],
        "keywords": list(finding.get("keywords", [])),
        "fingerprints": dict(finding.get("fingerprints", {})),
        "finding_id": finding.get("finding_id"),
    }
    validate_normalized_finding(projected)
    return projected


def construct_inference_request(
    *,
    finding: Mapping[str, Any],
    repository_artifact_sha256: str,
    source_kind: str,
    ranker: str = DEFAULT_RANKER,
    top_k: int = 1000,
    maximum_candidates: int = 10_000,
    maximum_files: int = 100_000,
    maximum_total_bytes: int = 2 * 1024 * 1024 * 1024,
    maximum_file_bytes: int = 2 * 1024 * 1024,
    measure_peak_memory: bool = True,
    model_artifact: Mapping[str, Any] | None = None,
    runtime_identity: str = RUNTIME_IDENTITY,
) -> dict[str, Any]:
    """Create the only object accepted by the inference builder."""

    if runtime_identity in SUPERSEDED_STEP1_RUNTIME_IDENTITIES:
        raise InputError("superseded Step 1 runtime is verification-only")
    if runtime_identity == STEP1_RUNTIME_IDENTITY and not supported_python_runtime():
        raise InputError(
            "current Step 1 runtime requires CPython 3.11 or 3.12 with the governed recursion limit"
        )
    model_binding = None
    if model_artifact is not None:
        verified_model = verify_model_artifact(model_artifact)
        model_binding = {
            "artifact_id": verified_model["artifact_id"],
            "canonical_sha256": sha256_bytes(canonical_json_bytes(verified_model)),
        }
    value = {
        "schema_version": REQUEST_SCHEMA,
        "finding": _project_finding(finding, runtime_identity=runtime_identity),
        "repository": {
            "artifact_sha256": repository_artifact_sha256,
            "source_kind": source_kind,
        },
        "configuration": {
            "runtime_identity": runtime_identity,
            "quarantine_policy": QUARANTINE_POLICY,
            "candidate_algorithm": _candidate_algorithm_for_runtime(runtime_identity),
            "ranker": ranker,
            "top_k": top_k,
            "maximum_candidates": maximum_candidates,
            "maximum_files": maximum_files,
            "maximum_total_bytes": maximum_total_bytes,
            "maximum_file_bytes": maximum_file_bytes,
            "measure_peak_memory": measure_peak_memory,
            "model": model_binding,
        },
    }
    value["request_id"] = stable_id("localization-request", value)
    validate_inference_request(value)
    return value


def validate_inference_request(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reject broad receipts and every known answer-bearing field."""

    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "finding",
        "repository",
        "configuration",
        "request_id",
    }:
        raise InputError("localization builder accepts only the allowed-field request")
    if value.get("schema_version") != REQUEST_SCHEMA or _contains_forbidden_field(value):
        raise InputError("localization request contains a forbidden inference field")
    finding = value.get("finding")
    if not isinstance(finding, dict):
        raise InputError("localization request finding is invalid")
    validate_normalized_finding(finding)
    repository = value.get("repository")
    if (
        not isinstance(repository, dict)
        or set(repository) != {"artifact_sha256", "source_kind"}
        or repository.get("source_kind") not in {"archive", "directory"}
        or not isinstance(repository.get("artifact_sha256"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", repository["artifact_sha256"]) is None
    ):
        raise InputError("localization request repository projection is invalid")
    configuration = value.get("configuration")
    required_configuration = {
        "runtime_identity",
        "quarantine_policy",
        "candidate_algorithm",
        "ranker",
        "top_k",
        "maximum_candidates",
        "maximum_files",
        "maximum_total_bytes",
        "maximum_file_bytes",
        "measure_peak_memory",
        "model",
    }
    if (
        not isinstance(configuration, dict)
        or set(configuration) != required_configuration
        or configuration.get("runtime_identity") not in SUPPORTED_RUNTIME_IDENTITIES
        or configuration.get("quarantine_policy") != QUARANTINE_POLICY
        or configuration.get("candidate_algorithm")
        != RUNTIME_CANDIDATE_ALGORITHMS.get(str(configuration.get("runtime_identity")))
        or configuration.get("ranker") not in {*_RANKER_PROFILES, LEARNED_RANKER}
    ):
        raise InputError("localization request configuration is invalid")
    model_binding = configuration.get("model")
    if configuration["ranker"] == LEARNED_RANKER:
        if (
            not isinstance(model_binding, dict)
            or set(model_binding) != {"artifact_id", "canonical_sha256"}
            or re.fullmatch(
                r"lumi-trace-localization-model:[0-9a-f]{64}",
                str(model_binding.get("artifact_id", "")),
            )
            is None
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(model_binding.get("canonical_sha256", "")),
            )
            is None
        ):
            raise InputError("learned localization request has no bound model")
    elif model_binding is not None:
        raise InputError("deterministic localization request cannot bind a model")
    for key, minimum, maximum in (
        ("top_k", 1, 1000),
        ("maximum_candidates", 20, 100_000),
        ("maximum_files", 1, 1_000_000),
        ("maximum_total_bytes", 1, 16 * 1024 * 1024 * 1024),
        ("maximum_file_bytes", 1, 16 * 1024 * 1024),
    ):
        item = configuration.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item <= maximum:
            raise InputError(f"localization request {key} bound is invalid")
    if not isinstance(configuration.get("measure_peak_memory"), bool):
        raise InputError("localization request memory measurement flag is invalid")
    if configuration["top_k"] > configuration["maximum_candidates"]:
        raise InputError("localization top_k exceeds the candidate bound")
    expected = stable_id("localization-request", value, omit_keys=("request_id",))
    if value.get("request_id") != expected:
        raise IntegrityError("localization request identity mismatch")
    return dict(value)


def build_access_policy(
    *, allowed_roots: Sequence[Path], forbidden_roots: Sequence[Path] = ()
) -> dict[str, Any]:
    allowed = sorted({str(path.resolve(strict=True)) for path in allowed_roots})
    forbidden = sorted({str(path.resolve(strict=True)) for path in forbidden_roots})
    if not allowed:
        raise InputError("builder access policy needs at least one allowed root")
    value = {
        "schema_version": ACCESS_POLICY_SCHEMA,
        "allowed_roots": allowed,
        "forbidden_roots": forbidden,
    }
    value["policy_id"] = stable_id("localization-builder-access-policy", value)
    return value


def validate_access_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "allowed_roots",
            "forbidden_roots",
            "policy_id",
        }
        or value.get("schema_version") != ACCESS_POLICY_SCHEMA
        or not isinstance(value.get("allowed_roots"), list)
        or not value["allowed_roots"]
        or not isinstance(value.get("forbidden_roots"), list)
        or any(
            not isinstance(item, str) or not Path(item).is_absolute()
            for item in [*value["allowed_roots"], *value["forbidden_roots"]]
        )
    ):
        raise InputError("builder access policy is invalid")
    expected = stable_id(
        "localization-builder-access-policy",
        value,
        omit_keys=("policy_id",),
    )
    if value.get("policy_id") != expected:
        raise IntegrityError("builder access policy identity mismatch")
    return dict(value)


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def assert_builder_path(path: Path, policy: Mapping[str, Any], *, must_exist: bool) -> Path:
    validated = validate_access_policy(policy)
    resolved = path.resolve(strict=must_exist)
    allowed = [Path(item).resolve(strict=True) for item in validated["allowed_roots"]]
    forbidden = [Path(item).resolve(strict=True) for item in validated["forbidden_roots"]]
    if not any(_within(resolved, root) for root in allowed):
        raise InputError("builder path lies outside its allowed roots")
    if any(_within(resolved, root) or _within(root, resolved) for root in forbidden):
        raise InputError("builder path intersects a forbidden root")
    return resolved


def _path_role(path: str) -> str:
    pure = PurePosixPath(path)
    parts = {part.casefold() for part in pure.parts}
    stem = pure.stem.casefold()
    if parts & _VENDOR_PARTS:
        return "vendor"
    if parts & _FIXTURE_PARTS:
        return "fixture"
    if parts & _TEST_PARTS or stem.startswith("test_") or stem.endswith("_test"):
        return "test"
    if parts & _GENERATED_PARTS or stem.endswith(("_generated", "_pb2", "_pb2_grpc")):
        return "generated"
    if parts & _WRAPPER_PARTS:
        return "wrapper"
    return "implementation"


def _quarantine_reason(path: str, data: bytes) -> str | None:
    pure = PurePosixPath(path)
    if any(part.casefold() in _IGNORED_PARTS for part in pure.parts):
        return "IGNORED_TREE"
    if pure.suffix.casefold() != ".py":
        return "NON_PYTHON"
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        return "NON_UTF8"
    if any(pattern.search(source) for pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS):
        return "HIGH_CONFIDENCE_SECRET"
    return None


def _symbols_ast(
    source: str,
    *,
    maximum_symbols: int | None = None,
    feature_version: tuple[int, int] | None = PYTHON_AST_FEATURE_VERSION,
) -> tuple[list[dict[str, Any]], bool]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            tree = (
                ast.parse(source)
                if feature_version is None
                else ast.parse(source, feature_version=feature_version)
            )
    except (SyntaxError, SyntaxWarning, ValueError, RecursionError):
        return [], False
    # Historical reconstruction retains its original host-parser line
    # projection. The current product scanner below uses fixed newline rules.
    lines = source.splitlines()
    result: list[dict[str, Any]] = []
    stack: list[tuple[ast.AST, tuple[str, ...]]] = [(tree, ())]
    while stack:
        node, parents = stack.pop()
        name = getattr(node, "name", None)
        qualified = (*parents, name) if isinstance(name, str) else parents
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if maximum_symbols is not None and len(result) >= maximum_symbols:
                return result, True
            start = int(getattr(node, "lineno", 1))
            end = int(getattr(node, "end_lineno", start))
            result.append(
                {
                    "name": str(name),
                    "qualified_name": ".".join(qualified),
                    "kind": (
                        "class"
                        if isinstance(node, ast.ClassDef)
                        else "async_function"
                        if isinstance(node, ast.AsyncFunctionDef)
                        else "function"
                    ),
                    "start_line": start,
                    "end_line": end,
                    "source": "\n".join(lines[max(0, start - 1) : end])[:131_072],
                }
            )
        children = list(ast.iter_child_nodes(node))
        stack.extend((child, qualified) for child in reversed(children))
    return result, False


def _symbols(
    source: str,
    *,
    maximum_symbols: int | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    declarations, issue, limited = scan_python_declarations(
        source,
        maximum_symbols=STEP1_MAXIMUM_CANDIDATES if maximum_symbols is None else maximum_symbols,
        maximum_lines=STEP1_MAXIMUM_PYTHON_SOURCE_LINES,
        maximum_name_chars=256,
        maximum_qualified_name_chars=1_024,
    )
    if issue is not None:
        return [], False
    lines = split_python_lines(source)
    return (
        [
            {
                "name": declaration["name"],
                "qualified_name": declaration["qualified_name"],
                "kind": declaration["declaration_kind"],
                "start_line": declaration["start_line"],
                "end_line": declaration["end_line"],
                "source": "\n".join(
                    lines[max(0, int(declaration["start_line"]) - 1) : int(declaration["end_line"])]
                )[:131_072],
            }
            for declaration in declarations
        ],
        limited,
    )


def _query(finding: Mapping[str, Any]) -> dict[str, Any]:
    location_paths: set[str] = set()
    location_symbols: set[str] = set()
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
        location_paths.add(str(location["path"]))
        values.append(str(location["path"]))
        if location.get("symbol"):
            location_symbols.add(str(location["symbol"]).casefold())
            values.append(str(location["symbol"]))
    description_values = [
        str(finding["message"]["title"]),
        str(finding["message"]["text"]),
    ]
    terms = Counter(_tokens(values))
    observed = set(terms)
    for triggers, expansions in _VULNERABILITY_SEMANTIC_EXPANSIONS:
        if triggers & observed:
            terms.update(sorted(expansions))
    return {
        "terms": terms,
        "description": Counter(_tokens(description_values)),
        "reported_paths": location_paths,
        "reported_symbols": location_symbols,
    }


def _overlap(query: Counter[str], values: Sequence[str]) -> int:
    return sum((query & Counter(item.casefold() for item in values)).values())


def _candidate(
    *,
    path: str,
    source: str,
    symbol: Mapping[str, Any] | None,
    query: Mapping[str, Any],
    fixed_newlines: bool = True,
) -> dict[str, Any]:
    role = _path_role(path)
    symbol_name = str(symbol["qualified_name"]) if symbol else ""
    path_tokens = _tokens(PurePosixPath(path).as_posix().replace("/", " "))
    basename_tokens = _tokens(PurePosixPath(path).stem)
    symbol_tokens = _tokens(symbol_name)
    source_tokens = _tokens(source[:131_072])
    query_terms = set(query["terms"]) | set(query["description"])
    matched = list(dict.fromkeys(item for item in source_tokens if item in query_terms))
    content_tokens = matched[:512]
    kind = "symbol" if symbol else "file"
    start = int(symbol["start_line"]) if symbol else 1
    end = (
        int(symbol["end_line"])
        if symbol
        else max(1, len(split_python_lines(source) if fixed_newlines else source.splitlines()))
    )
    identity = {
        "kind": kind,
        "path": path,
        "symbol": symbol_name or None,
        "start_line": start,
        "end_line": end,
        "role": role,
    }
    return {
        "candidate_id": stable_id("localization-candidate", identity),
        **identity,
        "path_tokens": path_tokens,
        "basename_tokens": basename_tokens,
        "symbol_tokens": symbol_tokens,
        "content_tokens": content_tokens,
        "features": {
            "path_overlap": _overlap(query["terms"], path_tokens),
            "basename_overlap": _overlap(query["terms"], basename_tokens),
            "symbol_overlap": _overlap(query["terms"], symbol_tokens),
            "content_overlap": _overlap(query["terms"], content_tokens),
            "description_overlap": _overlap(query["description"], content_tokens),
            "dangerous_overlap": len(set(source_tokens) & _DANGEROUS_CALL_TERMS),
            "path_depth": len(PurePosixPath(path).parts),
            "source_token_count": len(source_tokens),
            "reported_path": path in query["reported_paths"],
            "reported_symbol": symbol_name.casefold() in query["reported_symbols"],
        },
    }


def _enumerate_candidates(
    root: Path,
    finding: Mapping[str, Any],
    *,
    maximum_files: int,
    maximum_total_bytes: int,
    maximum_file_bytes: int,
    maximum_candidates: int,
    strict_candidate_bound: bool = False,
    use_historical_ast: bool = False,
    require_ascii_paths: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    query = _query(finding)
    candidates: list[dict[str, Any]] = []
    excluded = Counter()
    file_count = 0
    total_bytes = 0
    indexed_paths: list[str] = []
    candidate_universe_truncated = False
    entries = sorted(
        (item for item in root.rglob("*") if item.is_file() and not item.is_symlink()),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    )
    for path in entries:
        relative = path.relative_to(root).as_posix()
        if require_ascii_paths and not is_printable_ascii(relative):
            raise InputError(
                "current Step 1 runtime requires printable ASCII repository paths "
                "for cross-runtime determinism"
            )
        file_count += 1
        if file_count > maximum_files:
            raise InputError("repository exceeds the localization file bound")
        size = path.stat().st_size
        total_bytes += size
        if total_bytes > maximum_total_bytes:
            raise InputError("repository exceeds the localization byte bound")
        if size > maximum_file_bytes:
            excluded["FILE_TOO_LARGE"] += 1
            continue
        data = path.read_bytes()
        reason = _quarantine_reason(relative, data)
        if reason:
            excluded[reason] += 1
            continue
        source = data.decode("utf-8")
        indexed_paths.append(relative)
        if strict_candidate_bound and candidate_universe_truncated:
            continue
        candidates.append(
            _candidate(
                path=relative,
                source=source,
                symbol=None,
                query=query,
                fixed_newlines=not use_historical_ast,
            )
        )
        symbol_limit = (
            max(0, maximum_candidates + 1 - len(candidates)) if strict_candidate_bound else None
        )
        if use_historical_ast:
            symbols, symbol_limit_reached = _symbols_ast(
                source,
                maximum_symbols=symbol_limit,
                feature_version=None,
            )
        else:
            symbols, symbol_limit_reached = _symbols(
                source,
                maximum_symbols=symbol_limit,
            )
        for symbol in symbols:
            candidates.append(
                _candidate(
                    path=relative,
                    source=str(symbol["source"]),
                    symbol=symbol,
                    query=query,
                    fixed_newlines=not use_historical_ast,
                )
            )
        if strict_candidate_bound and (
            symbol_limit_reached or len(candidates) > maximum_candidates
        ):
            # A Step 1 result with an incomplete candidate universe will
            # abstain. Continue only the bounded repository inventory scan;
            # do not retain or score an unbounded intermediate candidate set.
            candidate_universe_truncated = True
    if len(candidates) > maximum_candidates:
        # The selection key uses only finding and repository facts.  Preserve
        # broad file coverage before adding the strongest symbol candidates.
        files = [item for item in candidates if item["kind"] == "file"]
        symbols = [item for item in candidates if item["kind"] == "symbol"]
        preliminary = lambda item: (  # noqa: E731
            -(
                5 * item["features"]["symbol_overlap"]
                + 3 * item["features"]["basename_overlap"]
                + 2 * item["features"]["path_overlap"]
                + item["features"]["content_overlap"]
            ),
            item["candidate_id"],
        )
        file_budget = min(len(files), max(1, maximum_candidates * 3 // 5))
        selected_files = sorted(files, key=preliminary)[:file_budget]
        selected_symbols = sorted(symbols, key=preliminary)[
            : maximum_candidates - len(selected_files)
        ]
        candidates = [*selected_files, *selected_symbols]
        truncated = True
    else:
        truncated = candidate_universe_truncated
    return candidates, {
        "repository_file_count": file_count,
        "repository_bytes": total_bytes,
        "indexed_python_file_count": len(indexed_paths),
        "candidate_count": len(candidates),
        "truncated": truncated,
        "quarantine_counts": dict(sorted(excluded.items())),
        "indexed_path_set_id": stable_id("localization-indexed-paths", indexed_paths),
    }


def _rank(
    candidates: list[dict[str, Any]],
    finding: Mapping[str, Any],
    *,
    algorithm: str,
    model_artifact: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    base_algorithm = BASE_RANKER if algorithm == LEARNED_RANKER else algorithm
    profile = _RANKER_PROFILES[base_algorithm]
    query = _query(finding)
    query_tokens = set(query["terms"])
    documents: list[tuple[Counter[str], int]] = []
    frequencies: Counter[str] = Counter()
    for candidate in candidates:
        counts: Counter[str] = Counter()
        counts.update(
            {
                token: count * 3
                for token, count in Counter(candidate["path_tokens"]).items()
                if token in query_tokens
            }
        )
        counts.update(
            {
                token: count * 4
                for token, count in Counter(candidate["basename_tokens"]).items()
                if token in query_tokens
            }
        )
        counts.update(
            {
                token: count * 5
                for token, count in Counter(candidate["symbol_tokens"]).items()
                if token in query_tokens
            }
        )
        counts.update(token for token in candidate["content_tokens"] if token in query_tokens)
        frequencies.update(counts.keys())
        document_length = (
            3 * len(candidate["path_tokens"])
            + 4 * len(candidate["basename_tokens"])
            + 5 * len(candidate["symbol_tokens"])
            + int(candidate["features"]["source_token_count"])
        )
        documents.append((counts, document_length))
    average_length = (
        sum(document_length for _, document_length in documents) / len(documents)
        if documents
        else 0.0
    )
    ranked: list[dict[str, Any]] = []
    for candidate, (document_counts, document_length) in zip(
        candidates,
        documents,
        strict=True,
    ):
        bm25 = 0.0
        for token, query_frequency in query["terms"].items():
            frequency = document_counts[token]
            if not frequency:
                continue
            inverse_frequency = math.log(
                1 + (len(documents) - frequencies[token] + 0.5) / (frequencies[token] + 0.5)
            )
            denominator = frequency + 1.2 * (
                0.25 + 0.75 * (document_length / average_length if average_length else 0.0)
            )
            bm25 += query_frequency * inverse_frequency * (frequency * 2.2 / denominator)
        features = candidate["features"]
        components = {
            "BM25": round(bm25 * profile["bm25"]),
            "PATH": int(features["path_overlap"]) * profile["path"],
            "BASENAME": int(features["basename_overlap"]) * profile["basename"],
            "SYMBOL": int(features["symbol_overlap"]) * profile["symbol"],
            "CONTENT": int(features["content_overlap"]) * profile["content"],
            "DESCRIPTION": int(features["description_overlap"]) * profile["description"],
            "DANGEROUS_CONTEXT": min(4, int(features["dangerous_overlap"])) * profile["dangerous"],
            "SYMBOL_CANDIDATE": profile["symbol_candidate"] if candidate["kind"] == "symbol" else 0,
            "ROLE": profile[candidate["role"]],
            "PATH_DEPTH": max(0, 12 - int(features["path_depth"])) * profile["path_depth"],
            "REPORTED_PATH": 100_000 if features["reported_path"] else 0,
            "REPORTED_SYMBOL": 80_000 if features["reported_symbol"] else 0,
        }
        if "role_precision_divisor" in profile:
            role_precision_base = max(0, sum(components.values()))
            components["ROLE_PRECISION"] = (
                -(role_precision_base // profile["role_precision_divisor"])
                if candidate["role"] in {"test", "fixture", "generated", "vendor"}
                and not features["reported_path"]
                and not features["reported_symbol"]
                else 0
            )
        score = sum(components.values())
        ranked.append(
            {
                "candidate_id": candidate["candidate_id"],
                "kind": candidate["kind"],
                "path": candidate["path"],
                "symbol": candidate["symbol"],
                "region": {
                    "start_line": candidate["start_line"],
                    "end_line": candidate["end_line"],
                },
                "role": candidate["role"],
                "integer_score": score,
                "score_components": components,
            }
        )
    ranked.sort(
        key=lambda item: (
            -item["integer_score"],
            item["path"],
            item["region"]["start_line"],
            item["candidate_id"],
        )
    )
    if algorithm == "structured-role-sparse-v0.4.1.4":
        by_path: dict[str, list[dict[str, Any]]] = {}
        path_order: list[str] = []
        for item in ranked:
            if item["path"] not in by_path:
                by_path[item["path"]] = []
                path_order.append(item["path"])
            by_path[item["path"]].append(item)
        representatives = [
            next(
                (
                    item
                    for item in by_path[path]
                    if item["kind"] == "symbol" and item["role"] == "implementation"
                ),
                by_path[path][0],
            )
            for path in path_order
        ]
        representative_ids = {item["candidate_id"] for item in representatives}
        ranked = [
            *representatives,
            *[item for item in ranked if item["candidate_id"] not in representative_ids],
        ]
    for position, candidate in enumerate(ranked, start=1):
        candidate["rank"] = position
    if algorithm == LEARNED_RANKER:
        if model_artifact is None:
            raise IntegrityError("learned ranker model artifact is unavailable")
        ranked = [
            *rank_with_model(finding, ranked[:LEARNED_SUPPORT], model_artifact),
            *ranked[LEARNED_SUPPORT:],
        ]
        for position, candidate in enumerate(ranked, start=1):
            candidate["rank"] = position
    return ranked


def finding_guided_score(candidate: Mapping[str, Any]) -> int:
    """Return only score components tied to the supplied finding.

    Role, path-depth, symbol-kind, and generic dangerous-call priors can order
    otherwise relevant candidates, but cannot independently justify a
    non-abstaining product result.
    """

    components = candidate.get("score_components")
    if not isinstance(components, Mapping):
        return 0
    return sum(
        int(points)
        for code, points in components.items()
        if code in FINDING_GUIDED_SCORE_COMPONENTS
        and isinstance(points, int)
        and not isinstance(points, bool)
    )


def build_raw_localization(
    request: Mapping[str, Any],
    *,
    repository_source: Path,
    access_policy: Mapping[str, Any] | None = None,
    model_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the product implementation with no scoring or evaluation inputs."""

    validated = validate_inference_request(request)
    runtime_identity = str(validated["configuration"]["runtime_identity"])
    if runtime_identity in SUPERSEDED_STEP1_RUNTIME_IDENTITIES:
        raise InputError("superseded Step 1 runtime is verification-only")
    if runtime_identity == V041_EVIDENCE_RUNTIME_IDENTITY and (
        sys.implementation.name != "cpython" or sys.version_info[:2] != V041_EVIDENCE_PYTHON_VERSION
    ):
        raise InputError("historical V0.4.1 runtime reconstruction requires CPython 3.12")
    if runtime_identity == STEP1_RUNTIME_IDENTITY and not supported_python_runtime():
        raise InputError(
            "current Step 1 runtime requires CPython 3.11 or 3.12 with the governed recursion limit"
        )
    model_binding = validated["configuration"]["model"]
    verified_model = None
    if validated["configuration"]["ranker"] == LEARNED_RANKER:
        if model_artifact is None:
            raise InputError("learned localization requires the bound model artifact")
        verified_model = verify_model_artifact(model_artifact)
        if (
            verified_model["artifact_id"] != model_binding["artifact_id"]
            or sha256_bytes(canonical_json_bytes(verified_model))
            != model_binding["canonical_sha256"]
        ):
            raise IntegrityError("learned localization model differs from request binding")
    elif model_artifact is not None:
        raise InputError("deterministic localization cannot receive a model artifact")
    source = (
        assert_builder_path(repository_source, access_policy, must_exist=True)
        if access_policy is not None
        else repository_source.resolve(strict=True)
    )
    expected_hash = validated["repository"]["artifact_sha256"]
    if source.is_file() and sha256_file(source) != expected_hash:
        raise IntegrityError("repository artifact identity differs from the request")
    started_wall = time.perf_counter()
    started_cpu = time.process_time()
    measure_peak_memory = bool(validated["configuration"]["measure_peak_memory"])
    if measure_peak_memory:
        tracemalloc.start()
    with RepositoryWorkspace(
        source,
        RepositoryLimits(
            max_files=int(validated["configuration"]["maximum_files"]),
            max_bytes=int(validated["configuration"]["maximum_total_bytes"]),
            max_archive_member_bytes=min(
                int(validated["configuration"]["maximum_total_bytes"]),
                256 * 1024 * 1024,
            ),
        ),
    ) as workspace:
        if workspace.root is None or workspace.identity is None:
            raise IntegrityError("repository workspace did not materialize")
        if source.is_dir() and canonical_sha256(workspace.identity["manifest_id"]) != expected_hash:
            raise IntegrityError("repository directory identity differs from the request")
        candidates, generation = _enumerate_candidates(
            workspace.root,
            validated["finding"],
            maximum_files=int(validated["configuration"]["maximum_files"]),
            maximum_total_bytes=int(validated["configuration"]["maximum_total_bytes"]),
            maximum_file_bytes=int(validated["configuration"]["maximum_file_bytes"]),
            maximum_candidates=int(validated["configuration"]["maximum_candidates"]),
            strict_candidate_bound=runtime_identity in STEP1_RUNTIME_IDENTITIES,
            use_historical_ast=runtime_identity == V041_EVIDENCE_RUNTIME_IDENTITY,
            require_ascii_paths=runtime_identity != V041_EVIDENCE_RUNTIME_IDENTITY,
        )
        ranked = _rank(
            candidates,
            validated["finding"],
            algorithm=str(validated["configuration"]["ranker"]),
            model_artifact=verified_model,
        )
        peak_memory = tracemalloc.get_traced_memory()[1] if measure_peak_memory else None
    if measure_peak_memory:
        tracemalloc.stop()
    selected = ranked[: int(validated["configuration"]["top_k"])]
    if runtime_identity == V041_EVIDENCE_RUNTIME_IDENTITY:
        # Preserve the sealed V0.4.1 runtime's original decision rule. Step 1
        # uses the stricter finding-guided and truncation-aware rule below.
        abstained = not selected or int(selected[0]["integer_score"]) <= 0
        abstention_reason = NO_SIGNAL_ABSTENTION if abstained else None
    elif generation["truncated"]:
        abstained = True
        abstention_reason = CANDIDATE_TRUNCATION_ABSTENTION
    else:
        abstained = not selected or finding_guided_score(selected[0]) <= 0
        abstention_reason = NO_SIGNAL_ABSTENTION if abstained else None
    inventory = sorted(
        [
            {
                "candidate_id": item["candidate_id"],
                "kind": item["kind"],
                "path": item["path"],
                "symbol": item["symbol"],
                "region": item["region"],
                "role": item["role"],
            }
            for item in ranked
        ],
        key=lambda item: item["candidate_id"],
    )
    payload = {
        "schema_version": RAW_OUTPUT_SCHEMA,
        "request_id": validated["request_id"],
        "runtime_identity": runtime_identity,
        "repository": {
            "repository_id": workspace.identity["repository_id"],
            "manifest_id": workspace.identity["manifest_id"],
            "source_kind": workspace.identity["source_kind"],
        },
        "quarantine_policy": QUARANTINE_POLICY,
        "candidate_algorithm": RUNTIME_CANDIDATE_ALGORITHMS[runtime_identity],
        "ranker": validated["configuration"]["ranker"],
        "model_artifact_id": None if verified_model is None else verified_model["artifact_id"],
        "generation": generation,
        "candidate_count_ranked": len(ranked),
        "candidate_inventory": inventory,
        "candidates": selected,
        "abstention": {
            "abstained": abstained,
            "reason": abstention_reason,
        },
        "telemetry": {
            "wall_seconds": time.perf_counter() - started_wall,
            "cpu_seconds": time.process_time() - started_cpu,
            "peak_python_bytes": peak_memory,
            "peak_memory_measured": measure_peak_memory,
            "network_used": False,
            "repository_code_executed": False,
        },
        "confidence_is_not_probability": True,
    }
    payload["ranking_id"] = stable_id(
        "localization-ranking",
        [item["candidate_id"] for item in selected],
    )
    payload["raw_output_seal"] = stable_id("localization-raw-output", payload)
    verify_raw_localization(payload)
    return payload


def _verified_raw_candidate_id(
    candidate: Mapping[str, Any],
    *,
    require_printable_ascii: bool,
) -> str:
    candidate_id = candidate.get("candidate_id")
    kind = candidate.get("kind")
    role = candidate.get("role")
    if (
        not isinstance(candidate_id, str)
        or _CANDIDATE_ID.fullmatch(candidate_id) is None
        or kind not in {"file", "symbol"}
        or role not in {"implementation", "wrapper", "test", "fixture", "generated", "vendor"}
    ):
        raise IntegrityError("raw localization candidate identity fields are invalid")
    path = candidate.get("path")
    pure = PurePosixPath(path) if isinstance(path, str) else None
    if (
        pure is None
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in path
        or "\x00" in path
        or not path
        or pure.as_posix() != path
        or re.match(r"^[A-Za-z]:", path)
        or require_printable_ascii
        and not is_printable_ascii(path)
    ):
        raise IntegrityError("raw localization candidate path is unsafe")
    symbol = candidate.get("symbol")
    if (kind == "symbol" and (not isinstance(symbol, str) or not symbol)) or (
        kind == "file" and symbol is not None
    ):
        raise IntegrityError("raw localization candidate symbol contract is invalid")
    region = candidate.get("region")
    if (
        not isinstance(region, dict)
        or set(region) != {"start_line", "end_line"}
        or any(
            not isinstance(region.get(key), int) or isinstance(region[key], bool) or region[key] < 1
            for key in ("start_line", "end_line")
        )
        or region["end_line"] < region["start_line"]
    ):
        raise IntegrityError("raw localization candidate region is invalid")
    expected_id = stable_id(
        "localization-candidate",
        {
            "kind": kind,
            "path": path,
            "symbol": symbol,
            "start_line": region["start_line"],
            "end_line": region["end_line"],
            "role": role,
        },
    )
    if candidate_id != expected_id:
        raise IntegrityError("raw localization candidate identity mismatch")
    return candidate_id


def verify_raw_localization(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != RAW_OUTPUT_SCHEMA
        or value.get("runtime_identity") not in SUPPORTED_RUNTIME_IDENTITIES
        or value.get("quarantine_policy") != QUARANTINE_POLICY
        or value.get("candidate_algorithm")
        != RUNTIME_CANDIDATE_ALGORITHMS.get(str(value.get("runtime_identity")))
        or value.get("ranker") not in {*_RANKER_PROFILES, LEARNED_RANKER}
        or not isinstance(value.get("candidate_inventory"), list)
        or len(value["candidate_inventory"]) > 100_000
        or not isinstance(value.get("candidates"), list)
        or len(value["candidates"]) > 1000
        or value.get("candidate_count_ranked") != len(value["candidate_inventory"])
        or value.get("confidence_is_not_probability") is not True
    ):
        raise IntegrityError("raw localization output contract is invalid")
    if (
        value["ranker"] == LEARNED_RANKER
        and re.fullmatch(
            r"lumi-trace-localization-model:[0-9a-f]{64}",
            str(value.get("model_artifact_id", "")),
        )
        is None
    ) or (value["ranker"] != LEARNED_RANKER and value.get("model_artifact_id") is not None):
        raise IntegrityError("raw localization model binding is invalid")
    generation = value.get("generation")
    if (
        not isinstance(generation, dict)
        or not isinstance(generation.get("truncated"), bool)
        or not isinstance(generation.get("candidate_count"), int)
        or isinstance(generation.get("candidate_count"), bool)
    ):
        raise IntegrityError("raw localization generation summary is invalid")
    abstention = value.get("abstention")
    allowed_abstention_reasons = {NO_SIGNAL_ABSTENTION}
    if value["runtime_identity"] in STEP1_RUNTIME_IDENTITIES:
        allowed_abstention_reasons.add(CANDIDATE_TRUNCATION_ABSTENTION)
    if (
        not isinstance(abstention, dict)
        or set(abstention) != {"abstained", "reason"}
        or not isinstance(abstention.get("abstained"), bool)
        or (abstention["abstained"] and abstention.get("reason") not in allowed_abstention_reasons)
        or (not abstention["abstained"] and abstention.get("reason") is not None)
    ):
        raise IntegrityError("raw localization abstention is invalid")
    if value["runtime_identity"] in STEP1_RUNTIME_IDENTITIES:
        candidates = value.get("candidates")
        no_signal = (
            not isinstance(candidates, list)
            or not candidates
            or finding_guided_score(candidates[0]) <= 0
        )
        expected_reason = (
            CANDIDATE_TRUNCATION_ABSTENTION
            if generation["truncated"]
            else NO_SIGNAL_ABSTENTION
            if no_signal
            else None
        )
        if (
            abstention["abstained"] is not (expected_reason is not None)
            or abstention["reason"] != expected_reason
        ):
            raise IntegrityError("raw localization abstention does not match finding-guided signal")
    else:
        candidates = value.get("candidates")
        expected_abstained = (
            not isinstance(candidates, list)
            or not candidates
            or int(candidates[0]["integer_score"]) <= 0
        )
        expected_reason = NO_SIGNAL_ABSTENTION if expected_abstained else None
        if (
            abstention["abstained"] is not expected_abstained
            or abstention["reason"] != expected_reason
        ):
            raise IntegrityError("historical localization abstention does not match its score")
    inventory_by_id: dict[str, Mapping[str, Any]] = {}
    for candidate in value["candidate_inventory"]:
        if not isinstance(candidate, dict) or set(candidate) != {
            "candidate_id",
            "kind",
            "path",
            "symbol",
            "region",
            "role",
        }:
            raise IntegrityError("raw localization inventory candidate is invalid")
        candidate_id = _verified_raw_candidate_id(
            candidate,
            require_printable_ascii=value["runtime_identity"] == STEP1_RUNTIME_IDENTITY,
        )
        if candidate_id in inventory_by_id:
            raise IntegrityError("raw localization inventory candidate is duplicated")
        inventory_by_id[candidate_id] = candidate
    if generation["candidate_count"] != len(inventory_by_id):
        raise IntegrityError("raw localization inventory count mismatch")
    seen: set[str] = set()
    for rank, candidate in enumerate(value["candidates"], start=1):
        if (
            not isinstance(candidate, dict)
            or set(candidate)
            != {
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
            or candidate["rank"] != rank
            or not isinstance(candidate["integer_score"], int)
            or isinstance(candidate["integer_score"], bool)
        ):
            raise IntegrityError("raw localization candidate is invalid")
        candidate_id = _verified_raw_candidate_id(
            candidate,
            require_printable_ascii=value["runtime_identity"] == STEP1_RUNTIME_IDENTITY,
        )
        if candidate_id in seen:
            raise IntegrityError("raw localization ranked candidate is duplicated")
        seen.add(candidate_id)
        inventory_candidate = inventory_by_id.get(candidate_id)
        if inventory_candidate is None or any(
            candidate[key] != inventory_candidate[key]
            for key in ("kind", "path", "symbol", "region", "role")
        ):
            raise IntegrityError("raw localization ranking is not bound to its inventory")
    expected_ranking = stable_id(
        "localization-ranking",
        [item["candidate_id"] for item in value["candidates"]],
    )
    if value.get("ranking_id") != expected_ranking:
        raise IntegrityError("raw localization ranking identity mismatch")
    expected_seal = stable_id(
        "localization-raw-output",
        value,
        omit_keys=("raw_output_seal",),
    )
    if value.get("raw_output_seal") != expected_seal:
        raise IntegrityError("raw localization output seal mismatch")
    if not _SAFE_ID.fullmatch(str(value.get("request_id", ""))):
        raise IntegrityError("raw localization request identity is invalid")
    return dict(value)


def repository_artifact_identity(source: Path) -> tuple[str, str]:
    """Return the request identity for a local archive or directory."""

    resolved = source.resolve(strict=True)
    if resolved.is_file():
        return sha256_file(resolved), "archive"
    if resolved.is_dir():
        with RepositoryWorkspace(resolved) as workspace:
            if workspace.identity is None:
                raise IntegrityError("repository identity is unavailable")
            return canonical_sha256(workspace.identity["manifest_id"]), "directory"
    raise InputError("repository source must be a directory or archive")


def information_flow_manifest(*, runtime_identity: str = RUNTIME_IDENTITY) -> dict[str, Any]:
    """Describe the complete, machine-checkable inference dependency graph."""

    if runtime_identity not in SUPPORTED_RUNTIME_IDENTITIES:
        raise InputError("unsupported localization runtime identity")
    allowed = [
        "finding",
        "repository.artifact_sha256",
        "repository.source_kind",
        "configuration.runtime_identity",
        "configuration.quarantine_policy",
        "configuration.candidate_algorithm",
        "configuration.ranker",
        "configuration.top_k",
        "configuration.maximum_candidates",
        "configuration.maximum_files",
        "configuration.maximum_total_bytes",
        "configuration.maximum_file_bytes",
        "configuration.measure_peak_memory",
        "configuration.model",
        "model_artifact",
        "repository_snapshot",
    ]
    forbidden = sorted(_FORBIDDEN_FIELD_FRAGMENTS)
    stages = {
        "repository_enumeration": [
            "repository_snapshot",
            "configuration.maximum_files",
            "configuration.maximum_total_bytes",
        ],
        "path_quarantine": [
            "repository_snapshot",
            "configuration.quarantine_policy",
            "configuration.maximum_file_bytes",
        ],
        "file_selection": [
            "finding",
            "repository_snapshot",
            "configuration.maximum_candidates",
            "configuration.candidate_algorithm",
        ],
        "symbol_extraction": [
            "repository_snapshot",
            "configuration.candidate_algorithm",
        ],
        "feature_construction": [
            "finding",
            "repository_snapshot",
            "configuration.candidate_algorithm",
        ],
        "model_input": [
            "finding",
            "candidate_output",
            "configuration.model",
            "model_artifact",
        ],
        "ranking": [
            "finding",
            "repository_snapshot",
            "configuration.ranker",
            "configuration.model",
            "model_artifact",
        ],
        "abstention": [
            "finding",
            "repository_snapshot",
            "configuration.ranker",
        ],
        "raw_output_sealing": [
            "request_id",
            "repository_identity",
            "candidate_output",
            "runtime_telemetry",
        ],
    }
    value = {
        "schema_version": "localization-information-flow-manifest-v0.4.1",
        "runtime_identity": runtime_identity,
        "allowed_inputs": allowed,
        "forbidden_field_fragments": forbidden,
        "stages": stages,
        "forbidden_paths_to_output": [],
        "scoring_boundary": {
            "builder_emits": RAW_OUTPUT_SCHEMA,
            "scoring_requires_raw_output_seal": True,
            "builder_imports_scorer": False,
            "builder_accepts_audit_receipt": False,
        },
    }
    value["manifest_id"] = stable_id("localization-information-flow", value)
    return value
