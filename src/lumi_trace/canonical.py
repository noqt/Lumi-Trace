# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON and SHA-256 helpers.

Canonical evidence uses sorted, compact ASCII JSON. Human-facing JSON is
pretty printed, but all identities are calculated from the compact encoding.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Return the stable byte representation used by every Lumi Trace ID."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a labelled SHA-256 digest."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file without loading it into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def canonical_sha256(value: Any, omit_keys: Iterable[str] = ()) -> str:
    """Hash a mapping after omitting top-level self-identity fields."""

    if isinstance(value, dict) and omit_keys:
        omitted = set(omit_keys)
        value = {key: item for key, item in value.items() if key not in omitted}
    return sha256_bytes(canonical_json_bytes(value))


def load_json(
    path: Path,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    max_depth: int = 64,
    max_items: int = 1_000_000,
) -> Any:
    """Read a UTF-8 JSON document with a useful path in parse errors."""

    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError(f"JSON document exceeds byte limit of {max_bytes}")
        value = json.loads(path.read_text(encoding="utf-8"))
        stack = [(value, 1)]
        items = 0
        while stack:
            current, depth = stack.pop()
            if depth > max_depth:
                raise ValueError(f"JSON document exceeds nesting limit of {max_depth}")
            if isinstance(current, dict):
                items += len(current)
                stack.extend((item, depth + 1) for item in current.values())
            elif isinstance(current, list):
                items += len(current)
                stack.extend((item, depth + 1) for item in current)
            if items > max_items:
                raise ValueError(f"JSON document exceeds item limit of {max_items}")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"cannot read JSON document {path}: {exc}") from exc


def dump_json(path: Path, value: Any, *, canonical: bool = False) -> None:
    """Atomically write JSON with LF endings."""

    path.parent.mkdir(parents=True, exist_ok=True)
    data = (
        canonical_json_bytes(value)
        if canonical
        else (
            json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def stable_id(prefix: str, value: Any, omit_keys: Iterable[str] = ()) -> str:
    """Create a readable stable identifier from canonical content."""

    digest = canonical_sha256(value, omit_keys).removeprefix("sha256:")
    return f"{prefix}:{digest}"
