# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON, identities, and bounded local file handling."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .errors import ContractError

MAX_JSON_BYTES = 64 * 1024 * 1024


def _check_json(value: Any, *, items: list[int] | None = None) -> None:
    counter = items if items is not None else [0]
    counter[0] += 1
    if counter[0] > 1_000_000:
        raise ContractError("JSON item limit exceeded")
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError("non-finite JSON number is prohibited")
        return
    if isinstance(value, list):
        for item in value:
            _check_json(item, items=counter)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ContractError("JSON object keys must be strings")
        for key in sorted(value):
            _check_json(value[key], items=counter)
        return
    raise ContractError(f"non-JSON value is prohibited: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check_json(value)
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"expected a regular file: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{sha256_bytes(canonical_bytes(value)).removeprefix('sha256:')}"


def load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ContractError(f"JSON input is missing, unsafe, or oversized: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError(f"cannot load canonical JSON: {path.name}") from exc
    _check_json(value)
    return value


def dump_json(path: Path, value: Any) -> None:
    rendered = (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
