# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from lumi_trace.canonical import canonical_json_bytes, canonical_sha256, stable_id


def test_canonical_json_is_key_order_independent() -> None:
    left = {"z": [2, 1], "a": {"beta": True, "alpha": None}}
    right = {"a": {"alpha": None, "beta": True}, "z": [2, 1]}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_sha256(left) == canonical_sha256(right)
    assert stable_id("fixture", left) == stable_id("fixture", right)


def test_canonical_json_uses_ascii_and_no_whitespace() -> None:
    assert canonical_json_bytes({"snow": "☃"}) == b'{"snow":"\\u2603"}'
