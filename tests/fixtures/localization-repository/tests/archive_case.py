# SPDX-License-Identifier: Apache-2.0
"""Owned observational hard-negative fixture."""

from __future__ import annotations

from src.archive import validate_member_path


def parent_traversal_is_rejected() -> None:
    try:
        validate_member_path("../outside.txt")
    except ValueError:
        return
    raise AssertionError("parent traversal was not rejected")
