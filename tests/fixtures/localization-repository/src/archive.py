# SPDX-License-Identifier: Apache-2.0
"""Owned inert localization fixture for archive path validation."""

from __future__ import annotations

from pathlib import PurePosixPath


def validate_member_path(member_name: str) -> PurePosixPath:
    """Reject absolute and parent-traversing archive member paths."""

    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe archive member path")
    return path


def extract_archive_member(member_name: str, payload: bytes) -> tuple[PurePosixPath, bytes]:
    """Return an inert validated member without writing or executing it."""

    return validate_member_path(member_name), payload
