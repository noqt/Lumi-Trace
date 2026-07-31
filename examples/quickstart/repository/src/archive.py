# SPDX-License-Identifier: Apache-2.0
"""Inert synthetic fixture for the Lumi Trace quickstart."""

from pathlib import PurePosixPath


def extraction_target(root: PurePosixPath, member_name: str) -> PurePosixPath:
    """Return a target path without performing filesystem I/O."""

    return root / member_name
