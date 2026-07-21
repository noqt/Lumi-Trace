# SPDX-License-Identifier: Apache-2.0
"""Typed errors surfaced by the CLI without Python tracebacks."""


class LumiTraceError(Exception):
    """Base class for expected product errors."""

    exit_code = 2


class InputError(LumiTraceError):
    """The supplied finding, repository, archive, or plan is invalid."""


class UnsupportedError(LumiTraceError):
    """The supplied input is outside the V0.1 support contract."""

    exit_code = 3


class IntegrityError(LumiTraceError):
    """A deterministic identity or immutability check failed."""

    exit_code = 4
