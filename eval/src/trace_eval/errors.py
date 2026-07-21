# SPDX-License-Identifier: Apache-2.0
"""Trace-Eval error taxonomy."""

from __future__ import annotations


class TraceEvalError(RuntimeError):
    """Base class for evaluator failures that must be reported without traceback leakage."""

    exit_code = 2


class ContractError(TraceEvalError):
    """A schema, identity, or package contract is invalid."""


class PolicyError(TraceEvalError):
    """Rights, split, exposure, lineage, or holdback policy rejected an operation."""


class RunnerError(TraceEvalError):
    """The isolated runtime could not produce a complete bounded attempt."""
