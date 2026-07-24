# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import sys
from pathlib import Path

from trace_eval.runner import _run_observed


def test_observed_process_records_bounded_tree_resources(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.bin"
    stderr_path = tmp_path / "stderr.bin"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        observed = _run_observed(
            [sys.executable, "-c", "value = bytearray(1024 * 1024); print(len(value))"],
            stdout=stdout,
            stderr=stderr,
            environment=dict(os.environ),
            timeout_seconds=10,
        )

    assert observed["timed_out"] is False
    assert observed["return_code"] == 0
    assert observed["wall_time_ms"] >= 0
    assert observed["peak_process_count"] >= 1
    assert observed["peak_resident_bytes"] is None or observed["peak_resident_bytes"] > 0


def test_observed_process_terminates_on_wall_time_limit(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.bin"
    stderr_path = tmp_path / "stderr.bin"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        observed = _run_observed(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdout=stdout,
            stderr=stderr,
            environment=dict(os.environ),
            timeout_seconds=1,
        )

    assert observed["timed_out"] is True
    assert observed["return_code"] is None
    assert observed["wall_time_ms"] < 5_000
