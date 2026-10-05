# SPDX-License-Identifier: Apache-2.0
"""Self-contained synthetic first-use workflow for the Lumi Trace wheel."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .errors import InputError
from .pipeline import trace_repository

_DEMO_FIXTURE_LABEL = "examples/quickstart"
_DEMO_FINDING = {
    "schema_version": "manual-finding-v1",
    "id": "LUMI-TRACE-DEMO-001",
    "title": "Archive member path may escape the extraction root",
    "description": (
        "The extraction target joins an untrusted archive member name to the root "
        "without rejecting absolute paths or parent traversal."
    ),
    "severity": "high",
    "rule": {
        "id": "CWE-22",
        "name": "Path traversal",
        "cwes": ["CWE-22"],
        "tags": ["archive", "path-traversal", "validation"],
    },
    "locations": [
        {
            "path": "src/archive.py",
            "symbol": "extraction_target",
            "start_line": 8,
            "start_column": 1,
            "end_line": 10,
            "end_column": 30,
        }
    ],
    "keywords": ["archive", "member", "path", "traversal", "extraction", "root"],
    "fingerprints": {"skylark/demo": "lumi-trace-demo-001"},
}
_DEMO_ARCHIVE_SOURCE = '''# SPDX-License-Identifier: Apache-2.0
"""Inert synthetic fixture for the Lumi Trace quickstart."""

from pathlib import PurePosixPath


def extraction_target(root: PurePosixPath, member_name: str) -> PurePosixPath:
    """Return a target path without performing filesystem I/O."""

    return root / member_name
'''


def _materialize_fixture(destination: Path) -> tuple[Path, Path]:
    """Materialize only the embedded inert finding and fixture source."""

    repository = destination / "repository" / "src"
    repository.mkdir(parents=True)
    finding_path = destination / "finding.json"
    archive_path = repository / "archive.py"
    finding_path.write_text(
        json.dumps(_DEMO_FINDING, indent=2) + "\n",
        encoding="utf-8",
    )
    archive_path.write_text(_DEMO_ARCHIVE_SOURCE, encoding="utf-8")
    return finding_path, repository.parent


def run_demo(*, output_directory: Path) -> dict[str, object]:
    """Run the synthetic quickstart without a source checkout or private input."""

    if output_directory.exists() or output_directory.is_symlink():
        raise InputError("output directory already exists; choose a new evidence-package path")

    with tempfile.TemporaryDirectory(prefix="lumi-trace-demo-") as temporary_root:
        finding_path, repository = _materialize_fixture(Path(temporary_root) / _DEMO_FIXTURE_LABEL)
        return trace_repository(
            finding_path=finding_path,
            finding_format="manual",
            repository_source=repository,
            output_directory=output_directory,
        )
