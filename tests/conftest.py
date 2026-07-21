# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def fixture_repository(project_root: Path) -> Path:
    return project_root / "tests" / "fixtures" / "demo-repository"


@pytest.fixture
def manual_finding_path(project_root: Path) -> Path:
    return project_root / "tests" / "data" / "manual-finding.json"


@pytest.fixture
def sarif_finding_path(project_root: Path) -> Path:
    return project_root / "tests" / "data" / "finding.sarif"
