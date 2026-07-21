# SPDX-License-Identifier: Apache-2.0
"""Verify the zero-runtime-dependency contract and installed environment."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

from dependency_inventory import (
    DependencyInventoryError,
    collect_dependency_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project", {})
    dependencies = project.get("dependencies")
    failures: list[str] = []
    if dependencies != []:
        failures.append("project.dependencies must be empty")
    for requirements in project.get("optional-dependencies", {}).values():
        for requirement in requirements:
            if "@" in requirement or "://" in requirement:
                failures.append("direct URL dependency in optional dependencies")
    build_requirements = document.get("build-system", {}).get("requires", [])
    if not build_requirements or any("@" in item or "://" in item for item in build_requirements):
        failures.append("build requirements must use registry names without direct URLs")
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").casefold()
    inventory: dict[str, object] | None = None
    try:
        inventory = collect_dependency_inventory(ROOT)
    except DependencyInventoryError as exc:
        failures.extend(exc.problems)
    if inventory is not None:
        for item in inventory["dependencies"]:
            if item["relationship"] == "direct" and f"| {item['name']} |" not in notices:
                failures.append(
                    f"direct dependency missing from THIRD_PARTY_NOTICES.md: {item['name']}"
                )
    check = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if check.returncode:
        failures.append("pip check reported an inconsistent installed environment")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    resolved_count = len(inventory["dependencies"]) if inventory is not None else 0
    print(
        "dependency check passed "
        f"(zero runtime dependencies; {resolved_count} resolved external tools; "
        "pip environment consistent)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
