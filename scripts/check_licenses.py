# SPDX-License-Identifier: Apache-2.0
"""Fail closed when the public source licence boundary is incomplete."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "tests/fixtures/fixture-manifest.json",
    "tests/fixtures/demo-repository/LICENSE",
}


def repository_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        path
        for item in result.stdout.split(b"\0")
        if item and (path := ROOT / item.decode("utf-8")).is_file()
    ]


def main() -> int:
    failures: list[str] = []
    for name in sorted(REQUIRED):
        if not (ROOT / name).is_file():
            failures.append(f"missing required licence file: {name}")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        failures.append("LICENSE is not the Apache License 2.0 text")
    for path in repository_files():
        if path.suffix == ".py":
            first_lines = "\n".join(path.read_text(encoding="utf-8").splitlines()[:5])
            if "SPDX-License-Identifier: Apache-2.0" not in first_lines:
                failures.append(f"missing Apache-2.0 SPDX header: {path.relative_to(ROOT)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"licence check passed ({len(repository_files())} repository files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
