# SPDX-License-Identifier: Apache-2.0
"""Small deterministic secret-pattern gate for the release boundary."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_SCAN_BYTES = 2 * 1024 * 1024
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "generic bearer token": re.compile(r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
}


def files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[str] = []
    scanned = 0
    for path in files():
        if not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"secret check passed ({scanned} UTF-8 files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
