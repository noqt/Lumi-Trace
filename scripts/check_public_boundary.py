# SPDX-License-Identifier: Apache-2.0
"""Reject model artefacts, host paths, and protected-evidence path names."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".gguf",
    ".onnx",
    ".pt",
    ".pth",
    ".safetensors",
}
FORBIDDEN_PATH_PARTS = {
    "cybergym",
    "holdback",
    "customer-evidence",
    "training-data",
    "v2_7",
}
HOST_PATHS = (
    re.compile(r"(?i)\b[A-Z]:\\Users\\"),
    re.compile(r"(?i)\bF:\\Data\\"),
    re.compile(r"/var/lib/lumi/"),
)
DOCUMENTED_TOPOLOGY_FILES = {
    Path("docs/build-briefs/Lumi-Trace-V0.2-Evaluation-and-Training-Readiness-Build-Brief.md"),
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
    failures: list[str] = []
    for path in files():
        relative = path.relative_to(ROOT)
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            failures.append(f"model/weight artefact extension is prohibited: {relative}")
        if set(part.casefold() for part in relative.parts) & FORBIDDEN_PATH_PARTS:
            failures.append(f"protected evidence path name is prohibited: {relative}")
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if path.resolve() == Path(__file__).resolve():
            # This checker necessarily contains the prohibited path signatures.
            continue
        for pattern in HOST_PATHS:
            if relative in DOCUMENTED_TOPOLOGY_FILES and pattern.pattern == r"(?i)\bF:\\Data\\":
                continue
            if pattern.search(text):
                failures.append(f"absolute historical host path found: {relative}")
    fixture_license = ROOT / "tests" / "fixtures" / "demo-repository" / "LICENSE"
    if not fixture_license.is_file() or "Apache-2.0" not in fixture_license.read_text(
        encoding="utf-8"
    ):
        failures.append("synthetic fixture licence is absent or not Apache-2.0")
    if failures:
        print("\n".join(sorted(set(failures))), file=sys.stderr)
        return 1
    print("public-boundary check passed (no weights or protected/host-path material)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
