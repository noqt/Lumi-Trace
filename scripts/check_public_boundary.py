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
INTERNAL_PATHS_MUST_BE_ABSENT = {
    Path("docs/STEP_1_RELEASE_GATE.md"),
    Path("docs/build-briefs"),
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
            if pattern.search(text):
                failures.append(f"absolute historical host path found: {relative}")
    for relative in INTERNAL_PATHS_MUST_BE_ABSENT:
        if (ROOT / relative).exists():
            failures.append(f"internal public-boundary path must be absent: {relative}")
    fixture_license = ROOT / "tests" / "fixtures" / "demo-repository" / "LICENSE"
    if not fixture_license.is_file() or "Apache-2.0" not in fixture_license.read_text(
        encoding="utf-8"
    ):
        failures.append("synthetic fixture licence is absent or not Apache-2.0")
    quickstart_readme = ROOT / "examples" / "quickstart" / "README.md"
    quickstart_source = ROOT / "examples" / "quickstart" / "repository" / "src" / "archive.py"
    if (
        not quickstart_readme.is_file()
        or "Apache-2.0" not in quickstart_readme.read_text(encoding="utf-8")
        or not quickstart_source.is_file()
        or not any(
            "SPDX-License-Identifier: Apache-2.0" in line
            for line in quickstart_source.read_text(encoding="utf-8").splitlines()[:5]
        )
    ):
        failures.append("public quickstart provenance or Apache-2.0 marker is incomplete")
    if failures:
        print("\n".join(sorted(set(failures))), file=sys.stderr)
        return 1
    print("public-boundary check passed (no weights or protected/host-path material)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
