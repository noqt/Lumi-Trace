# SPDX-License-Identifier: Apache-2.0
"""Recreate isolated Trace-Eval and V0.1 SUT environments from a staged wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{value}"


def run(*arguments: str) -> None:
    subprocess.run(arguments, check=True, timeout=900)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python", type=Path, required=True, help="approved Python 3.11 executable"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--eval-wheel", type=Path, required=True)
    parser.add_argument("--sut-wheel", type=Path, required=True)
    parser.add_argument("--sut-sha256", required=True)
    parser.add_argument("--eval-sha256", required=True)
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path(__file__).parents[1] / "eval" / "requirements" / "trace-eval.lock",
    )
    args = parser.parse_args()
    version = subprocess.run(
        [
            str(args.python),
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if version != "3.11":
        raise SystemExit("Trace-Eval recreation requires the approved Python 3.11 interpreter")
    if digest(args.sut_wheel) != args.sut_sha256 or digest(args.eval_wheel) != args.eval_sha256:
        raise SystemExit("staged wheel hash mismatch")
    eval_environment = args.root / "trace-eval"
    sut_environment = args.root / "sut-v0.1.0"
    if eval_environment.exists() or sut_environment.exists():
        raise SystemExit("refusing to overwrite an existing qualified environment")
    run(str(args.python), "-m", "venv", str(eval_environment))
    run(str(args.python), "-m", "venv", str(sut_environment))
    eval_python = eval_environment / (
        "Scripts/python.exe" if __import__("os").name == "nt" else "bin/python"
    )
    sut_python = sut_environment / (
        "Scripts/python.exe" if __import__("os").name == "nt" else "bin/python"
    )
    common = ("--no-index", "--find-links", str(args.wheelhouse), "--disable-pip-version-check")
    run(
        str(eval_python),
        "-m",
        "pip",
        "install",
        *common,
        "--require-hashes",
        "-r",
        str(args.lock),
    )
    run(str(eval_python), "-m", "pip", "install", *common, "--no-deps", str(args.eval_wheel))
    run(str(sut_python), "-m", "pip", "install", *common, "--no-deps", str(args.sut_wheel))
    print(f"Trace-Eval recreated under {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
