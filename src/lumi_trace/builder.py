# SPDX-License-Identifier: Apache-2.0
"""Isolated CLI for the V0.4.1 label-blind inference builder."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from .canonical import dump_json, load_json
from .errors import LumiTraceError
from .localization import (
    assert_builder_path,
    build_raw_localization,
    validate_access_policy,
)

_NETWORK_AND_PROCESS_EVENTS = {
    "os.system",
    "socket.__new__",
    "socket.bind",
    "socket.connect",
    "socket.connect_ex",
    "socket.getaddrinfo",
    "socket.gethostbyaddr",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
    "socket.getnameinfo",
    "subprocess.Popen",
}
_SINGLE_PATH_EVENTS = {
    "open",
    "os.chdir",
    "os.chmod",
    "os.chown",
    "os.listdir",
    "os.mkdir",
    "os.remove",
    "os.rmdir",
    "os.scandir",
    "os.truncate",
    "os.unlink",
}
_DOUBLE_PATH_EVENTS = {"os.link", "os.rename", "os.replace", "os.symlink"}


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _install_runtime_guard(policy: dict) -> None:
    """Deny network, subprocess, and out-of-workspace filesystem access."""

    validated = validate_access_policy(policy)
    allowed = [Path(item).resolve(strict=True) for item in validated["allowed_roots"]]
    forbidden = [Path(item).resolve(strict=True) for item in validated["forbidden_roots"]]
    trusted_read_roots = {
        Path(sys.base_prefix).resolve(strict=True),
        Path(__file__).resolve(strict=True).parents[1],
    }

    def check_path(value: object, *, read_only: bool) -> None:
        if isinstance(value, int):
            return
        try:
            decoded = os.fsdecode(value)
        except TypeError:
            return
        resolved = Path(decoded).resolve(strict=False)
        if any(_within(resolved, root) or _within(root, resolved) for root in forbidden):
            raise PermissionError("builder filesystem guard denied a forbidden root")
        if any(_within(resolved, root) for root in allowed):
            return
        if read_only and any(_within(resolved, root) for root in trusted_read_roots):
            return
        raise PermissionError("builder filesystem guard denied an out-of-root path")

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event in _NETWORK_AND_PROCESS_EVENTS:
            raise PermissionError("builder runtime guard denied network or process access")
        if event in _SINGLE_PATH_EVENTS and arguments:
            read_only = event in {"os.listdir", "os.scandir"}
            if event == "open":
                mode = arguments[1] if len(arguments) > 1 else "r"
                flags = arguments[2] if len(arguments) > 2 else 0
                read_only = (
                    isinstance(mode, str)
                    and all(marker not in mode for marker in ("+", "a", "w", "x"))
                ) or (
                    mode is None
                    and isinstance(flags, int)
                    and flags & (os.O_APPEND | os.O_CREAT | os.O_TRUNC | os.O_WRONLY) == 0
                )
            check_path(arguments[0], read_only=read_only)
        elif event in _DOUBLE_PATH_EVENTS:
            for value in arguments[:2]:
                check_path(value, read_only=False)

    sys.addaudithook(audit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m lumi_trace.builder")
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--access-policy", type=Path, required=True)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        request = load_json(args.request)
        policy = load_json(args.access_policy)
        if not isinstance(request, dict) or not isinstance(policy, dict):
            raise ValueError("builder inputs must be JSON objects")
        request_path = assert_builder_path(args.request, policy, must_exist=True)
        repository_path = assert_builder_path(args.repository, policy, must_exist=True)
        output_path = assert_builder_path(args.output, policy, must_exist=False)
        model = None
        if args.model is not None:
            model_path = assert_builder_path(args.model, policy, must_exist=True)
            model = load_json(model_path)
            if not isinstance(model, dict):
                raise ValueError("builder model must be a JSON object")
        _install_runtime_guard(policy)
        # Re-read the request under the installed guard so the complete
        # inference phase is covered by the same filesystem policy.
        request = load_json(request_path)
        result = build_raw_localization(
            request,
            repository_source=repository_path,
            access_policy=policy,
            model_artifact=model,
        )
        if output_path.exists():
            raise ValueError("builder output already exists")
        dump_json(output_path, result)
        return 0
    except (LumiTraceError, OSError, ValueError) as exc:
        print(f"lumi-trace-builder: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 2)


if __name__ == "__main__":
    raise SystemExit(main())
