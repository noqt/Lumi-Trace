# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

from trace_eval.canonical import canonical_bytes, sha256_bytes, sha256_file
from trace_eval.runner import _tree_id


def test_runner_tree_identity_uses_canonical_utf8_path_order(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("lower", encoding="utf-8")
    (tmp_path / "B.txt").write_text("upper", encoding="utf-8")
    paths = sorted(
        (path for path in tmp_path.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(tmp_path).as_posix().encode("utf-8"),
    )
    manifest = {
        "algorithm": "lumi-tree-sha256-v1",
        "files": [
            {
                "path": path.relative_to(tmp_path).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
            for path in paths
        ],
    }
    assert _tree_id(tmp_path) == sha256_bytes(canonical_bytes(manifest))
