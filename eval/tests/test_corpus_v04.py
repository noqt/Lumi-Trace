# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from trace_eval.corpus import (
    PythonChange,
    blind_label_pass_one,
    blind_label_pass_two,
    blind_passes_agree,
    is_python_harness,
    is_python_production,
    old_regions,
)

PARENT = """\
def helper(value):
    return value

def parse_record(value):
    if value:
        return value
    return None
"""

FIXED = """\
def helper(value):
    return value

def parse_record(value):
    if not isinstance(value, str):
        raise TypeError("text required")
    if value:
        return value
    return None
"""

PATCH = """\
@@ -5,2 +5,4 @@ def parse_record(value):
-    if value:
+    if not isinstance(value, str):
+        raise TypeError("text required")
+    if value:
"""


def test_v04_diff_and_ast_blind_passes_agree_on_vulnerable_symbol() -> None:
    change = PythonChange("src/parser.py", PARENT, FIXED, PATCH)
    first = blind_label_pass_one([change])
    second = blind_label_pass_two([change])
    assert blind_passes_agree(first, second)
    assert first[0]["private_mapping"]["path"] == "src/parser.py"
    assert first[0]["private_mapping"]["symbol"] == "parse_record"
    assert first[0]["role"] == "VULNERABLE_IMPLEMENTATION"


def test_v04_label_passes_do_not_treat_tests_as_production() -> None:
    assert is_python_production("src/parser.py")
    assert not is_python_production("tests/test_parser.py")
    assert is_python_harness("tests/test_parser.py")


def test_v04_insertion_hunk_binds_to_an_existing_parent_location() -> None:
    assert old_regions("@@ -5,0 +5,2 @@ def parse_record(value):") == [(5, 5)]
