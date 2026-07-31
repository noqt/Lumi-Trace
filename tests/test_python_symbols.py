# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from lumi_trace.indexing import build_repository_index
from lumi_trace.python_symbols import scan_python_declarations
from lumi_trace.repository import compute_repository_identity


def _scan(source: str, *, maximum_symbols: int = 100) -> tuple[list[dict], str | None, bool]:
    return scan_python_declarations(
        source,
        maximum_symbols=maximum_symbols,
        maximum_lines=10_000,
        maximum_name_chars=256,
        maximum_qualified_name_chars=1_024,
    )


def test_fixed_scanner_tracks_decorated_nested_declarations_and_ranges() -> None:
    source = """\
@wrapper(
    enabled=True,
)
async def outer(
    value,
):
    class Inner:
        def method(self):
            return (
                value
            )
    return value
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [
        (
            item["qualified_name"],
            item["declaration_kind"],
            item["start_line"],
            item["end_line"],
        )
        for item in declarations
    ] == [
        ("outer", "async_function", 4, 12),
        ("outer.Inner", "class", 7, 11),
        ("outer.Inner.method", "function", 8, 11),
    ]


@pytest.mark.parametrize(
    "expression",
    [
        'f"{value}"',
        'f"{{literal}}"',
        'f"{value!r:>10}"',
        'f"{value:{width}.{precision}f}"',
        """f"{ {'x': 1}['x'] }" """.strip(),
        """f"{f'{value}'}" """.strip(),
        'rf"path={value!r}"',
        'f"\\{value}"',
        'rf"\\{value}"',
        'f"{value:#x}"',
        'f"{(lambda item: item)(value)}"',
        'f"{value=}"',
        'f"\\N{GREEK CAPITAL LETTER DELTA}"',
        'f"\\N{GREEK CAPITAL LETTER DELTA}: {value}"',
        'f"""{(\n        value + 1\n    )}"""',
        'rf"""{value +\n        1}"""',
        'f"""{\n        value\n        =}"""',
    ],
)
def test_fixed_scanner_accepts_bounded_python_311_fstrings(expression: str) -> None:
    source = f"def render(value, width=10, precision=2):\n    return {expression}\n"

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["render"]


def test_fixed_scanner_treats_walrus_as_expression_not_suite_colon() -> None:
    source = """\
def read(stream):
    while chunk := stream.read(1024):
        consume(chunk)
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["read"]
    assert declarations[0]["end_line"] == 3


def test_fixed_scanner_accepts_soft_keyword_names_lambda_headers_and_continued_defs() -> None:
    source = """\
for callback in lambda value: value, str:
    def match(): pass
async \\
def case(): pass
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [
        (
            declaration["qualified_name"],
            declaration["declaration_kind"],
            declaration["start_line"],
            declaration["end_line"],
        )
        for declaration in declarations
    ] == [
        ("match", "function", 2, 2),
        ("case", "async_function", 3, 4),
    ]


def test_fixed_scanner_accepts_python_311_expression_decorators() -> None:
    source = """\
@False or wrapper
def first(): pass
@decorator := wrapper
def second(): pass
@lambda function: wrapper(function)
def third(): pass
@[None, wrapper][1]
def fourth(): pass
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [declaration["qualified_name"] for declaration in declarations] == [
        "first",
        "second",
        "third",
        "fourth",
    ]


def test_fixed_scanner_rejects_pep701_same_delimiter_false_declaration() -> None:
    source = '''\
def real():
    return f"""{"""
def fake():
    pass
"""}"""
'''

    assert _scan(source) == ([], "syntax_error", False)


@pytest.mark.parametrize(
    "source",
    [
        "type Alias = int\nclass C:\n    pass\n",
        "type Alias[T] = T\ndef retained(): pass\n",
        "type Alias[\n    T,\n] = T\ndef retained(): pass\n",
        "def generic[T]():\n    pass\n",
        "async class C:\n    pass\n",
        "def broken nonsense:\n    pass\n",
        "def broken(1): pass\n",
        "def broken(value value): pass\n",
        "def broken(value, value): pass\n",
        "def broken(value=1, required): pass\n",
        "def broken(value=): pass\n",
        "def broken(value:): pass\n",
        "def broken(*): pass\n",
        "def broken(/): pass\n",
        "def broken(value, /, /): pass\n",
        "def broken(**values, trailing): pass\n",
        "def broken(value==1): pass\n",
        "def broken(value=1+): pass\n",
        "def broken() -> int junk: pass\n",
        "def broken() -> +: pass\n",
        "class Broken(metaclass=type, metaclass=type): pass\n",
        "class Broken(/): pass\n",
        "class Broken(=): pass\n",
        "class Broken(value=): pass\n",
        "class Broken(*): pass\n",
        "class Broken(left,,right): pass\n",
        "def empty():\n",
        "def café():\n    pass\n",
        "def a\U00011f04():\n    pass\n",
        "\tdef tabbed():\n\t\tpass\n",
        "def nul():\n    pass\n" + (" " * 9_000) + "\x00",
        "def dangling():\\\n",
        "@decorator\nvalue = 1\n",
        "@   \ndef retained(): pass\n",
        "@decorator extra\ndef retained(): pass\n",
        "@lambda\ndef retained(): pass\n",
        "@if\ndef retained(): pass\n",
        "@wrapper extra more\ndef retained(): pass\n",
        "@wrapper extra.name\ndef retained(): pass\n",
        "???\ndef retained(): pass\n",
        "$bad\ndef retained(): pass\n",
        "value =\ndef retained(): pass\n",
        "value = 1\\  \ndef retained(): pass\n",
        "value = \\\n\ndef retained(): pass\n",
        "value = \\\n# no continuation expression\ndef retained(): pass\n",
        "type\tAlias = int\ndef retained(): pass\n",
        "type Alias\t= int\ndef retained(): pass\n",
        "type \\\n\tAlias = int\ndef retained(): pass\n",
        'z"value"\ndef retained(): pass\n',
        't"value"\ndef retained(): pass\n',
        'x1f"{value}"\ndef retained(): pass\n',
        'b"caf\u00e9"\ndef retained(): pass\n',
        'br"caf\u00e9"\ndef retained(): pass\n',
        'value = f"{\U00011f04}"\ndef retained(): pass\n',
        'def render(): return f"{}"\n',
        'def render(): return f"{   }"\n',
        'def render(value): return f"{value!z}"\n',
        'def render(): return f"{lambda value: value}"\n',
        'def render(x, y): return f"""{x\ny}"""\n',
        'def render(x): return f"{x y}"\n',
        'def render(x): return f"{x +}"\n',
        'def render(): return f"{+}"\n',
        'def render(): return f"{1 2}"\n',
        'def render(x, y): return f"{x,,y}"\n',
        'def render(x): return f"{if x}"\n',
        'def render(x): return f"{x for}"\n',
        'def render(x): return f"{await x}"\n',
        'def render(x): return f"{x and}"\n',
        'def render(): return f"{not}"\n',
        'def render(x): return f"{x ==}"\n',
        'def render(x, y): return f"{x; y}"\n',
        'def render(x): return f"{*x}"\n',
        'def render(x): return f"{**x}"\n',
        'def render(): return bf"value"\n',
        "def render(values): return f\"{'\\\\n'.join(values)}\"\n",
        "def render(): return f\"{'\\\\N{SNOWMAN}'}\"\n",
        "def render(values): return rf\"{'\\\\n'.join(values)}\"\n",
    ],
)
def test_fixed_scanner_fails_closed_on_ambiguous_or_unsupported_source(source: str) -> None:
    assert _scan(source) == ([], "syntax_error", False)


def test_fixed_scanner_allows_unicode_inside_strings_and_comments() -> None:
    source = 'def retained():\n    value = "café \U00011f04"\n    return value  # café\n'

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["retained"]


def test_fixed_scanner_accepts_python311_horizontal_declaration_whitespace() -> None:
    source = "async\tdef tabbed(): pass\nclass\fFormFeed: pass\n"

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["tabbed", "FormFeed"]


def test_fixed_scanner_accepts_implicit_string_concatenation_in_projections() -> None:
    source = """\
@skip("first " "second")
def first(value: "First" "Second" = "left " "right"): pass
class Second(option="left " "right"): pass
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["first", "Second"]


def test_prefixed_string_marker_preserves_statement_indentation() -> None:
    source = """\
def retained():
    r\"\"\"A raw docstring.\"\"\"
    return 1
"""

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["retained"]


@pytest.mark.parametrize(
    "source",
    [
        "def retained(value=\x01): pass\n",
        "class Retained(\x02): pass\n",
        "@\x01\ndef retained(): pass\n",
    ],
    ids=["default", "base", "decorator"],
)
def test_source_control_bytes_cannot_collide_with_internal_string_markers(
    source: str,
) -> None:
    assert _scan(source) == ([], "syntax_error", False)


def test_fixed_scanner_normalizes_lf_crlf_and_cr() -> None:
    source = "def retained():\n    return 1\n"

    assert _scan(source) == _scan(source.replace("\n", "\r\n"))
    assert _scan(source) == _scan(source.replace("\n", "\r"))


def test_fixed_scanner_validates_the_tail_before_applying_the_symbol_cap() -> None:
    source = "def retained():\n    pass\n\ndef broken nonsense:\n    pass\n"

    assert _scan(source, maximum_symbols=0) == ([], "syntax_error", False)
    assert _scan(source, maximum_symbols=1) == ([], "syntax_error", False)


def test_fixed_scanner_uses_bounded_mask_storage_for_large_unicode_strings() -> None:
    source = 'def retained():\n    value = """' + ("\u0100" * 250_000) + '"""\n'

    declarations, issue, limited = _scan(source)

    assert issue is None
    assert limited is False
    assert [item["qualified_name"] for item in declarations] == ["retained"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"maximum_symbols": True},
        {"maximum_lines": True},
        {"maximum_name_chars": 0},
        {"maximum_qualified_name_chars": "1024"},
    ],
)
def test_fixed_scanner_rejects_invalid_limits(overrides: dict[str, object]) -> None:
    limits: dict[str, object] = {
        "maximum_symbols": 10,
        "maximum_lines": 100,
        "maximum_name_chars": 256,
        "maximum_qualified_name_chars": 1_024,
    }
    limits.update(overrides)

    with pytest.raises(ValueError, match="limits are invalid"):
        scan_python_declarations("def retained(): pass\n", **limits)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "source",
    [
        "def bounded(value=[" + ("0," * 20_000) + "]): pass\n",
        "@wrapper(" + ("0," * 20_000) + "0)\ndef bounded(): pass\n",
        'def bounded(): return f"{' + ("value+" * 4_000) + 'value}"\n',
    ],
    ids=["declaration", "decorator", "fstring-expression"],
)
def test_ast_projection_limit_is_checked_before_parser_allocation(
    source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    real_parse = ast.parse

    def tracking_parse(*args: object, **kwargs: object) -> ast.AST:
        nonlocal calls
        calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", tracking_parse)

    assert _scan(source) == ([], "complexity_limit", False)
    assert calls == 0


@pytest.mark.parametrize(
    "source",
    [
        "def bounded(value=" + "+".join(["1"] * 1_000) + "): pass\n",
        "def bounded(value=" + ("1" * 5_000) + "): pass\n",
        "def bounded(value=" + ("-" * 140) + "1): pass\n",
    ],
    ids=["binary-chain", "decimal-digits", "ast-depth"],
)
def test_projection_work_and_ast_depth_are_fixed_before_compilation(source: str) -> None:
    assert _scan(source) == ([], "complexity_limit", False)


def test_product_index_does_not_derive_symbols_from_the_host_ast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text(
        "def retained():\n    return 1\n",
        encoding="utf-8",
    )

    def unrelated_tree(*args: object, **kwargs: object) -> ast.Module:
        return ast.Module(body=[], type_ignores=[])

    monkeypatch.setattr(ast, "parse", unrelated_tree)
    index = build_repository_index(repository, compute_repository_identity(repository))

    assert [symbol["name"] for symbol in index["files"][0]["symbols"]] == ["retained"]
    assert index["files"][0]["symbols"][0]["extractor"] == "python-lexical-v1"


def test_nul_after_text_probe_window_is_a_bounded_file_only_result(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text(
        "def retained():\n    pass\n" + (" " * 9_000) + "\x00",
        encoding="utf-8",
    )

    index = build_repository_index(repository, compute_repository_identity(repository))

    assert index["files"][0]["symbols"] == []
    assert index["files"][0]["symbol_extraction_issue"] == "syntax_error"
