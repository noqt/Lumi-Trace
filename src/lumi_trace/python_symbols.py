# SPDX-License-Identifier: Apache-2.0
"""Bounded Python 3.11 declaration extraction for CPython 3.11 and 3.12.

The fixed lexical pass freezes string, f-string, continuation, indentation, and
ASCII-identifier handling before a Python 3.11 grammar projection validates
declaration headers. The host AST never supplies symbols or ranges.
"""

from __future__ import annotations

import ast
import re
import sys
import warnings
from dataclasses import dataclass
from typing import Any

MAX_BRACKET_DEPTH = 512
MAX_FSTRING_DEPTH = 32
MAX_PYTHON_PROJECTION_CHARS = 16_384
MAX_PYTHON_PROJECTION_WORK = 512
MAX_PYTHON_PROJECTION_AST_NODES = 2_048
MAX_PYTHON_PROJECTION_AST_DEPTH = 128
SUPPORTED_CPYTHON_MINORS = frozenset({(3, 11), (3, 12)})
MINIMUM_RECURSION_LIMIT = 1_000

# Values above ASCII cannot collide with source text in the masked buffer:
# every unmasked non-ASCII source code point is represented by 0x80.
_TEXT_STRING_MARKER = "\xfe"
_BYTES_STRING_MARKER = "\xff"
_STRING_MARKERS = {_TEXT_STRING_MARKER, _BYTES_STRING_MARKER}

_ASCII_IDENTIFIER_TAIL = r"(?![A-Za-z0-9_])"
_DECLARATION = re.compile(
    r"^(?P<indent> *)(?:(?P<async>async)[ \t\f]+def|(?P<kind>def|class))[ \t\f]+"
    rf"(?P<name>[A-Za-z_][A-Za-z0-9_]*){_ASCII_IDENTIFIER_TAIL}"
)
_DECLARATION_PREFIX = re.compile(rf"^ *(?:(?:async[ \t\f]+)?def|class){_ASCII_IDENTIFIER_TAIL}")
_ASYNC_CLASS = re.compile(rf"^ *async[ \t\f]+class{_ASCII_IDENTIFIER_TAIL}")
_TYPE_ALIAS = re.compile(
    rf"^ *type[ \t\f]+[A-Za-z_][A-Za-z0-9_]*{_ASCII_IDENTIFIER_TAIL}"
    r"(?:[ \t\f]*\[|[ \t\f]*=)"
)
_OPENING = {"(": ")", "[": "]", "{": "}"}
_CLOSING = {value: key for key, value in _OPENING.items()}
_PREFIXES = {"", "b", "br", "f", "fr", "r", "rb", "rf", "u"}
_KEYWORDS = {
    "False",
    "None",
    "True",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
}


class _LexicalFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Statement:
    start_index: int
    end_index: int
    indent: int


@dataclass
class _DeclarationRecord:
    name: str
    declaration_kind: str
    indent: int
    start_line: int
    end_line: int | None
    qualified_name: str
    scope_depth: int


def normalize_python_newlines(source: str) -> str:
    """Normalize only Python's three physical newline encodings."""

    return source.replace("\r\n", "\n").replace("\r", "\n")


def split_python_lines(source: str) -> list[str]:
    """Split physical lines without Unicode-version-sensitive separators."""

    normalized = normalize_python_newlines(source)
    if not normalized:
        return []
    lines = normalized.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _ascii_identifier_character(character: str) -> bool:
    return (
        "A" <= character <= "Z"
        or "a" <= character <= "z"
        or "0" <= character <= "9"
        or character == "_"
    )


def supported_python_runtime() -> bool:
    """Return whether the parser-assisted profile has its governed runtime."""

    return (
        sys.implementation.name == "cpython"
        and sys.version_info[:2] in SUPPORTED_CPYTHON_MINORS
        and sys.getrecursionlimit() >= MINIMUM_RECURSION_LIMIT
    )


def _string_prefix(source: str, quote_index: int) -> str:
    start = quote_index
    while start > 0:
        previous = source[start - 1]
        if not _ascii_identifier_character(previous):
            break
        start -= 1
    token = source[start:quote_index]
    prefix = token.lower()
    if prefix in _PREFIXES and (not token or token.isalpha()):
        return prefix
    if token and token not in _KEYWORDS:
        raise _LexicalFailure("syntax_error")
    return ""


def _mask_strings_and_comments(
    source: str,
) -> tuple[str, frozenset[int], frozenset[int]]:
    # One byte per source code point avoids the large object amplification of
    # ``list(source)`` on hostile or non-Latin-1 string contents. Bytes above
    # ASCII are represented by one sentinel until they are either masked as
    # string/comment data or rejected by the fixed source subset.
    output = bytearray(len(source))
    for position, character in enumerate(source):
        codepoint = ord(character)
        output[position] = codepoint if codepoint < 128 else 0x80
    string_lines: set[int] = set()
    string_continues_to_next: set[int] = set()
    length = len(source)

    def mask_string(
        start: int,
        line: int,
        *,
        marker: bool,
        prefix: str,
        nesting: int,
        forbid_backslash: bool = False,
    ) -> tuple[int, int]:
        if nesting > MAX_FSTRING_DEPTH:
            raise _LexicalFailure("complexity_limit")
        f_string = "f" in prefix
        bytes_literal = "b" in prefix
        raw = "r" in prefix
        quote = source[start]
        triple = source.startswith(quote * 3, start)
        delimiter_length = 3 if triple else 1
        marker_position = start - len(prefix)
        if marker:
            for position in range(marker_position, start + delimiter_length):
                output[position] = ord(" ")
            output[marker_position] = ord(
                _BYTES_STRING_MARKER if bytes_literal else _TEXT_STRING_MARKER
            )
        else:
            for position in range(start, start + delimiter_length):
                output[position] = ord(" ")
        index = start + delimiter_length

        def mask_literal_backslash(
            position: int,
            current_line: int,
        ) -> tuple[int, int]:
            if forbid_backslash:
                raise _LexicalFailure("syntax_error")
            if raw:
                end = position
                while end < length and source[end] == "\\":
                    output[end] = ord(" ")
                    end += 1
                next_character = source[end : end + 1]
                run_length = end - position
                if next_character == quote and run_length % 2:
                    output[end] = ord(" ")
                    return end + 1, current_line
                if next_character == "\n" and run_length % 2:
                    output[end] = ord("\n")
                    string_continues_to_next.add(current_line)
                    return end + 1, current_line + 1
                return end, current_line
            next_character = source[position + 1 : position + 2]
            if f_string and next_character == "N" and source[position + 2 : position + 3] == "{":
                closing = source.find("}", position + 3)
                if closing < 0 or "\n" in source[position + 3 : closing]:
                    raise _LexicalFailure("syntax_error")
                name = source[position + 3 : closing]
                if not name or re.fullmatch(r"[A-Za-z0-9 ()-]+", name) is None:
                    raise _LexicalFailure("syntax_error")
                for masked_position in range(position, closing + 1):
                    output[masked_position] = ord(" ")
                return closing + 1, current_line
            output[position] = ord(" ")
            if next_character == "\n":
                output[position + 1] = ord("\n")
                string_continues_to_next.add(current_line)
                return position + 2, current_line + 1
            if f_string and next_character in {"{", "}"}:
                return position + 1, current_line
            if next_character:
                output[position + 1] = ord(" ")
                return position + 2, current_line
            return position + 1, current_line

        def mask_replacement(
            field_start: int,
            field_line: int,
            *,
            field_nesting: int,
        ) -> tuple[int, int]:
            if field_nesting > MAX_FSTRING_DEPTH:
                raise _LexicalFailure("complexity_limit")
            field_index = field_start
            brackets: list[str] = []
            expression_seen = False
            top_level_word: list[str] = []
            top_level_word_too_long = False
            projection_work = 0
            phase = "expression"

            def validate_expression(end: int) -> None:
                expression = source[field_start:end]
                debug_equals = re.search(
                    r"(?<![=!<>:])=(?!=)[ \t\f\n]*\Z",
                    expression,
                )
                if debug_equals is not None:
                    expression = expression[: debug_equals.start()]
                if not _valid_ast_projection(
                    expression.strip(" \t\f\n"),
                    mode="eval",
                    lexical_work=projection_work,
                ):
                    raise _LexicalFailure("syntax_error")

            def finish_word() -> None:
                nonlocal top_level_word_too_long
                if not top_level_word_too_long and "".join(top_level_word) == "lambda":
                    raise _LexicalFailure("syntax_error")
                top_level_word.clear()
                top_level_word_too_long = False

            while field_index < length:
                if source.startswith(quote * delimiter_length, field_index):
                    raise _LexicalFailure("syntax_error")
                character = source[field_index]
                string_lines.add(field_line)

                if phase == "format":
                    if character == "}":
                        output[field_index] = ord(" ")
                        return field_index + 1, field_line
                    if character == "{":
                        output[field_index] = ord(" ")
                        if source.startswith("{{", field_index):
                            output[field_index + 1] = ord(" ")
                            field_index += 2
                            continue
                        field_index, field_line = mask_replacement(
                            field_index + 1,
                            field_line,
                            field_nesting=field_nesting + 1,
                        )
                        continue
                    if character == "\n":
                        if not triple:
                            raise _LexicalFailure("syntax_error")
                        output[field_index] = ord("\n")
                        string_continues_to_next.add(field_line)
                        field_line += 1
                        field_index += 1
                        continue
                    if character == "\\":
                        field_index, field_line = mask_literal_backslash(
                            field_index,
                            field_line,
                        )
                        continue
                    output[field_index] = ord(" ")
                    field_index += 1
                    continue

                if phase == "after_conversion":
                    if character == "}":
                        output[field_index] = ord(" ")
                        return field_index + 1, field_line
                    if character == ":":
                        output[field_index] = ord(" ")
                        phase = "format"
                        field_index += 1
                        continue
                    raise _LexicalFailure("syntax_error")

                if ord(character) > 127:
                    raise _LexicalFailure("syntax_error")
                if character not in {" ", "\t", "\f", "\n"}:
                    projection_work += 1
                    if projection_work > MAX_PYTHON_PROJECTION_WORK:
                        raise _LexicalFailure("complexity_limit")
                if character == "\n":
                    if not triple:
                        raise _LexicalFailure("syntax_error")
                    finish_word()
                    output[field_index] = ord("\n")
                    string_continues_to_next.add(field_line)
                    field_line += 1
                    field_index += 1
                    continue
                if character in {"#", "\\"}:
                    raise _LexicalFailure("syntax_error")
                if character in {"'", '"'}:
                    finish_word()
                    nested_prefix = _string_prefix(source, field_index)
                    field_index, field_line = mask_string(
                        field_index,
                        field_line,
                        marker=False,
                        prefix=nested_prefix,
                        nesting=nesting + 1,
                        forbid_backslash=True,
                    )
                    expression_seen = True
                    continue
                if character in _OPENING:
                    finish_word()
                    brackets.append(character)
                    if len(brackets) > MAX_BRACKET_DEPTH:
                        raise _LexicalFailure("complexity_limit")
                    expression_seen = True
                    output[field_index] = ord(" ")
                    field_index += 1
                    continue
                if character in _CLOSING:
                    finish_word()
                    if character == "}" and not brackets:
                        if not expression_seen:
                            raise _LexicalFailure("syntax_error")
                        validate_expression(field_index)
                        output[field_index] = ord(" ")
                        return field_index + 1, field_line
                    if not brackets or brackets[-1] != _CLOSING[character]:
                        raise _LexicalFailure("syntax_error")
                    brackets.pop()
                    expression_seen = True
                    output[field_index] = ord(" ")
                    field_index += 1
                    continue
                if not brackets and character == "!":
                    finish_word()
                    if source[field_index + 1 : field_index + 2] == "=":
                        expression_seen = True
                        output[field_index] = output[field_index + 1] = ord(" ")
                        field_index += 2
                        continue
                    conversion = source[field_index + 1 : field_index + 2]
                    if not expression_seen or conversion not in {"a", "r", "s"}:
                        raise _LexicalFailure("syntax_error")
                    validate_expression(field_index)
                    output[field_index] = output[field_index + 1] = ord(" ")
                    phase = "after_conversion"
                    field_index += 2
                    continue
                if not brackets and character == ":":
                    finish_word()
                    if not expression_seen:
                        raise _LexicalFailure("syntax_error")
                    validate_expression(field_index)
                    output[field_index] = ord(" ")
                    phase = "format"
                    field_index += 1
                    continue
                if not brackets and _ascii_identifier_character(character):
                    if len(top_level_word) < 7:
                        top_level_word.append(character)
                    else:
                        top_level_word_too_long = True
                elif not brackets:
                    finish_word()
                if character not in {" ", "\t", "\f"}:
                    if character == "=" and not expression_seen:
                        raise _LexicalFailure("syntax_error")
                    expression_seen = True
                output[field_index] = ord(" ")
                field_index += 1
            raise _LexicalFailure("syntax_error")

        while index < length:
            character = source[index]
            string_lines.add(line)
            if source.startswith(quote * delimiter_length, index):
                for position in range(index, index + delimiter_length):
                    output[position] = ord(" ")
                return index + delimiter_length, line
            if bytes_literal and ord(character) > 127:
                raise _LexicalFailure("syntax_error")
            if f_string and character == "{":
                if source.startswith("{{", index):
                    output[index] = output[index + 1] = ord(" ")
                    index += 2
                else:
                    output[index] = ord(" ")
                    index, line = mask_replacement(
                        index + 1,
                        line,
                        field_nesting=nesting + 1,
                    )
                continue
            if f_string and character == "}":
                if source.startswith("}}", index):
                    output[index] = output[index + 1] = ord(" ")
                    index += 2
                    continue
                raise _LexicalFailure("syntax_error")
            if character == "\\":
                index, line = mask_literal_backslash(index, line)
                continue
            if character == "\n":
                if not triple:
                    raise _LexicalFailure("syntax_error")
                output[index] = ord("\n")
                string_continues_to_next.add(line)
                line += 1
            else:
                output[index] = ord(" ")
            index += 1
        raise _LexicalFailure("syntax_error")

    index = 0
    line = 0
    while index < length:
        character = source[index]
        if character == "#":
            while index < length and source[index] != "\n":
                output[index] = ord(" ")
                index += 1
            continue
        if character in {"'", '"'}:
            prefix = _string_prefix(source, index)
            index, line = mask_string(
                index,
                line,
                marker=True,
                prefix=prefix,
                nesting=0,
            )
            continue
        if character == "\n":
            line += 1
        index += 1
    return (
        output.decode("latin-1"),
        frozenset(string_lines),
        frozenset(string_continues_to_next),
    )


def _line_metadata(
    masked_lines: list[str],
    string_continues_to_next: frozenset[int],
) -> tuple[list[int], list[bool]]:
    depth_at_start: list[int] = []
    continued_from_previous: list[bool] = []
    brackets: list[str] = []
    continued = False
    explicit_continuation = False
    for line_index, line in enumerate(masked_lines):
        depth_at_start.append(len(brackets))
        continued_from_previous.append(continued)
        if explicit_continuation and not line.strip(" \f\t"):
            raise _LexicalFailure("syntax_error")
        for character in line:
            if character in _OPENING:
                brackets.append(character)
                if len(brackets) > MAX_BRACKET_DEPTH:
                    raise _LexicalFailure("complexity_limit")
            elif character in _CLOSING:
                if not brackets or brackets[-1] != _CLOSING[character]:
                    raise _LexicalFailure("syntax_error")
                brackets.pop()
        backslash_count = line.count("\\")
        explicit = False
        if backslash_count:
            if backslash_count != 1 or not line.endswith("\\"):
                raise _LexicalFailure("syntax_error")
            explicit = True
        continued = bool(brackets) or explicit or line_index in string_continues_to_next
        explicit_continuation = explicit
    if brackets or continued:
        raise _LexicalFailure("syntax_error")
    return depth_at_start, continued_from_previous


def _statements(
    masked_lines: list[str],
    string_lines: frozenset[int],
    depth_at_start: list[int],
    continued_from_previous: list[bool],
) -> list[_Statement]:
    statements: list[_Statement] = []
    current: _Statement | None = None
    for line_index, line in enumerate(masked_lines):
        content = line.strip(" \f\t")
        starts_statement = bool(
            content and not depth_at_start[line_index] and not continued_from_previous[line_index]
        )
        meaningful = bool(content) or line_index in string_lines
        if starts_statement:
            if current is not None:
                statements.append(current)
            prefix = line[: len(line) - len(line.lstrip(" \t\f"))]
            if "\t" in prefix or "\f" in prefix:
                raise _LexicalFailure("syntax_error")
            current = _Statement(
                start_index=line_index,
                end_index=line_index,
                indent=len(prefix),
            )
        elif meaningful:
            if current is None:
                raise _LexicalFailure("syntax_error")
            current.end_index = line_index
    if current is not None:
        statements.append(current)
    return statements


def _top_level_colon(
    masked_lines: list[str],
    statement: _Statement,
    *,
    first_offset: int = 0,
    last: bool = True,
) -> tuple[int, int] | None:
    brackets: list[str] = []
    result: tuple[int, int] | None = None
    for line_index in range(statement.start_index, statement.end_index + 1):
        line = masked_lines[line_index]
        offset = first_offset if line_index == statement.start_index else 0
        for character_index in range(offset, len(line)):
            character = line[character_index]
            if character in _OPENING:
                brackets.append(character)
            elif character in _CLOSING:
                if not brackets or brackets[-1] != _CLOSING[character]:
                    raise _LexicalFailure("syntax_error")
                brackets.pop()
            elif (
                character == ":"
                and not brackets
                and line[character_index + 1 : character_index + 2] != "="
            ):
                if not last:
                    return line_index, character_index
                result = (line_index, character_index)
    return result


def _content_after(
    masked_lines: list[str],
    statement: _Statement,
    position: tuple[int, int],
) -> str:
    line_index, character_index = position
    parts = [masked_lines[line_index][character_index + 1 :]]
    parts.extend(masked_lines[line_index + 1 : statement.end_index + 1])
    return "".join(parts).replace("\\", "").strip(" \f\t")


def _logical_statement_text(masked_lines: list[str], statement: _Statement) -> str:
    physical = "\n".join(masked_lines[statement.start_index : statement.end_index + 1])
    return physical.replace("\\\n", " ").replace("\n", " ")


def _matching_close(text: str, start: int) -> int | None:
    opening = text[start]
    if opening not in _OPENING:
        return None
    brackets = [opening]
    for index in range(start + 1, len(text)):
        character = text[index]
        if character in _OPENING:
            brackets.append(character)
        elif character in _CLOSING:
            if not brackets or brackets[-1] != _CLOSING[character]:
                return None
            brackets.pop()
            if not brackets:
                return index
    return None


def _valid_parameter_projection(value: str) -> bool:
    brackets: list[str] = []
    start = 0

    def valid_part(part: str, *, final: bool) -> bool:
        item = part.strip(" \f\t")
        if not item:
            return final
        if item in {"/", "*"}:
            return True
        if item.startswith("**"):
            item = item[2:].lstrip(" \f\t")
        elif item.startswith("*"):
            item = item[1:].lstrip(" \f\t")
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", item)
        if match is None or match.group(0) in _KEYWORDS:
            return False
        remainder = item[match.end() :].lstrip(" \f\t")
        return not remainder or remainder[0] in {":", "="}

    for index, character in enumerate(value):
        if character in _OPENING:
            brackets.append(character)
        elif character in _CLOSING:
            if not brackets or brackets[-1] != _CLOSING[character]:
                return False
            brackets.pop()
        elif character == "," and not brackets:
            if not valid_part(value[start:index], final=False):
                return False
            start = index + 1
    if brackets:
        return False
    return valid_part(value[start:], final=True)


def _valid_decorator_projection(value: str) -> bool:
    expression = value.strip(" \f\t")
    if not expression:
        return False
    return _valid_ast_projection(f"@{expression}\ndef _lumi_trace_projection():\n    pass\n")


def _normalize_string_markers(source: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character not in _STRING_MARKERS:
            result.append(character)
            index += 1
            continue
        marker = character
        index += 1
        while True:
            cursor = index
            while cursor < len(source) and source[cursor] in " \t\f\n":
                cursor += 1
            if cursor >= len(source) or source[cursor] not in _STRING_MARKERS:
                break
            if source[cursor] != marker:
                raise _LexicalFailure("syntax_error")
            index = cursor + 1
        result.extend((" ", "B" if marker == _BYTES_STRING_MARKER else "S", " "))
    return "".join(result)


def _valid_ast_projection(
    source: str,
    *,
    mode: str = "exec",
    lexical_work: int | None = None,
) -> bool:
    """Validate a bounded masked projection without deriving evidence from its AST."""

    if not source:
        return False
    normalized = _normalize_string_markers(source)
    projected = f"({normalized})" if mode == "eval" else normalized
    work = (
        sum(character not in " \t\f\n" for character in projected)
        if lexical_work is None
        else lexical_work + 2
    )
    if len(projected) > MAX_PYTHON_PROJECTION_CHARS or work > MAX_PYTHON_PROJECTION_WORK:
        raise _LexicalFailure("complexity_limit")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(projected, mode=mode, feature_version=(3, 11))
            node_count = 0
            stack = [(tree, 1)]
            while stack:
                node, depth = stack.pop()
                node_count += 1
                if (
                    node_count > MAX_PYTHON_PROJECTION_AST_NODES
                    or depth > MAX_PYTHON_PROJECTION_AST_DEPTH
                ):
                    raise _LexicalFailure("complexity_limit")
                stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
            compile(
                tree,
                "<lumi-trace-declaration>",
                mode,
                dont_inherit=True,
                optimize=0,
            )
    except (SyntaxError, SyntaxWarning, TypeError, ValueError):
        return False
    except (MemoryError, RecursionError) as exc:
        raise _LexicalFailure("complexity_limit") from exc
    return True


def _parse_declaration(
    masked_lines: list[str],
    statement: _Statement,
) -> tuple[str, str, tuple[int, int], bool] | None:
    logical = _logical_statement_text(masked_lines, statement)
    if _ASYNC_CLASS.match(logical) or _TYPE_ALIAS.match(logical):
        raise _LexicalFailure("syntax_error")
    match = _DECLARATION.match(logical)
    if match is None:
        if _DECLARATION_PREFIX.match(logical):
            raise _LexicalFailure("syntax_error")
        return None
    name = match.group("name")
    if name in _KEYWORDS:
        raise _LexicalFailure("syntax_error")
    kind = "def" if match.group("async") else str(match.group("kind"))
    colon = _top_level_colon(masked_lines, statement, last=False)
    if colon is None:
        raise _LexicalFailure("syntax_error")
    logical_colon = -1
    brackets: list[str] = []
    for index in range(match.end(), len(logical)):
        character = logical[index]
        if character in _OPENING:
            brackets.append(character)
        elif character in _CLOSING:
            if not brackets or brackets[-1] != _CLOSING[character]:
                raise _LexicalFailure("syntax_error")
            brackets.pop()
        elif character == ":" and not brackets and logical[index + 1 : index + 2] != "=":
            logical_colon = index
            break
    if logical_colon < match.end():
        raise _LexicalFailure("syntax_error")
    projected_declaration = logical[: logical_colon + 1].lstrip(" ") + " pass"
    if not _valid_ast_projection(projected_declaration):
        raise _LexicalFailure("syntax_error")
    remainder = logical[match.end() : logical_colon]
    leading = len(remainder) - len(remainder.lstrip(" "))
    next_character = remainder[leading : leading + 1]
    if next_character == "[":
        raise _LexicalFailure("syntax_error")
    if kind == "def" and next_character != "(":
        raise _LexicalFailure("syntax_error")
    if kind == "class" and next_character not in {"(", ""}:
        raise _LexicalFailure("syntax_error")
    projected_header = remainder.lstrip(" ")
    if kind == "def":
        closing = _matching_close(projected_header, 0)
        if closing is None or not _valid_parameter_projection(projected_header[1:closing]):
            raise _LexicalFailure("syntax_error")
        suffix = projected_header[closing + 1 :].strip(" \f\t")
        if suffix and (not suffix.startswith("->") or not suffix[2:].strip(" \f\t")):
            raise _LexicalFailure("syntax_error")
    elif projected_header:
        closing = _matching_close(projected_header, 0)
        if closing is None or projected_header[closing + 1 :].strip(" \f\t"):
            raise _LexicalFailure("syntax_error")
    inline_suite = bool(_content_after(masked_lines, statement, colon))
    declaration_kind = (
        "class" if kind == "class" else "async_function" if match.group("async") else "function"
    )
    return name, declaration_kind, colon, inline_suite


def _scan(
    source: str,
    *,
    maximum_lines: int,
    maximum_name_chars: int,
    maximum_qualified_name_chars: int,
) -> list[_DeclarationRecord]:
    normalized = normalize_python_newlines(source)
    if "\x00" in normalized:
        raise _LexicalFailure("syntax_error")
    lines = split_python_lines(normalized)
    if len(lines) > maximum_lines:
        raise _LexicalFailure("complexity_limit")
    masked, string_lines, string_continues = _mask_strings_and_comments(normalized)
    masked_lines = split_python_lines(masked)
    if any(
        ord(character) > 127
        for character in masked
        if character != "\n" and character not in _STRING_MARKERS
    ) or any(character in "?$`" for character in masked):
        raise _LexicalFailure("syntax_error")
    depth_at_start, continued_from_previous = _line_metadata(
        masked_lines,
        string_continues,
    )
    statements = _statements(
        masked_lines,
        string_lines,
        depth_at_start,
        continued_from_previous,
    )

    indent_stack = [0]
    expected_indent = False
    pending_decorator_indent: int | None = None
    active: list[_DeclarationRecord] = []
    declarations: list[_DeclarationRecord] = []
    previous_statement_end = 0
    for statement in statements:
        indent = statement.indent
        if expected_indent:
            if indent <= indent_stack[-1]:
                raise _LexicalFailure("syntax_error")
            indent_stack.append(indent)
        else:
            while indent < indent_stack[-1]:
                indent_stack.pop()
            if indent != indent_stack[-1]:
                raise _LexicalFailure("syntax_error")

        while active and active[-1].indent >= indent:
            active[-1].end_line = previous_statement_end
            active.pop()

        parsed = _parse_declaration(masked_lines, statement)
        logical_content = _logical_statement_text(masked_lines, statement).lstrip(" ")
        decorator = logical_content.startswith("@")
        if decorator and not _valid_decorator_projection(logical_content[1:]):
            raise _LexicalFailure("syntax_error")
        if (
            parsed is None
            and not decorator
            and logical_content.rstrip(" \f\t").endswith(
                ("=", "+", "-", "/", "%", "@", "&", "|", "^", "~", "<", ">")
            )
        ):
            raise _LexicalFailure("syntax_error")
        if pending_decorator_indent is not None:
            if decorator:
                if indent != pending_decorator_indent:
                    raise _LexicalFailure("syntax_error")
            elif parsed is None or indent != pending_decorator_indent:
                raise _LexicalFailure("syntax_error")
            else:
                pending_decorator_indent = None
        elif decorator:
            pending_decorator_indent = indent

        colon = parsed[2] if parsed is not None else _top_level_colon(masked_lines, statement)
        opens_block = colon is not None and not _content_after(masked_lines, statement, colon)
        if parsed is not None:
            name, declaration_kind, _declaration_colon, inline_suite = parsed
            if len(name) > maximum_name_chars:
                raise _LexicalFailure("complexity_limit")
            qualified_name = ".".join([*[item.name for item in active], name])
            if len(qualified_name) > maximum_qualified_name_chars:
                raise _LexicalFailure("complexity_limit")
            declaration = _DeclarationRecord(
                name=name,
                declaration_kind=declaration_kind,
                indent=indent,
                start_line=statement.start_index + 1,
                end_line=statement.end_index + 1 if inline_suite else None,
                qualified_name=qualified_name,
                scope_depth=len(active),
            )
            declarations.append(declaration)
            if not inline_suite:
                if not opens_block:
                    raise _LexicalFailure("syntax_error")
                active.append(declaration)
        expected_indent = opens_block
        previous_statement_end = statement.end_index + 1

    if expected_indent or pending_decorator_indent is not None:
        raise _LexicalFailure("syntax_error")
    while active:
        active[-1].end_line = previous_statement_end
        active.pop()
    if any(declaration.end_line is None for declaration in declarations):
        raise _LexicalFailure("syntax_error")
    return declarations


def scan_python_declarations(
    source: str,
    *,
    maximum_symbols: int,
    maximum_lines: int,
    maximum_name_chars: int,
    maximum_qualified_name_chars: int,
) -> tuple[list[dict[str, Any]], str | None, bool]:
    """Return declaration records under the fixed, fail-closed lexical contract."""

    limits = (
        maximum_symbols,
        maximum_lines,
        maximum_name_chars,
        maximum_qualified_name_chars,
    )
    if (
        any(not isinstance(limit, int) or isinstance(limit, bool) for limit in limits)
        or maximum_symbols < 0
        or any(limit <= 0 for limit in limits[1:])
    ):
        raise ValueError("Python declaration scan limits are invalid")
    try:
        declarations = _scan(
            source,
            maximum_lines=maximum_lines,
            maximum_name_chars=maximum_name_chars,
            maximum_qualified_name_chars=maximum_qualified_name_chars,
        )
    except _LexicalFailure as exc:
        return [], exc.reason, False
    limited = len(declarations) > maximum_symbols
    return (
        [
            {
                "name": declaration.name,
                "qualified_name": declaration.qualified_name,
                "declaration_kind": declaration.declaration_kind,
                "scope_depth": declaration.scope_depth,
                "start_line": declaration.start_line,
                "end_line": declaration.end_line,
            }
            for declaration in declarations[:maximum_symbols]
        ],
        None,
        limited,
    )
