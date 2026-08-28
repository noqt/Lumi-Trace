# SPDX-License-Identifier: Apache-2.0
"""Manual and SARIF finding import into normalized-finding-v1."""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_sha256, load_json, sha256_file, stable_id
from .errors import InputError, UnsupportedError
from .indexing import tokenize

NORMALIZED_FINDING_VERSION = "normalized-finding-v1"
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTE", "UNKNOWN"}
_CWE = re.compile(r"(?i)\bCWE[-_ ]?(\d+)\b")
_FINDING_ID = re.compile(r"^[A-Za-z0-9._:-]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEYWORD = re.compile(r"^[a-z][a-z0-9]{1,63}$")
_MAX_SARIF_MESSAGE_CHARS = 16_384


def _require_fields(
    value: Any,
    field: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{field} must be an object")
    missing = sorted(required - set(value))
    if missing:
        raise InputError(f"{field} is missing: {', '.join(missing)}")
    unknown = sorted(set(value) - required - (optional or set()))
    if unknown:
        raise InputError(f"{field} has unknown fields: {', '.join(unknown)}")
    return value


def _validate_string_array(
    value: Any, field: str, *, pattern: re.Pattern[str] | None = None
) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InputError(f"{field} must be a string array")
    if len(value) != len(set(value)):
        raise InputError(f"{field} must not contain duplicates")
    if pattern is not None and any(pattern.fullmatch(item) is None for item in value):
        raise InputError(f"{field} contains an invalid value")


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _string(value: Any, field: str, *, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise InputError(f"{field} must be a non-empty string")
    return value.strip()


def _severity(value: Any) -> dict[str, str]:
    original = "" if value is None else str(value).strip()
    normalized = original.upper().replace("-", "_")
    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "INFO": "NOTE",
        "INFORMATIONAL": "NOTE",
        "NONE": "UNKNOWN",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in _SEVERITIES:
        normalized = "UNKNOWN"
    return {"normalized": normalized, "original": original or "unknown"}


def _security_severity(rule: dict[str, Any], fallback: Any) -> dict[str, str]:
    properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    raw = properties.get("security-severity")
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return _severity(fallback)
    if score >= 9.0:
        normalized = "CRITICAL"
    elif score >= 7.0:
        normalized = "HIGH"
    elif score >= 4.0:
        normalized = "MEDIUM"
    elif score > 0:
        normalized = "LOW"
    else:
        normalized = "UNKNOWN"
    return {"normalized": normalized, "original": str(raw)}


def _safe_relative_path(value: str, repository_root: Path | None = None) -> str:
    windows_drive_path = re.match(r"^[A-Za-z]:[\\/]", value) is not None
    if windows_drive_path:
        raw_path = urllib.parse.unquote(value)
    else:
        parsed = urllib.parse.urlsplit(value)
        scheme = parsed.scheme.casefold()
        if scheme and scheme != "file":
            raise UnsupportedError("remote SARIF artifact locations are unsupported")
        if scheme == "file" and parsed.netloc:
            raise UnsupportedError("remote file URI authorities are unsupported")
        if parsed.query or parsed.fragment:
            raise UnsupportedError("SARIF artifact location queries and fragments are unsupported")
        raw_path = urllib.parse.unquote(parsed.path if scheme else value)
    raw_path = raw_path.replace("\\", "/")
    if "\x00" in raw_path:
        raise InputError("finding location contains a NUL byte")
    if re.match(r"^/[A-Za-z]:/", raw_path):
        raw_path = raw_path[1:]
    is_absolute = raw_path.startswith("/") or bool(re.match(r"^[A-Za-z]:/", raw_path))
    if is_absolute:
        if repository_root is None:
            raise InputError(
                "absolute finding locations require --repository so host paths can be removed"
            )
        candidate = Path(raw_path).resolve(strict=False)
        root = repository_root.resolve(strict=True)
        try:
            raw_path = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise InputError("finding location is outside the supplied repository") from exc
    path = PurePosixPath(raw_path)
    if not raw_path or path.is_absolute() or ".." in path.parts:
        raise InputError(f"finding location is not a safe repository-relative path: {value!r}")
    return path.as_posix().removeprefix("./")


def _region(value: Any) -> dict[str, int]:
    region = value if isinstance(value, dict) else {}
    raw_values = {
        "start_line": region.get("startLine", region.get("start_line", 1)),
        "start_column": region.get("startColumn", region.get("start_column", 1)),
    }
    raw_values["end_line"] = region.get("endLine", region.get("end_line", raw_values["start_line"]))
    raw_values["end_column"] = region.get(
        "endColumn", region.get("end_column", raw_values["start_column"])
    )
    if any(not isinstance(item, int) or isinstance(item, bool) for item in raw_values.values()):
        raise InputError("source regions must use integers")
    start_line = raw_values["start_line"]
    start_column = raw_values["start_column"]
    end_line = raw_values["end_line"]
    end_column = raw_values["end_column"]
    if min(start_line, start_column, end_line, end_column) < 1:
        raise InputError("source regions are one-based positive integers")
    if (end_line, end_column) < (start_line, start_column):
        raise InputError("source region ends before it starts")
    return {
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
    }


def _normalise_locations(
    locations: Any, repository_root: Path | None = None
) -> list[dict[str, object]]:
    if locations is None:
        return []
    if not isinstance(locations, list):
        raise InputError("locations must be an array")
    normalized: list[dict[str, object]] = []
    for item in locations:
        if not isinstance(item, dict):
            raise InputError("each location must be an object")
        allowed_location = {
            "path",
            "uri",
            "symbol",
            "region",
            "startLine",
            "startColumn",
            "endLine",
            "endColumn",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        }
        unknown = sorted(set(item) - allowed_location)
        if unknown:
            raise InputError(f"unknown manual location fields: {', '.join(unknown)}")
        if "path" in item and "uri" in item:
            raise InputError("manual location must use path or uri, not both")
        path_value = item.get("path") or item.get("uri")
        if not isinstance(path_value, str):
            raise InputError("each location requires path")
        flat_region_fields = {
            "startLine",
            "startColumn",
            "endLine",
            "endColumn",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        }
        if "region" in item and set(item) & flat_region_fields:
            raise InputError("manual location must not mix nested and flat region fields")
        region_input = (
            item["region"]
            if "region" in item
            else {key: item[key] for key in flat_region_fields if key in item}
        )
        if not isinstance(region_input, dict):
            raise InputError("manual location region must be an object")
        region_unknown = sorted(set(region_input) - flat_region_fields)
        if region_unknown:
            raise InputError(f"unknown manual region fields: {', '.join(region_unknown)}")
        for camel, snake in (
            ("startLine", "start_line"),
            ("startColumn", "start_column"),
            ("endLine", "end_line"),
            ("endColumn", "end_column"),
        ):
            if camel in region_input and snake in region_input:
                raise InputError(f"manual region must not contain both {camel} and {snake}")
        location: dict[str, object] = {
            "path": _safe_relative_path(path_value, repository_root),
            "region": _region(region_input),
        }
        if "symbol" in item:
            location["symbol"] = _string(item["symbol"], "location.symbol", required=True)
        normalized.append(location)
    normalized.sort(
        key=lambda item: (
            str(item["path"]),
            int(item["region"]["start_line"]),  # type: ignore[index]
            int(item["region"]["start_column"]),  # type: ignore[index]
            str(item.get("symbol", "")),
        )
    )
    return normalized


def _cwes(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        raise InputError("rule.cwes must be a string array")
    found: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise InputError("rule.cwes entries must be strings")
        match = _CWE.search(value)
        if match:
            found.add(f"CWE-{int(match.group(1))}")
    return sorted(found, key=lambda item: int(item.split("-")[1]))


def _finalize_finding(
    payload: dict[str, object], supplied_id: str | None = None
) -> dict[str, object]:
    if supplied_id:
        safe_id = re.sub(r"[^A-Za-z0-9._:-]+", "-", supplied_id).strip("-")
        if not safe_id:
            raise InputError("finding id has no usable characters")
        payload["finding_id"] = safe_id
    else:
        payload["finding_id"] = stable_id("finding", payload)
    validate_normalized_finding(payload)
    return payload


def import_manual(path: Path, repository_root: Path | None = None) -> dict[str, object]:
    """Import a strict, human-authored finding JSON document."""

    raw = load_json(path, max_bytes=2 * 1024 * 1024, max_items=20_000)
    if not isinstance(raw, dict):
        raise InputError("manual finding must be a JSON object")
    allowed = {
        "schema_version",
        "id",
        "title",
        "description",
        "severity",
        "rule",
        "locations",
        "keywords",
        "fingerprints",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise InputError(f"unknown manual finding fields: {', '.join(unknown)}")
    if raw.get("schema_version", "manual-finding-v1") != "manual-finding-v1":
        raise UnsupportedError("manual finding schema_version must be manual-finding-v1")

    if "id" in raw and (not isinstance(raw["id"], str) or not raw["id"].strip()):
        raise InputError("id must be a non-empty string")
    if "description" in raw and not isinstance(raw["description"], str):
        raise InputError("description must be a string")
    if "severity" in raw and raw["severity"] is not None and not isinstance(raw["severity"], str):
        raise InputError("severity must be a string or null")
    if "rule" in raw and not isinstance(raw["rule"], dict):
        raise InputError("rule must be an object")
    rule_raw = raw.get("rule") or {}
    if not isinstance(rule_raw, dict):
        raise InputError("rule must be an object")
    rule_unknown = sorted(set(rule_raw) - {"id", "name", "cwes", "tags"})
    if rule_unknown:
        raise InputError(f"unknown manual rule fields: {', '.join(rule_unknown)}")
    if "cwes" in rule_raw and not isinstance(rule_raw["cwes"], str | list):
        raise InputError("rule.cwes must be a string or string array")
    if "tags" in rule_raw and not isinstance(rule_raw["tags"], list):
        raise InputError("rule.tags must be a string array")
    tags = rule_raw.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
        raise InputError("rule.tags must be a string array")
    if "keywords" in raw and not isinstance(raw["keywords"], list):
        raise InputError("keywords must be a string array")
    keywords = raw.get("keywords") or []
    if not isinstance(keywords, list) or not all(isinstance(item, str) for item in keywords):
        raise InputError("keywords must be a string array")
    if "locations" in raw and not isinstance(raw["locations"], list):
        raise InputError("locations must be an array")
    raw_locations = raw.get("locations") or []
    if not isinstance(raw_locations, list):
        raise InputError("locations must be an array")
    if len(keywords) > 1_000 or len(raw_locations) > 1_000:
        raise InputError("manual finding exceeds keyword or location count limit of 1000")
    if "fingerprints" in raw and not isinstance(raw["fingerprints"], dict):
        raise InputError("fingerprints must map strings to strings")
    fingerprints = raw.get("fingerprints") or {}
    if not isinstance(fingerprints, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in fingerprints.items()
    ):
        raise InputError("fingerprints must map strings to strings")

    title = _string(raw.get("title"), "title", required=True)
    description = _string(raw.get("description", ""), "description")
    rule_id = _string(rule_raw.get("id", "manual"), "rule.id", required=True)
    payload: dict[str, object] = {
        "schema_version": NORMALIZED_FINDING_VERSION,
        "source": {
            "kind": "MANUAL",
            "input_sha256": sha256_file(path),
        },
        "rule": {
            "id": rule_id,
            "name": _string(rule_raw.get("name", rule_id), "rule.name", required=True),
            "cwes": _cwes(rule_raw.get("cwes")),
            "tags": sorted(set(item.strip() for item in tags if item.strip())),
        },
        "message": {"title": title, "text": description or title},
        "severity": _severity(raw.get("severity")),
        "locations": _normalise_locations(raw.get("locations"), repository_root),
        "keywords": sorted(set(token for item in keywords for token in tokenize(item))),
        "fingerprints": dict(sorted(fingerprints.items())),
    }
    supplied_id = f"manual:{raw['id']}" if raw.get("id") else None
    return _finalize_finding(payload, supplied_id)


def _message_text(value: Any) -> str:
    if isinstance(value, dict):
        text = value.get("text") or value.get("markdown")
        if isinstance(text, str):
            return text.strip()
    return ""


def _sarif_location(
    location: dict[str, Any], repository_root: Path | None
) -> dict[str, object] | None:
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("uri"), str):
        return None
    uri_base_id = artifact.get("uriBaseId")
    if uri_base_id is not None and uri_base_id != "%SRCROOT%":
        raise UnsupportedError(
            "SARIF artifact uriBaseId must be omitted or use the explicit %SRCROOT% boundary"
        )
    result: dict[str, object] = {
        "path": _safe_relative_path(artifact["uri"], repository_root),
        "region": _region(physical.get("region")),
    }
    logical = location.get("logicalLocations")
    if isinstance(logical, list):
        names = [
            item.get("fullyQualifiedName") or item.get("name")
            for item in logical
            if isinstance(item, dict)
        ]
        symbol = next((item for item in names if isinstance(item, str) and item.strip()), None)
        if symbol:
            result["symbol"] = symbol.strip()
    return result


def _validate_sarif_uri_bases(run: dict[str, Any]) -> None:
    """Reject a declared source-root alias that changes its local meaning."""

    bases = run.get("originalUriBaseIds")
    if bases is None:
        return
    if not isinstance(bases, dict):
        raise InputError("SARIF run.originalUriBaseIds must be an object")
    source_root = bases.get("%SRCROOT%")
    if source_root is not None and (
        not isinstance(source_root, dict)
        or set(source_root) != {"uri"}
        or source_root.get("uri") != "./"
    ):
        raise UnsupportedError('SARIF %SRCROOT% must use the canonical local mapping {"uri":"./"}')


def _load_sarif_document(path: Path) -> tuple[list[object], str]:
    """Load and validate the document-level SARIF boundary once."""

    document = load_json(path, max_bytes=64 * 1024 * 1024, max_items=1_000_000)
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise UnsupportedError("SARIF input must use version 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise InputError("SARIF input has no runs")
    if len(runs) > 256:
        raise InputError("SARIF input exceeds run limit of 256")
    return runs, sha256_file(path)


def _sarif_run_context(
    run: object,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[object]]:
    """Validate a run and return its rule lookup and result collection."""

    if not isinstance(run, dict):
        raise InputError("SARIF run must be an object")
    _validate_sarif_uri_bases(run)
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise InputError("SARIF run.tool must be an object")
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise InputError("SARIF run.tool.driver must be an object")
    rules_value = driver.get("rules")
    if rules_value is not None and not isinstance(rules_value, list):
        raise InputError("SARIF driver.rules must be an array")
    rules = rules_value or []
    if len(rules) > 10_000:
        raise InputError("SARIF run exceeds rule limit of 10000")
    rule_by_id = {
        item.get("id"): item
        for item in rules
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    results = run.get("results")
    if results is None:
        results = []
    elif not isinstance(results, list):
        raise InputError("SARIF run.results must be an array")
    if len(results) > 10_000:
        raise InputError("SARIF run exceeds result limit of 10000")
    return driver, rule_by_id, results


def _normalize_sarif_result(
    result: object,
    *,
    driver: dict[str, Any],
    rule_by_id: dict[str, dict[str, Any]],
    input_sha256: str,
    run_index: int,
    result_index: int,
    repository_root: Path | None,
) -> dict[str, object]:
    """Normalize one already-selected SARIF result without reading the document again."""

    if not isinstance(result, dict):
        raise InputError("SARIF result must be an object")
    rule_id = str(result.get("ruleId") or "unknown")
    rule = rule_by_id.get(rule_id, {})
    message = _message_text(result.get("message")) or rule_id
    short = _message_text(rule.get("shortDescription")) or rule_id
    if len(message) > _MAX_SARIF_MESSAGE_CHARS or len(short) > _MAX_SARIF_MESSAGE_CHARS:
        raise InputError(
            f"SARIF result message exceeds character limit of {_MAX_SARIF_MESSAGE_CHARS}"
        )
    rule_properties = rule.get("properties")
    if rule_properties is not None and not isinstance(rule_properties, dict):
        raise InputError("SARIF rule.properties must be an object")
    tags_raw = (rule_properties or {}).get("tags", [])
    tags = tags_raw if isinstance(tags_raw, list) else []
    cwes = _cwes([*map(str, tags), rule_id, message])
    locations: list[dict[str, object]] = []
    result_locations = result.get("locations", [])
    if not isinstance(result_locations, list):
        raise InputError("SARIF result.locations must be an array")
    if len(result_locations) > 1_000:
        raise InputError("SARIF result exceeds location limit of 1000")
    for item in result_locations:
        if not isinstance(item, dict):
            raise InputError("SARIF result location must be an object")
        normalized = _sarif_location(item, repository_root)
        if normalized:
            locations.append(normalized)
    locations.sort(
        key=lambda item: (
            str(item["path"]),
            int(item["region"]["start_line"]),  # type: ignore[index]
            str(item.get("symbol", "")),
        )
    )
    fingerprints_raw = result.get("fingerprints") or {}
    fingerprints = (
        {
            str(key): str(value)
            for key, value in fingerprints_raw.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        if isinstance(fingerprints_raw, dict)
        else {}
    )
    payload: dict[str, object] = {
        "schema_version": NORMALIZED_FINDING_VERSION,
        "source": {
            "kind": "SARIF",
            "input_sha256": input_sha256,
            "tool_name": str(driver.get("name") or "unknown"),
            "tool_version": str(
                driver.get("semanticVersion") or driver.get("version") or "unknown"
            ),
            "sarif_run_index": run_index,
            "sarif_result_index": result_index,
        },
        "rule": {
            "id": rule_id,
            "name": str(rule.get("name") or rule_id),
            "cwes": cwes,
            "tags": sorted(set(str(item) for item in tags if isinstance(item, str))),
        },
        "message": {"title": short, "text": message},
        "severity": _security_severity(rule, result.get("level")),
        "locations": locations,
        "keywords": [],
        "fingerprints": dict(sorted(fingerprints.items())),
    }
    supplied = result.get("guid")
    supplied_id = f"sarif:{supplied}" if isinstance(supplied, str) else None
    return _finalize_finding(payload, supplied_id)


def import_sarif(
    path: Path,
    *,
    run_index: int | None = None,
    result_index: int | None = None,
    repository_root: Path | None = None,
) -> list[dict[str, object]]:
    """Import selected or all SARIF 2.1.0 results as separate findings."""

    runs, input_sha256 = _load_sarif_document(path)
    run_indexes = [run_index] if run_index is not None else list(range(len(runs)))
    findings: list[dict[str, object]] = []

    for selected_run in run_indexes:
        if selected_run is None or selected_run < 0 or selected_run >= len(runs):
            raise InputError("SARIF run index is out of range")
        driver, rule_by_id, results = _sarif_run_context(runs[selected_run])
        selected_results = [result_index] if result_index is not None else list(range(len(results)))

        for selected_result in selected_results:
            if selected_result is None or selected_result < 0 or selected_result >= len(results):
                raise InputError("SARIF result index is out of range")
            findings.append(
                _normalize_sarif_result(
                    results[selected_result],
                    driver=driver,
                    rule_by_id=rule_by_id,
                    input_sha256=input_sha256,
                    run_index=selected_run,
                    result_index=selected_result,
                    repository_root=repository_root,
                )
            )
    return findings


def import_sarif_batch(
    path: Path, *, repository_root: Path | None = None, max_findings: int = 100
) -> list[dict[str, object]]:
    """Normalize every SARIF result, preserving result-local errors for batch triage."""

    if (
        not isinstance(max_findings, int)
        or isinstance(max_findings, bool)
        or not 1 <= max_findings <= 1000
    ):
        raise InputError("max_findings must be between 1 and 1000")
    runs, input_sha256 = _load_sarif_document(path)
    contexts: list[tuple[dict[str, Any], dict[str, dict[str, Any]], list[object]]] = []
    selected_count = 0
    for run in runs:
        context = _sarif_run_context(run)
        contexts.append(context)
        selected_count += len(context[2])
    if selected_count > max_findings:
        raise InputError(
            "SARIF selection contains "
            f"{selected_count} results, exceeding --max-findings {max_findings}"
        )

    items: list[dict[str, object]] = []
    for run_index, (driver, rule_by_id, results) in enumerate(contexts):
        for result_index, result in enumerate(results):
            source = {"sarif_run_index": run_index, "sarif_result_index": result_index}
            try:
                finding = _normalize_sarif_result(
                    result,
                    driver=driver,
                    rule_by_id=rule_by_id,
                    input_sha256=input_sha256,
                    run_index=run_index,
                    result_index=result_index,
                    repository_root=repository_root,
                )
            except (InputError, UnsupportedError, ValueError, TypeError):
                items.append(
                    {"source": source, "finding": None, "error_code": "NORMALIZATION_FAILED"}
                )
            else:
                items.append({"source": source, "finding": finding, "error_code": None})
    return items


def validate_normalized_finding(value: Any) -> None:
    """Enforce normalized-finding-v1 without a runtime schema dependency."""

    finding = _require_fields(
        value,
        "normalized finding",
        required={
            "schema_version",
            "finding_id",
            "source",
            "rule",
            "message",
            "severity",
            "locations",
            "keywords",
            "fingerprints",
        },
    )
    if finding["schema_version"] != NORMALIZED_FINDING_VERSION:
        raise InputError("finding must use normalized-finding-v1")

    finding_id = finding["finding_id"]
    if not isinstance(finding_id, str) or _FINDING_ID.fullmatch(finding_id) is None:
        raise InputError("normalized finding id is invalid")

    source = _require_fields(
        finding["source"],
        "normalized finding source",
        required={"kind", "input_sha256"},
        optional={"tool_name", "tool_version", "sarif_run_index", "sarif_result_index"},
    )
    input_hash = source["input_sha256"]
    if not isinstance(input_hash, str) or _SHA256.fullmatch(input_hash) is None:
        raise InputError("normalized finding source hash is invalid")
    if source["kind"] == "MANUAL":
        if set(source) != {"kind", "input_sha256"}:
            raise InputError("manual source contains SARIF-only fields")
    elif source["kind"] == "SARIF":
        required_sarif = {
            "kind",
            "input_sha256",
            "tool_name",
            "tool_version",
            "sarif_run_index",
            "sarif_result_index",
        }
        if set(source) != required_sarif:
            raise InputError("SARIF source is missing required provenance")
        if any(
            not isinstance(source[key], str) or not source[key]
            for key in ("tool_name", "tool_version")
        ) or any(
            not _nonnegative_integer(source[key])
            for key in ("sarif_run_index", "sarif_result_index")
        ):
            raise InputError("SARIF source provenance is invalid")
    else:
        raise InputError("normalized finding source kind is invalid")

    rule = _require_fields(
        finding["rule"], "normalized finding rule", required={"id", "name", "cwes", "tags"}
    )
    if any(not isinstance(rule[key], str) or not rule[key] for key in ("id", "name")):
        raise InputError("normalized finding rule id and name must be non-empty strings")
    _validate_string_array(
        rule["cwes"], "normalized finding rule.cwes", pattern=re.compile(r"^CWE-[0-9]+$")
    )
    _validate_string_array(rule["tags"], "normalized finding rule.tags")

    message = _require_fields(
        finding["message"], "normalized finding message", required={"title", "text"}
    )
    if any(not isinstance(message[key], str) or not message[key] for key in ("title", "text")):
        raise InputError("normalized finding message values must be non-empty strings")

    severity = _require_fields(
        finding["severity"],
        "normalized finding severity",
        required={"normalized", "original"},
    )
    if (
        severity["normalized"] not in _SEVERITIES
        or not isinstance(severity["original"], str)
        or not severity["original"]
    ):
        raise InputError("normalized finding severity is invalid")

    locations = finding["locations"]
    if not isinstance(locations, list):
        raise InputError("normalized finding locations must be an array")
    for index, location_value in enumerate(locations):
        location = _require_fields(
            location_value,
            f"normalized finding locations[{index}]",
            required={"path", "region"},
            optional={"symbol"},
        )
        path = location["path"]
        if not isinstance(path, str) or not path or _safe_relative_path(path) != path:
            raise InputError(f"normalized finding locations[{index}].path is not canonical")
        if "symbol" in location and (
            not isinstance(location["symbol"], str) or not location["symbol"]
        ):
            raise InputError(f"normalized finding locations[{index}].symbol is invalid")
        region = _require_fields(
            location["region"],
            f"normalized finding locations[{index}].region",
            required={"start_line", "start_column", "end_line", "end_column"},
        )
        if not all(_positive_integer(region[key]) for key in region):
            raise InputError(f"normalized finding locations[{index}].region is invalid")
        if (region["end_line"], region["end_column"]) < (
            region["start_line"],
            region["start_column"],
        ):
            raise InputError(f"normalized finding locations[{index}].region ends before it starts")

    _validate_string_array(finding["keywords"], "normalized finding keywords", pattern=_KEYWORD)
    fingerprints = finding["fingerprints"]
    if not isinstance(fingerprints, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in fingerprints.items()
    ):
        raise InputError("normalized finding fingerprints must map strings to strings")

    expected = canonical_sha256({key: item for key, item in value.items() if key != "finding_id"})
    expected_finding_id = f"finding:{expected.removeprefix('sha256:')}"
    if finding_id.startswith("finding:") and finding_id != expected_finding_id:
        raise InputError("normalized finding content identity does not match its payload")


def load_normalized_finding(path: Path) -> dict[str, object]:
    value = load_json(path, max_bytes=8 * 1024 * 1024, max_items=100_000)
    validate_normalized_finding(value)
    return value
