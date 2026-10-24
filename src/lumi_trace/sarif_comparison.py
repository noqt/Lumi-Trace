# SPDX-License-Identifier: Apache-2.0
"""Bounded, fail-closed comparison of two local SARIF reports.

The comparison deliberately stays at the report boundary.  It uses the
existing SARIF batch importer for normalization, while retaining a small,
bounded projection of the original report locations and result positions for
auditability.  No repository source is read or executed.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from collections import defaultdict
from pathlib import Path, PurePosixPath

from .canonical import canonical_json_bytes, dump_json, load_json, sha256_file
from .errors import InputError, UnsupportedError
from .findings import import_sarif_batch


COMPARISON_SCHEMA_VERSION = "sarif-comparison-v1"
MAX_COMPARISON_RESULTS = 1_000
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_REPORT_ITEMS = 1_000_000

_UNKNOWN = "unknown"
_RAW_REGION_KEYS = (
    "startLine",
    "startColumn",
    "endLine",
    "endColumn",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
)
_REASON_PRIORITY = {
    "INPUT_FAILED": 0,
    "INPUT_PARTIAL": 1,
    "MALFORMED_INPUT": 2,
    "NORMALIZATION_ERROR": 3,
    "DUPLICATE_FINGERPRINT": 4,
    "CONFLICTING_FINGERPRINT": 5,
    "DUPLICATE_LOCATION": 6,
    "SHIFTED_LOCATION": 7,
    "TOOL_INCOMPATIBLE": 8,
    "IDENTITY_INSUFFICIENT": 9,
    "INPUT_EMPTY_IDENTITY_UNKNOWN": 10,
}


def _known(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.casefold() != _UNKNOWN


def _safe_report_file(path: Path, label: str) -> None:
    """Require a readable regular report file and reject direct symlinks."""

    if path.is_symlink():
        raise InputError(f"{label} must not be a symlink")
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise InputError(f"{label} is not readable: {path}") from exc
    if not path.is_file():
        raise InputError(f"{label} must be a regular file: {path}")
    if stat_result.st_size > MAX_REPORT_BYTES:
        raise InputError(f"{label} exceeds the bounded size limit of {MAX_REPORT_BYTES} bytes")


def _safe_repository(path: Path) -> Path:
    if path.is_symlink():
        raise InputError("repository must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise InputError(f"repository path cannot be resolved: {path}") from exc
    if not resolved.is_dir():
        raise InputError(f"repository must be an existing directory: {path}")
    return resolved


def _safe_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise InputError("output already exists; choose a new output path")


def _driver_metadata(driver: object) -> tuple[str, str]:
    if not isinstance(driver, dict):
        return _UNKNOWN, _UNKNOWN
    raw_name = driver.get("name")
    raw_version = driver.get("semanticVersion") or driver.get("version")
    name = raw_name if isinstance(raw_name, str) and raw_name else _UNKNOWN
    version = raw_version if isinstance(raw_version, str) and raw_version else _UNKNOWN
    return name, version


def _raw_region(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    # Keep the original SARIF spelling and scalar values, but never copy an
    # unbounded arbitrary object into the comparison artifact.
    return {
        key: value[key]
        for key in _RAW_REGION_KEYS
        if key in value and _json_scalar(value[key])
    }


def _json_scalar(value: object) -> bool:
    return value is None or isinstance(value, (bool, int, str)) or (
        isinstance(value, float) and math.isfinite(value)
    )


def _raw_location(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"artifact_uri": None, "artifact_uri_base_id": None, "region": None}
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        return {"artifact_uri": None, "artifact_uri_base_id": None, "region": None}
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        artifact = {}
    uri = artifact.get("uri") if isinstance(artifact.get("uri"), str) else None
    uri_base_id = (
        artifact.get("uriBaseId") if isinstance(artifact.get("uriBaseId"), str) else None
    )
    return {
        "artifact_uri": uri,
        "artifact_uri_base_id": uri_base_id,
        "region": _raw_region(physical.get("region")),
    }


def _raw_locations(result: object) -> list[dict[str, object]]:
    if not isinstance(result, dict):
        return []
    locations = result.get("locations")
    if not isinstance(locations, list):
        return []
    return [_raw_location(item) for item in locations[:MAX_COMPARISON_RESULTS]]


def _raw_result(runs: object, run_index: int, result_index: int) -> object:
    if not isinstance(runs, list) or not 0 <= run_index < len(runs):
        return None
    run = runs[run_index]
    if not isinstance(run, dict):
        return None
    results = run.get("results")
    if not isinstance(results, list) or not 0 <= result_index < len(results):
        return None
    return results[result_index]


def _report_identities(document: dict[str, object]) -> tuple[set[tuple[str, str, str]], bool]:
    """Collect known tool/version/rule identities without reading source files."""

    identities: set[tuple[str, str, str]] = set()
    has_unknown_metadata = False
    runs = document.get("runs")
    if not isinstance(runs, list):
        return identities, True
    for run in runs:
        if not isinstance(run, dict):
            has_unknown_metadata = True
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name, version = _driver_metadata(driver)
        if not _known(name) or not _known(version):
            has_unknown_metadata = True
        rule_ids_from_rules: set[str] = set()
        rules = driver.get("rules") if isinstance(driver, dict) else None
        if rules is not None:
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict) and _known(rule.get("id")):
                        rule_ids_from_rules.add(str(rule["id"]))
            else:
                has_unknown_metadata = True
        results = run.get("results")
        rule_ids_from_results: set[str] = set()
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict) and _known(result.get("ruleId")):
                    rule_ids_from_results.add(str(result["ruleId"]))
                elif result is not None:
                    has_unknown_metadata = True
        elif results is not None:
            has_unknown_metadata = True
        rule_ids = rule_ids_from_results if rule_ids_from_results else rule_ids_from_rules
        if _known(name) and _known(version):
            identities.update((name, version, rule_id) for rule_id in rule_ids)
            if len(identities) > MAX_COMPARISON_RESULTS:
                has_unknown_metadata = True
                identities = set(sorted(identities)[:MAX_COMPARISON_RESULTS])
    return identities, has_unknown_metadata


def _has_failed_invocation(document: dict[str, object]) -> bool:
    """Return whether any SARIF run explicitly reports a failed invocation."""

    runs = document.get("runs")
    if not isinstance(runs, list):
        return False
    for run in runs:
        if not isinstance(run, dict):
            continue
        invocations = run.get("invocations")
        if not isinstance(invocations, list):
            continue
        if any(
            isinstance(invocation, dict)
            and invocation.get("executionSuccessful") is False
            for invocation in invocations
        ):
            return True
    return False


def _unsafe_uri(uri: object, repository: Path) -> bool:
    """Return whether a raw SARIF artifact URI is outside the local boundary."""

    if not isinstance(uri, str):
        return False
    decoded = urllib.parse.unquote(uri)
    if "\x00" in decoded or "\\" in decoded:
        return True
    windows_drive_path = re.match(r"^[A-Za-z]:/", decoded) is not None
    parsed = urllib.parse.urlsplit(decoded)
    if parsed.query or parsed.fragment:
        return True
    if parsed.netloc:
        return True
    if not windows_drive_path and parsed.scheme and parsed.scheme.casefold() != "file":
        return True
    raw_path = (
        parsed.path
        if not windows_drive_path and parsed.scheme.casefold() == "file"
        else decoded
    )
    raw_path = raw_path.replace("\\", "/")
    if re.match(r"^/[A-Za-z]:/", raw_path):
        raw_path = raw_path[1:]
    if not raw_path or any(part == ".." for part in PurePosixPath(raw_path).parts):
        return True
    # Absolute artifact paths are supported only when the existing importer
    # can prove they are inside the supplied repository.
    if raw_path.startswith("/") or re.match(r"^[A-Za-z]:/", raw_path):
        candidate = Path(raw_path).resolve(strict=False)
        try:
            candidate.relative_to(repository)
        except ValueError:
            return True
    return False


def _reject_unsafe_locations(document: dict[str, object], repository: Path) -> None:
    runs = document.get("runs")
    if not isinstance(runs, list):
        return
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations")
            if not isinstance(locations, list):
                continue
            for location in locations:
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                if not isinstance(artifact, dict):
                    continue
                if artifact.get("uriBaseId") not in (None, "%SRCROOT%"):
                    raise InputError(
                        "SARIF artifact uriBaseId must be omitted or use %SRCROOT%"
                    )
                if _unsafe_uri(artifact.get("uri"), repository):
                    raise InputError("SARIF artifact location is unsafe")


def _empty_report(
    *,
    path: Path,
    input_sha256: str,
    completeness: str,
    error_codes: list[str],
    identities: set[tuple[str, str, str]] | None = None,
    unknown_metadata: bool = True,
    result_count: int = 0,
    normalized_count: int = 0,
    error_count: int = 0,
) -> dict[str, object]:
    return {
        "path": str(path),
        "sha256": input_sha256,
        "completeness": completeness,
        "error_codes": sorted(set(error_codes)),
        "identities": identities or set(),
        "unknown_metadata": unknown_metadata,
        "result_count": result_count,
        "normalized_count": normalized_count,
        "error_count": error_count,
        "records": [],
    }


def _record_from_finding(
    *,
    finding: dict[str, object],
    item: dict[str, object],
    raw_result: object,
    input_sha256: str,
) -> dict[str, object]:
    source = finding.get("source")
    rule = finding.get("rule")
    locations = finding.get("locations")
    fingerprints = finding.get("fingerprints")
    source = source if isinstance(source, dict) else {}
    rule = rule if isinstance(rule, dict) else {}
    locations = locations if isinstance(locations, list) else []
    fingerprints = fingerprints if isinstance(fingerprints, dict) else {}
    position = item.get("source")
    position = position if isinstance(position, dict) else {}
    run_index = position.get("sarif_run_index")
    result_index = position.get("sarif_result_index")
    return {
        "source_sha256": input_sha256,
        "raw_position": {
            "run_index": run_index if isinstance(run_index, int) and run_index >= 0 else 0,
            "result_index": result_index
            if isinstance(result_index, int) and result_index >= 0
            else 0,
        },
        "tool_name": str(source.get("tool_name") or _UNKNOWN),
        "tool_version": str(source.get("tool_version") or _UNKNOWN),
        "rule_id": str(rule.get("id") or _UNKNOWN),
        "rule_name": str(rule.get("name") or rule.get("id") or _UNKNOWN),
        "locations": locations,
        "raw_locations": _raw_locations(raw_result),
        "fingerprints": {
            str(key): str(value)
            for key, value in fingerprints.items()
            if isinstance(key, str) and isinstance(value, str)
        },
        "error_code": None,
    }


def _record_from_error(
    *,
    item: dict[str, object],
    raw_result: object,
    input_sha256: str,
    document: dict[str, object],
) -> dict[str, object]:
    position = item.get("source")
    position = position if isinstance(position, dict) else {}
    run_index = position.get("sarif_run_index")
    result_index = position.get("sarif_result_index")
    run_index = run_index if isinstance(run_index, int) and run_index >= 0 else 0
    result_index = result_index if isinstance(result_index, int) and result_index >= 0 else 0
    runs = document.get("runs")
    run = runs[run_index] if isinstance(runs, list) and run_index < len(runs) else None
    driver = None
    if isinstance(run, dict) and isinstance(run.get("tool"), dict):
        driver = run["tool"].get("driver")
    tool_name, tool_version = _driver_metadata(driver)
    raw_rule_id = raw_result.get("ruleId") if isinstance(raw_result, dict) else None
    rule_id = raw_rule_id if isinstance(raw_rule_id, str) and raw_rule_id else _UNKNOWN
    return {
        "source_sha256": input_sha256,
        "raw_position": {"run_index": run_index, "result_index": result_index},
        "tool_name": tool_name,
        "tool_version": tool_version,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "locations": [],
        "raw_locations": _raw_locations(raw_result),
        "fingerprints": {},
        "error_code": "NORMALIZATION_ERROR",
    }


def _load_report(path: Path, repository: Path) -> dict[str, object]:
    try:
        input_sha256 = sha256_file(path)
    except OSError as exc:
        raise InputError(f"cannot read SARIF input: {path}") from exc

    try:
        document = load_json(
            path,
            max_bytes=MAX_REPORT_BYTES,
            max_items=MAX_REPORT_ITEMS,
        )
    except (ValueError, OSError) as exc:
        return _empty_report(
            path=path,
            input_sha256=input_sha256,
            completeness="malformed",
            error_codes=["MALFORMED_INPUT"],
        ) | {"detail": str(exc)}

    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        return _empty_report(
            path=path,
            input_sha256=input_sha256,
            completeness="malformed",
            error_codes=["MALFORMED_INPUT"],
        ) | {"detail": "SARIF input must use version 2.1.0"}
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        return _empty_report(
            path=path,
            input_sha256=input_sha256,
            completeness="malformed",
            error_codes=["MALFORMED_INPUT"],
        ) | {"detail": "SARIF input has no runs"}

    identities, unknown_metadata = _report_identities(document)
    failed_invocation = _has_failed_invocation(document)
    _reject_unsafe_locations(document, repository)
    result_count = sum(
        len(run.get("results", []))
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("results", []), list)
    )

    try:
        imported = import_sarif_batch(
            path,
            repository_root=repository,
            max_findings=MAX_COMPARISON_RESULTS,
        )
    except (InputError, UnsupportedError, ValueError, TypeError, OSError) as exc:
        error_codes = ["IMPORT_FAILED"]
        if failed_invocation:
            error_codes.append("INVOCATION_FAILED")
        return _empty_report(
            path=path,
            input_sha256=input_sha256,
            completeness="failed",
            error_codes=error_codes,
            identities=identities,
            unknown_metadata=unknown_metadata,
            result_count=result_count,
        ) | {"detail": str(exc)}

    records: list[dict[str, object]] = []
    normalization_errors = 0
    for item in imported:
        if not isinstance(item, dict):
            normalization_errors += 1
            continue
        source = item.get("source")
        source = source if isinstance(source, dict) else {}
        run_index = source.get("sarif_run_index")
        result_index = source.get("sarif_result_index")
        run_index = run_index if isinstance(run_index, int) and run_index >= 0 else 0
        result_index = result_index if isinstance(result_index, int) and result_index >= 0 else 0
        raw_result = _raw_result(runs, run_index, result_index)
        finding = item.get("finding")
        if isinstance(finding, dict):
            records.append(
                _record_from_finding(
                    finding=finding,
                    item=item,
                    raw_result=raw_result,
                    input_sha256=input_sha256,
                )
            )
        else:
            normalization_errors += 1
            records.append(
                _record_from_error(
                    item=item,
                    raw_result=raw_result,
                    input_sha256=input_sha256,
                    document=document,
                )
            )
    if failed_invocation:
        completeness = "partial" if records else "failed"
    else:
        completeness = "partial" if normalization_errors else ("empty" if not records else "complete")
    error_codes = []
    if failed_invocation:
        error_codes.append("INVOCATION_FAILED")
    if normalization_errors:
        error_codes.append("NORMALIZATION_ERROR")
    return {
        "path": str(path),
        "sha256": input_sha256,
        "completeness": completeness,
        "error_codes": error_codes,
        "identities": identities,
        "unknown_metadata": unknown_metadata,
        "result_count": result_count,
        "normalized_count": len(records) - normalization_errors,
        "error_count": normalization_errors,
        "records": records,
    }


def _stable_fingerprint(record: dict[str, object]) -> tuple[tuple[str, str], ...] | None:
    fingerprints = record.get("fingerprints")
    if not isinstance(fingerprints, dict) or not fingerprints:
        return None
    pairs: list[tuple[str, str]] = []
    for key, value in fingerprints.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or not value:
            return None
        pairs.append((key, value))
    return tuple(sorted(pairs)) or None


def _canonical_locations(record: dict[str, object]) -> tuple[tuple[object, ...], ...] | None:
    locations = record.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    canonical: list[tuple[object, ...]] = []
    for location in locations:
        if not isinstance(location, dict):
            return None
        path = location.get("path")
        region = location.get("region")
        if not isinstance(path, str) or not isinstance(region, dict):
            return None
        values = tuple(
            region.get(key)
            for key in ("start_line", "start_column", "end_line", "end_column")
        )
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            return None
        canonical.append((path, *values))
    return tuple(sorted(canonical))


def _paths(record: dict[str, object]) -> set[str]:
    locations = record.get("locations")
    if not isinstance(locations, list):
        return set()
    return {
        str(item.get("path"))
        for item in locations
        if isinstance(item, dict) and item.get("path")
    }


def _record_identity_key(record: dict[str, object]) -> tuple[str, str, str] | None:
    values = (record.get("tool_name"), record.get("tool_version"), record.get("rule_id"))
    if not all(_known(value) for value in values):
        return None
    return str(values[0]), str(values[1]), str(values[2])


def _identity(
    record: dict[str, object] | None,
    *,
    method: str,
    value: object | None = None,
) -> dict[str, object] | None:
    if record is None:
        return None
    return {
        "tool_name": str(record.get("tool_name") or _UNKNOWN),
        "tool_version": str(record.get("tool_version") or _UNKNOWN),
        "rule_id": str(record.get("rule_id") or _UNKNOWN),
        "method": method,
        "value": value,
    }


def _evidence(record: dict[str, object] | None) -> dict[str, object] | None:
    if record is None:
        return None
    return {
        "input_sha256": str(record["source_sha256"]),
        "tool": {
            "name": str(record.get("tool_name") or _UNKNOWN),
            "version": str(record.get("tool_version") or _UNKNOWN),
        },
        "rule": {
            "id": str(record.get("rule_id") or _UNKNOWN),
            "name": str(record.get("rule_name") or _UNKNOWN),
        },
        "locations": record.get("locations") if isinstance(record.get("locations"), list) else [],
        "raw_locations": (
            record.get("raw_locations") if isinstance(record.get("raw_locations"), list) else []
        ),
        "fingerprints": (
            record.get("fingerprints") if isinstance(record.get("fingerprints"), dict) else {}
        ),
        "raw_position": record.get("raw_position")
        if isinstance(record.get("raw_position"), dict)
        else {"run_index": 0, "result_index": 0},
    }


def _item(
    *,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
    method: str,
    value: object | None,
    match_basis: str | None,
    reason_code: str,
) -> dict[str, object]:
    identity_record = before or after
    return {
        "identity": _identity(identity_record, method=method, value=value),
        "match_basis": match_basis,
        "reason_code": reason_code,
        "before": _evidence(before),
        "after": _evidence(after),
    }


def _record_sort_key(record: dict[str, object]) -> tuple[object, ...]:
    position = record.get("raw_position")
    position = position if isinstance(position, dict) else {}
    return (
        str(record.get("tool_name") or _UNKNOWN),
        str(record.get("tool_version") or _UNKNOWN),
        str(record.get("rule_id") or _UNKNOWN),
        canonical_json_bytes(record.get("locations", [])),
        canonical_json_bytes(record.get("fingerprints", {})),
        int(position.get("run_index", 0)),
        int(position.get("result_index", 0)),
    )


def _category_sort_key(item: dict[str, object]) -> tuple[object, ...]:
    identity = item.get("identity")
    identity_bytes = canonical_json_bytes(identity) if identity is not None else b""
    before = item.get("before")
    after = item.get("after")
    before_position = before.get("raw_position", {}) if isinstance(before, dict) else {}
    after_position = after.get("raw_position", {}) if isinstance(after, dict) else {}
    return (
        identity_bytes,
        str(item.get("reason_code") or ""),
        int(before_position.get("run_index", 0)),
        int(before_position.get("result_index", 0)),
        int(after_position.get("run_index", 0)),
        int(after_position.get("result_index", 0)),
    )


def _compare_group(
    before: list[dict[str, object]],
    after: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    categories: dict[str, list[dict[str, object]]] = {
        "new_in_report": [],
        "absent_from_report": [],
        "unchanged": [],
        "ambiguous": [],
    }
    before = sorted(before, key=_record_sort_key)
    after = sorted(after, key=_record_sort_key)
    ambiguous: dict[int, set[str]] = defaultdict(set)
    matched: set[int] = set()

    def mark(record: dict[str, object], reason: str) -> None:
        ambiguous[id(record)].add(reason)

    def reason_for(record: dict[str, object]) -> str:
        reasons = ambiguous.get(id(record), {"IDENTITY_INSUFFICIENT"})
        return min(reasons, key=lambda reason: (_REASON_PRIORITY.get(reason, 100), reason))

    def fp_map(
        records: list[dict[str, object]],
    ) -> dict[tuple[tuple[str, str], ...], list[dict[str, object]]]:
        result: dict[tuple[tuple[str, str], ...], list[dict[str, object]]] = defaultdict(list)
        for record in records:
            fingerprint = _stable_fingerprint(record)
            if fingerprint is not None:
                result[fingerprint].append(record)
        return result

    before_fp = fp_map(before)
    after_fp = fp_map(after)
    duplicate_fingerprints: set[tuple[tuple[str, str], ...]] = set()
    for mapping in (before_fp, after_fp):
        for fingerprint, records in mapping.items():
            if len(records) > 1:
                duplicate_fingerprints.add(fingerprint)
                for record in records:
                    mark(record, "DUPLICATE_FINGERPRINT")
    for fingerprint in duplicate_fingerprints:
        for record in [*before_fp.get(fingerprint, []), *after_fp.get(fingerprint, [])]:
            mark(record, "DUPLICATE_FINGERPRINT")

    # A different fingerprint at the same tool/rule/path is explicitly
    # ambiguous.  It may be a moved finding, a conflicting producer result, or
    # a duplicate that cannot be safely distinguished.
    by_path: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in [*before, *after]:
        for path in _paths(record):
            by_path[path].append(record)
    for records in by_path.values():
        fingerprints = {
            fingerprint
            for record in records
            if (fingerprint := _stable_fingerprint(record)) is not None
        }
        if len(fingerprints) > 1:
            for record in records:
                mark(record, "CONFLICTING_FINGERPRINT")

    def location_map(
        records: list[dict[str, object]],
    ) -> dict[tuple[tuple[object, ...], ...], list[dict[str, object]]]:
        result: dict[tuple[tuple[object, ...], ...], list[dict[str, object]]] = defaultdict(list)
        for record in records:
            location = _canonical_locations(record)
            if location is not None:
                result[location].append(record)
        return result

    before_locations = location_map(before)
    after_locations = location_map(after)
    duplicate_locations: set[tuple[tuple[object, ...], ...]] = set()
    for mapping in (before_locations, after_locations):
        for location, records in mapping.items():
            if len(records) > 1:
                duplicate_locations.add(location)
                for record in records:
                    mark(record, "DUPLICATE_LOCATION")
    for location in duplicate_locations:
        for record in [*before_locations.get(location, []), *after_locations.get(location, [])]:
            mark(record, "DUPLICATE_LOCATION")

    # Stable fingerprints are the first matching method.
    for fingerprint in sorted(set(before_fp) & set(after_fp)):
        left = [record for record in before_fp[fingerprint] if not ambiguous.get(id(record))]
        right = [record for record in after_fp[fingerprint] if not ambiguous.get(id(record))]
        if len(left) == 1 and len(right) == 1:
            left_record, right_record = left[0], right[0]
            matched.update((id(left_record), id(right_record)))
            categories["unchanged"].append(
                _item(
                    before=left_record,
                    after=right_record,
                    method="stable_fingerprint",
                    value={key: value for key, value in fingerprint},
                    match_basis="stable_fingerprint",
                    reason_code="MATCHED_STABLE_FINGERPRINT",
                )
            )

    # Exact canonical path+region is the only fallback.  Records with a
    # conflicting fingerprint were marked above and cannot reach this path.
    for location in sorted(set(before_locations) & set(after_locations), key=repr):
        left = [
            record
            for record in before_locations[location]
            if id(record) not in matched and not ambiguous.get(id(record))
        ]
        right = [
            record
            for record in after_locations[location]
            if id(record) not in matched and not ambiguous.get(id(record))
        ]
        if len(left) == 1 and len(right) == 1:
            left_record, right_record = left[0], right[0]
            matched.update((id(left_record), id(right_record)))
            categories["unchanged"].append(
                _item(
                    before=left_record,
                    after=right_record,
                    method="canonical_path_region",
                    value=[
                        {
                            "path": item[0],
                            "region": {
                                "start_line": item[1],
                                "start_column": item[2],
                                "end_line": item[3],
                                "end_column": item[4],
                            },
                        }
                        for item in location
                    ],
                    match_basis="canonical_path_region",
                    reason_code="MATCHED_CANONICAL_PATH_REGION",
                )
            )

    unmatched_before = [record for record in before if id(record) not in matched]
    unmatched_after = [record for record in after if id(record) not in matched]

    # A line/column shift on the same path is never treated as an add/remove.
    before_paths = {path for record in unmatched_before for path in _paths(record)}
    after_paths = {path for record in unmatched_after for path in _paths(record)}
    shifted_paths = before_paths & after_paths
    for record in unmatched_before:
        if _paths(record) & shifted_paths:
            mark(record, "SHIFTED_LOCATION")
    for record in unmatched_after:
        if _paths(record) & shifted_paths:
            mark(record, "SHIFTED_LOCATION")

    for record in before:
        if id(record) in matched:
            continue
        if ambiguous.get(id(record)) or _canonical_locations(record) is None:
            categories["ambiguous"].append(
                _item(
                    before=record,
                    after=None,
                    method="insufficient",
                    value=None,
                    match_basis=None,
                    reason_code=reason_for(record),
                )
            )
        else:
            categories["absent_from_report"].append(
                _item(
                    before=record,
                    after=None,
                    method="canonical_path_region",
                    value=[
                        {
                            "path": item[0],
                            "region": {
                                "start_line": item[1],
                                "start_column": item[2],
                                "end_line": item[3],
                                "end_column": item[4],
                            },
                        }
                        for item in (_canonical_locations(record) or ())
                    ],
                    match_basis=None,
                    reason_code="ONLY_IN_BEFORE",
                )
            )
    for record in after:
        if id(record) in matched:
            continue
        if ambiguous.get(id(record)) or _canonical_locations(record) is None:
            categories["ambiguous"].append(
                _item(
                    before=None,
                    after=record,
                    method="insufficient",
                    value=None,
                    match_basis=None,
                    reason_code=reason_for(record),
                )
            )
        else:
            categories["new_in_report"].append(
                _item(
                    before=None,
                    after=record,
                    method="canonical_path_region",
                    value=[
                        {
                            "path": item[0],
                            "region": {
                                "start_line": item[1],
                                "start_column": item[2],
                                "end_line": item[3],
                                "end_column": item[4],
                            },
                        }
                        for item in (_canonical_locations(record) or ())
                    ],
                    match_basis=None,
                    reason_code="ONLY_IN_AFTER",
                )
            )
    return categories


def _report_item(
    *,
    reason_code: str,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
) -> dict[str, object]:
    return _item(
        before=before,
        after=after,
        method="insufficient",
        value=None,
        match_basis=None,
        reason_code=reason_code,
    )


def _compatibility(
    before: dict[str, object],
    after: dict[str, object],
) -> dict[str, object]:
    before_ids = set(before.get("identities", set()))
    after_ids = set(after.get("identities", set()))
    common = before_ids & after_ids
    unknown = bool(before.get("unknown_metadata")) or bool(after.get("unknown_metadata"))
    if common and (before_ids - common or after_ids - common or unknown):
        status = "partial"
    elif common:
        status = "compatible"
    elif unknown or not before_ids or not after_ids:
        status = "unknown"
    else:
        status = "incompatible"
    return {
        "status": status,
        "before_identities": [
            {"tool_name": item[0], "tool_version": item[1], "rule_id": item[2]}
            for item in sorted(before_ids)
        ],
        "after_identities": [
            {"tool_name": item[0], "tool_version": item[1], "rule_id": item[2]}
            for item in sorted(after_ids)
        ],
        "compatible_identities": [
            {"tool_name": item[0], "tool_version": item[1], "rule_id": item[2]}
            for item in sorted(common)
        ],
    }


def _input_summary(report: dict[str, object]) -> dict[str, object]:
    return {
        "path": str(report.get("path", "")),
        "sha256": str(report.get("sha256", "")),
        "completeness": str(report.get("completeness", "failed")),
        "result_count": int(report.get("result_count", 0)),
        "normalized_count": int(report.get("normalized_count", 0)),
        "error_count": int(report.get("error_count", 0)),
        "error_codes": sorted(str(item) for item in report.get("error_codes", [])),
    }


def _sort_categories(categories: dict[str, list[dict[str, object]]]) -> None:
    for values in categories.values():
        values.sort(key=_category_sort_key)


def _build_comparison(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    categories: dict[str, list[dict[str, object]]] = {
        "new_in_report": [],
        "absent_from_report": [],
        "unchanged": [],
        "ambiguous": [],
    }
    compatibility = _compatibility(before, after)
    before_records = [item for item in before.get("records", []) if isinstance(item, dict)]
    after_records = [item for item in after.get("records", []) if isinstance(item, dict)]
    before_complete = before.get("completeness") in {"complete", "empty"}
    after_complete = after.get("completeness") in {"complete", "empty"}

    if not before_complete or not after_complete:
        reason = (
            "INPUT_PARTIAL"
            if "partial" in (before.get("completeness"), after.get("completeness"))
            else "INPUT_FAILED"
        )
        for record in before_records:
            categories["ambiguous"].append(
                _report_item(
                    reason_code=str(record.get("error_code") or reason),
                    before=record,
                )
            )
        for record in after_records:
            categories["ambiguous"].append(
                _report_item(
                    reason_code=str(record.get("error_code") or reason),
                    after=record,
                )
            )
        if not before_records and before.get("completeness") not in {"complete", "empty"}:
            categories["ambiguous"].append(
                _report_item(
                    reason_code=(
                        "MALFORMED_INPUT"
                        if before.get("completeness") == "malformed"
                        else "INPUT_FAILED"
                    )
                )
            )
        if not after_records and after.get("completeness") not in {"complete", "empty"}:
            categories["ambiguous"].append(
                _report_item(
                    reason_code=(
                        "MALFORMED_INPUT"
                        if after.get("completeness") == "malformed"
                        else "INPUT_FAILED"
                    )
                )
            )
    elif compatibility["status"] in {"compatible", "partial"}:
        common = {
            (item["tool_name"], item["tool_version"], item["rule_id"])
            for item in compatibility["compatible_identities"]
            if isinstance(item, dict)
        }
        before_groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
        after_groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
        for record in before_records:
            key = _record_identity_key(record)
            if key is None:
                categories["ambiguous"].append(
                    _report_item(reason_code="IDENTITY_INSUFFICIENT", before=record)
                )
            elif key in common:
                before_groups[key].append(record)
            else:
                categories["ambiguous"].append(
                    _report_item(reason_code="TOOL_INCOMPATIBLE", before=record)
                )
        for record in after_records:
            key = _record_identity_key(record)
            if key is None:
                categories["ambiguous"].append(
                    _report_item(reason_code="IDENTITY_INSUFFICIENT", after=record)
                )
            elif key in common:
                after_groups[key].append(record)
            else:
                categories["ambiguous"].append(
                    _report_item(reason_code="TOOL_INCOMPATIBLE", after=record)
                )
        for key in sorted(common):
            group = _compare_group(before_groups.get(key, []), after_groups.get(key, []))
            for category, values in group.items():
                categories[category].extend(values)
        if not before_records and not after_records and (
            before.get("unknown_metadata") or after.get("unknown_metadata")
        ):
            categories["ambiguous"].append(
                _report_item(reason_code="INPUT_EMPTY_IDENTITY_UNKNOWN")
            )
        elif before.get("unknown_metadata") or after.get("unknown_metadata"):
            categories["ambiguous"].append(
                _report_item(reason_code="IDENTITY_INSUFFICIENT")
            )
    else:
        reason = (
            "TOOL_INCOMPATIBLE"
            if compatibility["status"] == "incompatible"
            else "IDENTITY_INSUFFICIENT"
        )
        for record in before_records:
            categories["ambiguous"].append(_report_item(reason_code=reason, before=record))
        for record in after_records:
            categories["ambiguous"].append(_report_item(reason_code=reason, after=record))
        if not before_records and not after_records:
            categories["ambiguous"].append(_report_item(reason_code="INPUT_EMPTY_IDENTITY_UNKNOWN"))

    _sort_categories(categories)
    comparison_status = (
        "COMPLETE"
        if compatibility["status"] == "compatible"
        and before_complete
        and after_complete
        and not categories["ambiguous"]
        else "INCONCLUSIVE"
    )
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "comparison_status": comparison_status,
        "compatibility": compatibility,
        "input_completeness": {
            "before": str(before.get("completeness", "failed")),
            "after": str(after.get("completeness", "failed")),
        },
        "inputs": {"before": _input_summary(before), "after": _input_summary(after)},
        "matching_policy": {
            "methods_in_order": ["stable_fingerprint", "canonical_path_region"],
            "identity_excludes": [
                "whole_input_sha256",
                "sarif_run_index",
                "sarif_result_index",
                "rank",
            ],
            "fuzzy_matching": False,
            "code_matching": False,
            "history_matching": False,
        },
        "categories": categories,
        "summary": {
            "new_in_report": len(categories["new_in_report"]),
            "absent_from_report": len(categories["absent_from_report"]),
            "unchanged": len(categories["unchanged"]),
            "ambiguous": len(categories["ambiguous"]),
        },
    }


def compare_sarif(
    before: Path,
    after: Path,
    repository: Path,
    output: Path | None = None,
) -> dict[str, object]:
    """Compare two local SARIF reports and optionally write a fresh artifact."""

    _safe_report_file(before, "before SARIF input")
    _safe_report_file(after, "after SARIF input")
    repository_root = _safe_repository(repository)
    if output is not None:
        _safe_output(output)
    before_report = _load_report(before, repository_root)
    after_report = _load_report(after, repository_root)
    result = _build_comparison(before_report, after_report)
    if output is not None:
        dump_json(output, result)
    return result

