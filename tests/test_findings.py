# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from lumi_trace.errors import InputError, UnsupportedError
from lumi_trace.findings import import_manual, import_sarif, validate_normalized_finding


def test_manual_import_is_deterministic(
    manual_finding_path: Path, fixture_repository: Path
) -> None:
    first = import_manual(manual_finding_path, fixture_repository)
    second = import_manual(manual_finding_path, fixture_repository)
    assert first == second
    assert first["schema_version"] == "normalized-finding-v1"
    assert first["finding_id"] == "manual:TRACE-FIXTURE-001"
    assert first["rule"]["cwes"] == ["CWE-22"]
    assert first["locations"][0]["path"] == "src/archive.sh"
    validate_normalized_finding(first)


def test_sarif_import_preserves_rule_location_and_provenance(
    sarif_finding_path: Path, fixture_repository: Path
) -> None:
    findings = import_sarif(sarif_finding_path, repository_root=fixture_repository)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_id"].startswith("sarif:")
    assert finding["source"]["tool_name"] == "Skylark Fixture Analyzer"
    assert finding["severity"]["normalized"] == "HIGH"
    assert finding["rule"]["cwes"] == ["CWE-22"]
    assert finding["locations"][0]["symbol"] == "unsafe_join"


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.invalid/a.py",
        "ftp://example.invalid/a.py",
        "s3://bucket/a.py",
        "custom+transport://example.invalid/a.py",
        "file://remote-host/share/a.py",
    ],
)
def test_sarif_remote_location_is_rejected(tmp_path: Path, uri: str) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fixture"}},
                "results": [
                    {
                        "ruleId": "X",
                        "message": {"text": "remote"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "remote.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    with pytest.raises(UnsupportedError):
        import_sarif(path)


def test_sarif_percent_decoded_nul_location_is_rejected(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fixture"}},
                "results": [
                    {
                        "ruleId": "X",
                        "message": {"text": "nul"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "src/%00module.py"}}}
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "nul.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    with pytest.raises(InputError, match="NUL"):
        import_sarif(path)


def test_sarif_ambiguous_uri_base_is_rejected(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fixture"}},
                "results": [
                    {
                        "ruleId": "X",
                        "message": {"text": "ambiguous base"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/module.py",
                                        "uriBaseId": "UNRESOLVED_BASE",
                                    }
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "ambiguous-base.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    with pytest.raises(UnsupportedError, match="%SRCROOT%"):
        import_sarif(path)


@pytest.mark.parametrize(
    "mapped_uri",
    ["https://example.invalid/source/", "file:///private/source/", "../other/"],
)
def test_sarif_conflicting_srcroot_mapping_is_rejected(
    tmp_path: Path,
    mapped_uri: str,
) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fixture"}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": mapped_uri}},
                "results": [
                    {
                        "ruleId": "X",
                        "message": {"text": "conflicting source root"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/module.py",
                                        "uriBaseId": "%SRCROOT%",
                                    }
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "conflicting-srcroot.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    with pytest.raises(UnsupportedError, match="canonical local mapping"):
        import_sarif(path)


def test_manual_unknown_fields_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "finding.json"
    path.write_text('{"title":"x","execute_this":"no"}', encoding="utf-8")
    with pytest.raises(InputError, match="unknown manual finding fields"):
        import_manual(path)


def test_manual_unknown_location_fields_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "finding.json"
    path.write_text(
        json.dumps(
            {
                "title": "x",
                "locations": [{"path": "source.py", "execute_this": "no"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(InputError, match="unknown manual location fields"):
        import_manual(path)


def test_loaded_normalized_finding_enforces_full_v1_shape(
    manual_finding_path: Path, fixture_repository: Path
) -> None:
    finding = import_manual(manual_finding_path, fixture_repository)

    unknown = deepcopy(finding)
    unknown["execute_this"] = "no"
    with pytest.raises(InputError, match="unknown fields"):
        validate_normalized_finding(unknown)

    unsafe_path = deepcopy(finding)
    unsafe_path["locations"][0]["path"] = "../outside.py"
    with pytest.raises(InputError, match="safe repository-relative path"):
        validate_normalized_finding(unsafe_path)

    invalid_region = deepcopy(finding)
    invalid_region["locations"][0]["region"]["start_line"] = True
    with pytest.raises(InputError, match="region is invalid"):
        validate_normalized_finding(invalid_region)

    invalid_source = deepcopy(finding)
    invalid_source["source"]["tool_name"] = "not-manual"
    with pytest.raises(InputError, match="manual source"):
        validate_normalized_finding(invalid_source)
