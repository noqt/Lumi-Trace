# SPDX-License-Identifier: Apache-2.0
"""Owned adversarial tests for the V0.5 deterministic precision candidate."""

from __future__ import annotations

from copy import deepcopy

from lumi_trace.localization import _candidate, _query, _rank


def _finding() -> dict[str, object]:
    return {
        "rule": {"id": "path-validation", "name": "path validation", "cwes": [], "tags": []},
        "message": {
            "title": "Path validation bypass",
            "text": "Validate an archive path before extraction.",
        },
        "keywords": [],
        "locations": [],
    }


def test_v05_demotes_an_explicit_test_role_decoy_that_v04_ranks_first() -> None:
    finding = _finding()
    query = _query(finding)
    implementation = _candidate(
        path="src/archive.py",
        source="def validate(path):\n    return path is not None\n",
        symbol={"qualified_name": "validate", "start_line": 1, "end_line": 2},
        query=query,
    )
    test_decoy = _candidate(
        path="tests/test_archive_path.py",
        source=(
            "def validate_archive_path(path):\n"
            "    # archive path validation bypass extraction\n"
            "    return path\n"
        ),
        symbol={
            "qualified_name": "validate_archive_path",
            "start_line": 3,
            "end_line": 4,
        },
        query=query,
    )

    v04 = _rank(
        [test_decoy, implementation],
        finding,
        algorithm="role-aware-sparse-v0.4.1.3",
    )
    v05 = _rank(
        [test_decoy, implementation],
        finding,
        algorithm="role-aware-sparse-v0.5.0.2",
    )

    assert v04[0]["path"] == "tests/test_archive_path.py"
    assert v05[0]["path"] == "src/archive.py"
    assert v05[1]["score_components"]["ROLE_PRECISION"] < 0


def test_v05_records_scale_aware_role_demotion_as_an_explainable_component() -> None:
    finding = _finding()
    candidate = _candidate(
        path="tests/validation_support.py",
        source="def validate_archive_path(path):\n    return path\n",
        symbol=None,
        query=_query(finding),
    )

    ranked = _rank([candidate], finding, algorithm="role-aware-sparse-v0.5.0.2")

    assert ranked[0]["role"] == "test"
    components = ranked[0]["score_components"]
    subtotal = ranked[0]["integer_score"] - components["ROLE_PRECISION"]
    assert components["ROLE_PRECISION"] == -(subtotal // 2)


def test_v05_reported_test_target_is_exempt_from_role_precision_demotion() -> None:
    finding = deepcopy(_finding())
    finding["locations"] = [{"path": "tests/test_plugin.py", "symbol": "validate_archive_path"}]
    query = _query(finding)
    plugin_target = _candidate(
        path="tests/test_plugin.py",
        source="def validate_archive_path(path):\n    return path\n",
        symbol={
            "qualified_name": "validate_archive_path",
            "start_line": 3,
            "end_line": 4,
        },
        query=query,
    )
    decoy = _candidate(
        path="src/archive_validation.py",
        source="def validate_archive_path(path):\n    return path\n",
        symbol=None,
        query=query,
    )

    ranked = _rank([decoy, plugin_target], finding, algorithm="role-aware-sparse-v0.5.0.2")

    assert ranked[0]["path"] == "tests/test_plugin.py"
    assert ranked[0]["score_components"]["ROLE_PRECISION"] == 0


def test_v05_strong_unreported_test_target_can_override_role_precision() -> None:
    finding = _finding()
    query = _query(finding)
    genuine_test_target = _candidate(
        path="tests/test_archive_path.py",
        source=(
            "def validate_archive_path(path):\n"
            "    # archive path validation bypass extraction\n"
            "    return path\n"
        ),
        symbol={
            "qualified_name": "validate_archive_path",
            "start_line": 1,
            "end_line": 3,
        },
        query=query,
    )
    weak_implementation_decoy = _candidate(
        path="src/guard.py",
        source="def validate(value):\n    return value is not None\n",
        symbol={"qualified_name": "validate", "start_line": 1, "end_line": 2},
        query=query,
    )

    ranked = _rank(
        [genuine_test_target, weak_implementation_decoy],
        finding,
        algorithm="role-aware-sparse-v0.5.0.2",
    )

    assert finding["locations"] == []
    assert ranked[0]["path"] == "tests/test_archive_path.py"
    assert ranked[0]["score_components"]["ROLE_PRECISION"] < 0


def test_v05_does_not_demote_implementation_source_that_imports_pytest() -> None:
    finding = _finding()
    candidate = _candidate(
        path="src/plugin.py",
        source="import pytest\n\ndef pytest_configure(config):\n    return config\n",
        symbol={"qualified_name": "pytest_configure", "start_line": 3, "end_line": 4},
        query=_query(finding),
    )

    ranked = _rank([candidate], finding, algorithm="role-aware-sparse-v0.5.0.2")

    assert ranked[0]["score_components"]["ROLE_PRECISION"] == 0


def test_v05_does_not_demote_a_production_test_named_api() -> None:
    finding = _finding()
    candidate = _candidate(
        path="src/health.py",
        source="def test_connection(path):\n    return path is not None\n",
        symbol={"qualified_name": "test_connection", "start_line": 1, "end_line": 2},
        query=_query(finding),
    )

    ranked = _rank([candidate], finding, algorithm="role-aware-sparse-v0.5.0.2")

    assert ranked[0]["score_components"]["ROLE_PRECISION"] == 0


def test_v05_does_not_change_v04_score_component_or_replay_contract() -> None:
    finding = _finding()
    candidate = _candidate(
        path="src/validation.py",
        source="import pytest\n\ndef validate_archive_path(path):\n    return path\n",
        symbol=None,
        query=_query(finding),
    )

    ranked = _rank([candidate], finding, algorithm="role-aware-sparse-v0.4.1.3")

    assert "ROLE_PRECISION" not in ranked[0]["score_components"]
