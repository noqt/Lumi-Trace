# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.dependency_inventory import (
    DependencyInventoryError,
    _spdx_expression,
    collect_dependency_inventory,
    render_inventory,
)


def test_resolved_dependency_inventory_is_sanitized(project_root: Path) -> None:
    inventory = collect_dependency_inventory(project_root)
    assert inventory["schema_version"] == "resolved-dependency-inventory-v1"
    assert inventory["runtime_dependency_count"] == 0

    dependencies = inventory["dependencies"]
    direct = {item["name"] for item in dependencies if item["relationship"] == "direct"}
    assert {"packaging", "pip", "setuptools"}.issubset(direct)
    for item in dependencies:
        assert set(item) == {"licence", "name", "relationship", "version"}
        assert item["relationship"] in {"direct", "transitive"}

    rendered = render_inventory(inventory)
    assert "://" not in rendered
    assert "\\" not in rendered
    assert str(project_root) not in rendered

    schema = json.loads(
        (project_root / "schemas" / "resolved-dependency-inventory-v1.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(inventory)


def test_mit_zero_is_an_approved_spdx_atom() -> None:
    assert _spdx_expression("MIT-0") == "MIT-0"


@pytest.mark.parametrize("unsafe_value", ["https://packages.invalid/item", "C:\\host\\item"])
def test_inventory_render_rejects_url_and_path_material(unsafe_value: str) -> None:
    with pytest.raises(DependencyInventoryError, match="prohibited URL or path material"):
        render_inventory({"unsafe": unsafe_value})
