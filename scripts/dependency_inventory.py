# SPDX-License-Identifier: Apache-2.0
"""Build a sanitized, offline inventory of the resolved tool dependency closure."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import deque
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_REQUIREMENTS = ("pip==26.1.2",)

_SAFE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
_SAFE_LICENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .+()_;-]*$")
_SPDX_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")

_LICENCE_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd": "BSD-version-unspecified",
    "bsd license": "BSD-version-unspecified",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc": "ISC",
    "mit": "MIT",
    "mpl-2.0": "MPL-2.0",
    "psf-2.0": "PSF-2.0",
    "psfl": "PSF-2.0",
}
_CLASSIFIER_LICENCES = {
    "License :: Public Domain": "Public-Domain",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-version-unspecified",
    "License :: OSI Approved :: GNU General Public License (GPL)": "GPL-version-unspecified",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}
_ALLOWED_SPDX_ATOMS = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "MIT",
    "MPL-2.0",
    "PSF-2.0",
    "Unlicense",
}
_EXPRESSION_OPERATORS = {"AND", "OR", "WITH"}
_INCOMPATIBLE_FRAGMENTS = (
    "AGPL",
    "BUSL",
    "COMMONS-CLAUSE",
    "PROPRIETARY",
    "SSPL",
)


class DependencyInventoryError(RuntimeError):
    """Raised when the installed dependency closure cannot be safely inventoried."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = tuple(sorted(set(problems)))
        super().__init__("; ".join(self.problems))


def canonical_name(value: str) -> str:
    """Return the normalized distribution name without preserving unsafe metadata."""

    normalized = re.sub(r"[-_.]+", "-", value).casefold()
    if len(normalized) > 200 or not _SAFE_NAME.fullmatch(normalized):
        raise ValueError("distribution name is not safe for the public inventory")
    return normalized


def declared_requirement_strings(document: dict[str, Any]) -> list[str]:
    """Return runtime, build, development, and bootstrap requirements."""

    project = document.get("project", {})
    declared = list(project.get("dependencies", []))
    declared.extend(document.get("build-system", {}).get("requires", []))
    for requirements in project.get("optional-dependencies", {}).values():
        declared.extend(requirements)
    declared.extend(BOOTSTRAP_REQUIREMENTS)
    return declared


def _parse_requirement(raw: str, *, source_name: str, problems: list[str]) -> Requirement | None:
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        problems.append(f"invalid dependency requirement declared by {source_name}")
        return None
    if requirement.url is not None:
        problems.append(f"direct URL dependency declared by {source_name}")
        return None
    return requirement


def _requirement_applies(requirement: Requirement, extras: set[str]) -> bool:
    if requirement.marker is None:
        return True
    environment = default_environment()
    return any(
        requirement.marker.evaluate({**environment, "extra": extra}) for extra in (extras or {""})
    )


def _installed_distributions() -> tuple[dict[str, metadata.Distribution], set[str], list[str]]:
    installed: dict[str, metadata.Distribution] = {}
    duplicates: set[str] = set()
    problems: list[str] = []
    for distribution in metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        try:
            name = canonical_name(raw_name)
        except ValueError:
            problems.append("installed distribution has an unsafe or missing name")
            continue
        if name in installed:
            duplicates.add(name)
            continue
        installed[name] = distribution
    return installed, duplicates, problems


def _spdx_expression(value: str) -> str | None:
    expression = " ".join(value.split())
    if not expression or len(expression) > 256 or not _SAFE_LICENCE.fullmatch(expression):
        return None
    for token in _SPDX_TOKEN.findall(expression):
        if token in _EXPRESSION_OPERATORS:
            continue
        if token not in _ALLOWED_SPDX_ATOMS:
            return None
    return expression


def _licence_for(distribution: metadata.Distribution) -> str | None:
    expression = distribution.metadata.get("License-Expression")
    if expression:
        normalized = _spdx_expression(expression)
        if normalized is not None:
            return normalized

    raw_licence = " ".join((distribution.metadata.get("License") or "").split())
    alias = _LICENCE_ALIASES.get(raw_licence.casefold())
    if alias is not None:
        return alias

    classifiers = distribution.metadata.get_all("Classifier") or []
    declared: list[str] = []
    unknown_classifier = False
    for classifier in classifiers:
        if not classifier.startswith("License ::"):
            continue
        mapped = _CLASSIFIER_LICENCES.get(classifier)
        if mapped is None:
            unknown_classifier = True
        else:
            declared.append(mapped)
    if unknown_classifier or not declared:
        return None
    return "; ".join(sorted(set(declared)))


def _licence_is_compatible(value: str) -> bool:
    upper = value.upper()
    return not any(fragment in upper for fragment in _INCOMPATIBLE_FRAGMENTS)


def collect_dependency_inventory(project_root: Path = ROOT) -> dict[str, Any]:
    """Resolve the active installed closure without contacting a package index."""

    document = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    installed, duplicate_names, problems = _installed_distributions()
    project = document.get("project", {})
    runtime_dependencies = project.get("dependencies")
    if runtime_dependencies != []:
        problems.append("project runtime dependency contract is not empty")
    direct_names: set[str] = set()
    constraints: dict[str, list[Requirement]] = {}
    requested_extras: dict[str, set[str]] = {}
    pending: deque[str] = deque()

    def add_requirement(requirement: Requirement, *, direct: bool) -> None:
        if not _requirement_applies(requirement, set()):
            return
        try:
            name = canonical_name(requirement.name)
        except ValueError:
            problems.append("dependency requirement has an unsafe name")
            return
        if direct:
            direct_names.add(name)
        constraints.setdefault(name, []).append(requirement)
        known_extras = requested_extras.setdefault(name, set())
        new_extras = {extra.casefold() for extra in requirement.extras} - known_extras
        known_extras.update(new_extras)
        pending.append(name)

    for raw in declared_requirement_strings(document):
        if not isinstance(raw, str):
            problems.append("project dependency declaration is not a string")
            continue
        requirement = _parse_requirement(raw, source_name="the project", problems=problems)
        if requirement is not None:
            add_requirement(requirement, direct=True)

    processed_extras: dict[str, frozenset[str]] = {}
    while pending:
        name = pending.popleft()
        extras = frozenset(requested_extras.get(name, set()))
        if processed_extras.get(name) == extras:
            continue
        processed_extras[name] = extras
        distribution = installed.get(name)
        if distribution is None:
            problems.append(f"required distribution is not installed: {name}")
            continue
        for raw in distribution.metadata.get_all("Requires-Dist") or []:
            requirement = _parse_requirement(raw, source_name=name, problems=problems)
            if requirement is None or not _requirement_applies(requirement, set(extras)):
                continue
            try:
                child_name = canonical_name(requirement.name)
            except ValueError:
                problems.append(f"dependency declared by {name} has an unsafe name")
                continue
            constraints.setdefault(child_name, []).append(requirement)
            child_extras = requested_extras.setdefault(child_name, set())
            next_extras = {extra.casefold() for extra in requirement.extras}
            if child_name not in processed_extras or not next_extras.issubset(child_extras):
                child_extras.update(next_extras)
                pending.append(child_name)

    dependencies: list[dict[str, str]] = []
    for name in sorted(constraints):
        if name in duplicate_names:
            problems.append(f"multiple installed distributions resolve to {name}")
            continue
        distribution = installed.get(name)
        if distribution is None:
            continue
        try:
            installed_version = Version(distribution.version)
        except InvalidVersion:
            problems.append(f"installed distribution has an invalid version: {name}")
            continue
        version = str(installed_version)
        if len(version) > 200 or not _SAFE_VERSION.fullmatch(version):
            problems.append(f"installed distribution has an unsafe version: {name}")
            continue
        for requirement in constraints[name]:
            if requirement.specifier and installed_version not in requirement.specifier:
                problems.append(f"installed version does not satisfy a requirement: {name}")
        licence = _licence_for(distribution)
        if licence is None:
            problems.append(f"dependency licence metadata is unknown or ambiguous: {name}")
            continue
        if not _SAFE_LICENCE.fullmatch(licence):
            problems.append(f"dependency licence metadata is unsafe: {name}")
            continue
        if not _licence_is_compatible(licence):
            problems.append(
                f"dependency licence is outside the approved external-tool policy: {name}"
            )
            continue
        dependencies.append(
            {
                "licence": licence,
                "name": name,
                "relationship": "direct" if name in direct_names else "transitive",
                "version": version,
            }
        )

    if len(dependencies) > 10000:
        problems.append("resolved dependency count exceeds the public inventory bound")
    if problems:
        raise DependencyInventoryError(problems)

    return {
        "schema_version": "resolved-dependency-inventory-v1",
        "project_name": canonical_name(str(project.get("name", ""))),
        "project_version": str(Version(str(project.get("version", "")))),
        "runtime_dependency_count": len(runtime_dependencies),
        "dependencies": dependencies,
    }


def render_inventory(inventory: dict[str, Any]) -> str:
    """Render deterministic JSON after asserting the absence of path/URL material."""

    rendered = json.dumps(inventory, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if "://" in rendered or "\\" in rendered:
        raise DependencyInventoryError(["inventory contains prohibited URL or path material"])
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write sanitized JSON to this local file")
    arguments = parser.parse_args(argv)
    try:
        rendered = render_inventory(collect_dependency_inventory())
        if arguments.output is None:
            sys.stdout.write(rendered)
        else:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    except DependencyInventoryError as exc:
        print(f"dependency inventory failed: {exc}", file=sys.stderr)
        return 1
    except (InvalidVersion, OSError, tomllib.TOMLDecodeError):
        print("dependency inventory failed: local metadata could not be processed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
