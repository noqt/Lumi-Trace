# Third-Party Notices

This file records third-party material distributed in the Lumi Trace source
repository. It does not replace the licence supplied by a third-party author.

## Distributed Third-Party Material

No third-party source code, model weights, training data, customer repository
contents, CyberGym tasks, or protected Lumi evidence is vendored in the V0.2
source distribution.

Public test fixtures must be Skylark-authored synthetic content or must include
a file-specific source, author, licence, and modification notice demonstrating
that redistribution is permitted. A fixture without that provenance must not
be included in a public release.

## External Dependencies

Packages installed from a package index for development, testing, building, or
runtime use are not relicensed by Lumi Trace and are not covered by the
repository's Apache-2.0 licence. Each dependency remains subject to its own
licence and notice obligations.

`scripts/dependency_inventory.py` generates the V0.1 resolved dependency and
licence inventory entirely from installed package metadata. It records only
canonical package names, versions, licence declarations, and direct/transitive
relationships; it records no installation paths, download URLs, timestamps, or
host details. `scripts/check_dependencies.py` fails closed on missing packages,
unsatisfied requirements, unknown or prohibited licence metadata, direct URLs,
or an inconsistent installed environment. The generated inventory is reviewed
and manifest-bound as part of each versioned release seal.

Lumi Trace has no Python runtime dependencies. The declared build and
development tools are external and are not included in the source repository:

| Dependency | Declared version | Purpose | Upstream licence |
| --- | --- | --- | --- |
| pip | `26.1.2` | release-environment bootstrap installer | MIT |
| setuptools | `83.0.0` | PEP 517 build backend | MIT |
| build | `1.3.0` | source/wheel build check | MIT |
| jsonschema | `4.26.0` | test-time schema validation | MIT |
| packaging | `26.2` | release dependency and marker validation | Apache-2.0 OR BSD-2-Clause |
| pip-audit | `2.9.0` | dependency vulnerability audit | Apache-2.0 |
| PyYAML | `6.0.3` | test-time inventory YAML parsing | MIT |
| pytest | `9.0.3` | test runner | MIT |
| Ruff | `0.12.3` | lint and formatting checks | MIT |
| Twine | `6.1.0` | distribution metadata check | Apache-2.0 |

Their transitive dependencies remain under their respective upstream
licences. The inventory script traverses the active installed requirement
closure, while `python -m pip-audit` provides the separate vulnerability check.
All Python packages in this table and inventory are external build, test, or
release tools; none is bundled into the V0.1 source distribution or imported by
the Lumi Trace runtime.

The separately installed Trace-Eval environment uses `jsonschema 4.26.0`
(MIT), `attrs 26.1.0` (MIT), `jsonschema-specifications 2025.9.1` (MIT),
`referencing 0.37.0` (MIT), `rpds-py 2026.6.3` (MIT), and
`typing-extensions 4.16.0` (PSF-2.0). Exact versions are retained in
`eval/requirements/trace-eval.lock`. None is imported by the V0.1 runtime.

Docker, the Linux container runtime, and the pinned Alpine smoke-test image are
external prerequisites; Lumi Trace does not redistribute them. The smoke image
is preloaded before testing and reproduction is executed by immutable local
image identity with pulling disabled.

## Prohibited Inputs

The following are not third-party dependencies and must not be added to this
notice as a way to legitimise distribution: customer evidence, historical Lumi
evidence, protected holdback material, CyberGym task material, credentials,
private manifests, or third-party repository contents collected during a Lumi
Trace run. Those materials are outside the open-source boundary and must not be
committed or published.
