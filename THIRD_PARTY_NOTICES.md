# Third-Party Notices

This file records third-party material distributed in the Lumi Trace source
repository. It does not replace the licence supplied by a third-party author.

## Distributed Third-Party Material

No third-party source code, model weights, training data, customer repository
contents, CyberGym tasks, or protected Lumi evidence is vendored in the Step 1
source distribution.

The Step 1 Git source and separately supplied review bundle include two
Skylark-authored finding descriptions adapted from GitHub Advisory Database
record `GHSA-8359-h9fx-j6v9`: one manual JSON finding and one SARIF finding.
The adapted advisory facts are attributed to the GitHub Advisory Database,
with reporter credit to Hamza Haroon (`thegr1ffyn`), and distributed under
CC-BY-4.0. Their file-specific source URLs, modification statement, retrieval
date, licence URL, and content hashes are recorded in
`examples/public-ghsa-8359-h9fx-j6v9/RIGHTS_AND_PROVENANCE.md`.

The example directory and its CC-BY-4.0 finding files are supplied separately
for controlled review and are not members of the Apache-2.0 wheel or source
distribution. This separation keeps package metadata and the package-level
SPDX conclusion scoped to Skylark-authored Apache-2.0 material.

The referenced `koxudaxi/datamodel-code-generator` repository revision remains
under its upstream MIT licence. Its archive is fetch-only: it is not bundled,
vendored, or redistributed in the Lumi Trace source or wheel.

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

V0.3.1 natural-corpus intake is retained only on governed private storage.
Public upstream source remains under its upstream licence and is neither
vendored into Lumi Trace nor redistributed in its evidence seal. Security
advisory records, exact revisions, source snapshots, fixing diffs, labels, and
case-level output are private evaluation inputs rather than distributed
third-party material.

V0.4 governed intake uses a locally retained snapshot of the OSV PyPI advisory
export and PyPA advisory data. Advisory material is governed by its upstream
terms, including CC-BY-4.0 attribution requirements:

- OSV data and licence information:
  <https://google.github.io/osv.dev/data/>
- PyPA Advisory Database:
  <https://github.com/pypa/advisory-database>
- GitHub Advisory Database terms:
  <https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database>

Except for the two attributed Step 1 finding descriptions identified above,
the advisory archive, governed-corpus advisory prose, repository catalogue,
third-party repository objects, revisions, diffs, labels, and features are not
distributed with Lumi Trace. Each governed-corpus repository revision has a
private item-level licence record and historical licence receipt. Those
records authorise only the uses they expressly mark; they do not relicense
repository contents under Apache-2.0.

TRACE-001 training code uses no external foundation model, tokenizer, model
weights, hosted service, or remote code. The governed experiment produced one
eight-parameter checkpoint that did not advance through model selection. It
remains private and is not distributed by this source release.

## Prohibited Inputs

The following are not third-party dependencies and must not be added to this
notice as a way to legitimise distribution: customer evidence, historical Lumi
evidence, protected holdback material, CyberGym task material, credentials,
private manifests, or third-party repository contents collected during a Lumi
Trace run. Those materials are outside the open-source boundary and must not be
committed or published.
