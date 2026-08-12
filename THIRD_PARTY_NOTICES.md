# Third-Party Notices

This file records the third-party boundary for the Lumi Trace release source
and packages. It does not replace any licence supplied by a third-party author.

## Distributed material

The release does not distribute third-party source code, model weights,
training data, advisory records, customer repository content, examples,
generated evidence, CyberGym tasks, or protected Lumi evidence. The source,
documentation, schemas, and synthetic test material in the release are
distributed under Apache-2.0 unless a file states otherwise.

Users supply their own findings and local repositories or archives. Those
inputs and generated output do not become project content and remain subject to
their owners' terms and the user's authority to analyse them.

## External development and release tools

Lumi Trace has no Python runtime dependencies. The following tools may be
installed from their upstream package indexes for development, testing, build,
or release checks; they are not bundled in the runtime package and are not
relicensed by Lumi Trace.

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

Their transitive dependencies remain under their respective upstream licences.
The release dependency inventory and licence check are generated from installed
package metadata and reviewed as part of each release build. Docker and a
locally preloaded immutable Linux-container image are optional external
prerequisites for reproduction; Lumi Trace does not redistribute them or pull
images.

## GitHub Actions integration

The optional first-party GitHub Action references these GitHub-maintained
workflow actions by immutable commit SHA. They execute in the consumer's GitHub
workflow and are not included in the Lumi Trace Python wheel or source archive.

| Action | Immutable revision | Purpose | Upstream licence |
| --- | --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) | Consumer workflow checkout in the documented integration | MIT |
| `actions/setup-python` | `a309ff8b426b58ec0e2a45f0f869d46889d02405` (`v6.2.0`) | Select CPython 3.12 for the composite action | MIT |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`v7.0.1`) | Optional verified evidence-artifact retention | MIT |

## Historical private material

Historical evaluation and development records may refer to upstream advisory
feeds and repositories. They remain outside this release and are not a grant to
redistribute those materials. Future third-party material must not be included
unless its licence, attribution, modification notice, and redistribution rights
are documented here before publication.
