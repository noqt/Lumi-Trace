# Changelog

This file records user-visible changes to Lumi Trace.

Detailed research history, internal experiment records, and release-approval notes belong in a separate research or maintainer archive rather than the product changelog.

## 0.5.0 - 2026-08-01

### Changed

- Reduced test, fixture, generated, and vendor decoys with a deterministic, visible role-precision score component.
- Kept exact reported paths and symbols exempt from the role penalty, while allowing strong unreported source signals to override it.
- Made the reviewed V0.5 ranker the product default while retaining V0.4 ranking profiles for explicit replay.

### Validation

- On 11 scored cases in the frozen reviewed confirmation set, first-correct-implementation-file rank improved in 8 cases, was unchanged in 3, and regressed in none.
- Median first-correct-implementation-file rank improved from 67 to 60; aggregate wrong-role top-five entries decreased from 18 to 1; no severe regression occurred.
- These results describe the reviewed cases only and do not establish population accuracy or vulnerability-discovery capability.

### Limitations

- Lumi Trace remains a local deterministic review aid for known findings. It is not a vulnerability scanner, learned model, exploit generator, or safety verdict.

## 0.4.2 - 2026-07-31

### Added

- A public synthetic quickstart that demonstrates installation, ranking, export, and verification without implying real-world coverage.
- Plain-language documentation for product scope, evidence classifications, inputs, outputs, privacy, and optional reproduction.

### Changed

- Reworked the README around user problems and successful workflows.
- Separated localisation from optional confirmation in the documentation.
- Removed internal programme language from the product onboarding path.
- Limited packaged documentation to files useful to end users.

### Fixed

- Aligned documentation with the version and artifacts actually available through GitHub Releases.
- Removed internal decision records from the end-user documentation package.

## 0.4.1 - 2026-07-31

### Added

- Finding-guided Python file and symbol localisation for a known finding.
- Strict manual JSON, normalized JSON, and selected SARIF 2.1.0 inputs.
- Deterministic ranking with transparent score reasons and fail-closed abstention.
- Hash-bound JSON and SARIF evidence packages with package verification.
- Optional explicit reproduction in a preloaded, network-denied local container.
- Reproducible GitHub release artifacts, SHA-256 checksums, an SPDX SBOM, and provenance attestations.

### Security

- Repository content is copied into a bounded clean-room snapshot and treated as untrusted data during localisation.
- Findings and source cannot supply reproduction commands; a separate user-authored plan is required.
- Reproduction has no host fallback, does not pull images, and applies non-root, read-only, network-denied resource controls.

### Limitations

- The released product is deterministic and Python-focused. It does not include a learned model or claim vulnerability discovery.

## 0.1.0 - 2026-07-21

### Added

- Manual and SARIF finding import.
- Immutable local repository snapshots and deterministic indexing.
- Deterministic file and symbol ranking.
- Optional network-denied local container reproduction.
- Fail-closed evidence classification.
- JSON and SARIF export.
- Hash-bound evidence verification.
