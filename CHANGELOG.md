# Changelog

This file records user-visible changes to Lumi Trace.

Detailed research history, internal experiment records, and release-approval notes belong in a separate research or maintainer archive rather than the product changelog.

## 0.4.2 - Unreleased

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
