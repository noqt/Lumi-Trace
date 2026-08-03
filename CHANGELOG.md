# Changelog

This file records user-visible changes to Lumi Trace.

Detailed research history, internal experiment records, and release-approval notes belong in a separate research or maintainer archive rather than the product changelog.

## 0.8.0 - Unreleased

### Added

- Added the first-party `noqt/Lumi-Trace` composite GitHub Action for running
  the existing bounded `triage` workflow after a consumer's scanner produces
  local SARIF.
- The action writes a bounded job summary, exposes scalar result outputs, and
  can upload only a verified evidence package when the consumer explicitly
  enables artifact retention.
- Added opt-in CI policy handling for verified partial processing and the
  scanner-supplied SARIF severity level.

### Limitations

- The action is integration only: it neither scans a repository nor discovers
  vulnerabilities, executes repository code, posts PR comments, or turns queue
  order into a risk, exploitability, or safety verdict.
- GitHub receives workflow logs and summary content. Evidence artifact upload is
  disabled by default because evidence can contain sensitive metadata.

## 0.7.1 - 2026-08-03

### Added

- Added `lumi-trace triage` for one bounded local SARIF 2.1.0 report and one local repository snapshot.
- Emits a deterministic per-result V0.6.1-equivalent unique-path shortlist, a consolidated unique-path review queue, combined SARIF, and a hash-bound batch package.
- Supports verified partial success: malformed individual results are retained as bounded local error records while valid results remain usable. Partial success exits with code `5`.

### Limitations

- Batch queue order is review priority only. It is not a vulnerability verdict, risk probability, exploitability estimate, or repository safety result.
- Batch triage neither discovers findings nor executes repository code, and does not run optional reproduction across SARIF results.

### Validation

- Exact standalone-versus-batch parity passed for all 30 admitted findings across pinned Flask, Requests, and HTTPX workloads generated with Bandit 1.9.4.
- Every admitted batch and standalone evidence package verified; no result was lost, rejected, or silently truncated.
- These results validate workflow parity and package integrity, not vulnerability-discovery accuracy or repository safety.

## 0.6.1 - Included in 0.7.1; not separately released

### Changed

- Projected the deterministic raw ranking to one source anchor per repository path, so the default result is a ten-path actionable reviewer shortlist.
- Preserved V0.5 local scoring, raw-output verification, and historical V0.5 replay while assigning the V0.6 projection its own ranker identity.

### Governance

- Replaced a structurally mismatched zero-regression role comparator with a reviewer-dominance control: each full top-five shortlist must retain at least three implementation paths, and non-implementation paths may occupy no more than 20% of top-five positions across the reviewed set.
- This changes no ranker score, candidate order, product input, or fresh-case result. Roles and score reasons remain visible to reviewers.

### Validation

- On 12 fresh reviewed public Python vulnerability-fix cases, an accepted target path appeared in the first ten unique paths in 11 cases (91.7%), with median first accepted target-path rank 1.
- Every full top-five shortlist retained at least three implementation paths; non-implementation paths occupied 3 of 60 delivered top-five positions.
- These results describe the reviewed cases only and do not establish population accuracy or vulnerability-discovery capability.

### Limitations

- The shortlist is a deterministic aid for reviewing a supplied finding. It remains neither vulnerability discovery nor a safety verdict.

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
