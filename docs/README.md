# Lumi Trace documentation

## Start here

- [Getting started](GETTING_STARTED.md): install, run the synthetic walkthrough, and trace your own finding.
- [Product scope and limitations](PRODUCT_SCOPE.md): what the result means and what Lumi Trace does not claim.
- [Inputs and outputs](INPUTS_AND_OUTPUTS.md): manual JSON, SARIF, repositories, evidence files, and verification.
- [Optional local reproduction](REPRODUCTION.md): explicit plans, container requirements, controls, and residual risk.
- [Privacy and data handling](PRIVACY.md): local processing and evidence sensitivity.
- [Runtime threat model](THREAT_MODEL.md): detailed trust boundaries and controls.
- [Architecture](ARCHITECTURE.md): runtime components and deterministic evidence flow.

## Project documents

- [`../SECURITY.md`](../SECURITY.md): private vulnerability reporting and supported versions.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md): development setup and contribution standards.
- [`../CHANGELOG.md`](../CHANGELOG.md): user-visible changes by release.
- [`../DISCLAIMER.md`](../DISCLAIMER.md): product scope and warranty notice.

Release-specific assurance summaries are kept with the source repository and release material. They are not part of the installed documentation package.

## Machine-readable contracts

Published JSON Schemas are under [`../schemas/`](../schemas/).

The prose documentation explains how to use those contracts. The schema files remain authoritative for machine validation.
Detailed compatibility notes are under
[`reference/SCHEMA_COMPATIBILITY.md`](reference/SCHEMA_COMPATIBILITY.md).

## Research and provenance

Selected public research history, evaluation records, failed experiments, and
detailed implementation identities are kept in the repository's
[research archive](https://github.com/noqt/Lumi-Trace/tree/main/docs/research).
They are historical records, not the supported product contract, and are not
packaged into the end-user wheel.
