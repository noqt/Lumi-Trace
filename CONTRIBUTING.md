# Contributing to Lumi Trace

Thank you for helping improve Lumi Trace.

This repository provides Lumi's local, deterministic, fail-closed Trace
functionality. Contributions should preserve its clear boundary: existing
findings in, ranked source locations and verifiable evidence out.

## Good contribution areas

Useful contributions include:

- manual and SARIF input handling;
- safe repository and archive materialisation;
- deterministic indexing and ranking;
- evidence readability and SARIF interoperability;
- bounded local reproduction;
- verification and tamper detection;
- error messages and documentation;
- cross-platform support for CPython 3.11 and 3.12; and
- synthetic tests for supported and fail-closed behavior.

Open an issue before beginning a large architectural change.

## Do not submit

Do not include:

- credentials or secrets;
- customer or private repository content;
- real customer findings or generated evidence;
- third-party code or datasets without documented redistribution rights;
- model weights, training data, or hosted-service dependencies;
- automatic execution of commands found in SARIF or repository content;
- host-execution fallback for reproduction; or
- claims of security performance that are not supported by published evidence.

Use synthetic fixtures created specifically for this repository wherever possible.

## Development setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q -m "not docker"
python -m ruff check .
python -m ruff format --check .
python -m build
```

Docker tests are optional. They require a local Linux-container engine and a deliberately preloaded immutable test image. Acquisition and network-denied execution must remain separate.

## Design requirements

Contributions must:

- keep supported output deterministic;
- use explicit, stable ordering and canonical identities;
- reject unsafe or ambiguous input instead of guessing;
- preserve the clean-room repository snapshot boundary;
- keep reproduction commands as argument arrays;
- never pull images during reproduction;
- never upload findings, repositories, or evidence;
- preserve bounded resource use and fail-closed classifications;
- update schemas and documentation when a public contract changes; and
- add focused success, abstention, malformed-input, and boundary-failure tests.

## Pull request checklist

Before requesting review, confirm that:

- relevant tests pass;
- lint and formatting checks pass;
- licence, dependency, secret, and public-boundary checks pass;
- new or changed output is deterministic across repeated runs;
- security and privacy effects are described;
- schema and compatibility effects are documented;
- no sensitive or third-party material is included; and
- user-facing behavior and release notes are updated.

Small, reviewable changes are preferred.

## Licensing

By contributing work to this repository, you agree that it may be distributed under Apache-2.0 and confirm that you have the right to submit it.

Third-party material must retain its licence and required attribution and must be recorded in `THIRD_PARTY_NOTICES.md`.
