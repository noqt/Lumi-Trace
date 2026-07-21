# Contributing to Lumi Trace

Lumi Trace V0.1.0 is a public source release. Contributions must preserve its
deterministic, customer-local, fail-closed product contract and the hard stop
before `TRACE-001` training.

## Scope

Good V0.1 contributions improve finding import, immutable repository identity,
deterministic indexing and ranking, bounded Docker reproduction, evidence
classification, schema validation, documentation, or focused synthetic tests.

Do not contribute:

- model training, downloaded weights, learned adapters, or hosted inference;
- repair generation or task-specific repair rules;
- customer or third-party repository contents;
- historical Lumi evidence, `CKPT-003`, rejected V2.7 adapters, or protected
  holdback material;
- CyberGym tasks or derived task evidence;
- credentials, private manifests, or runtime evidence from customer systems; or
- dependencies that require an API key or conflict with local-only operation.

## Development Setup

Python 3.11 or newer is required. The runtime itself has no third-party Python
dependencies. Development tools are pinned in the `dev` optional extra.

```sh
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m build
```

Docker tests are optional and must run Lumi Trace against an explicitly
approved image already present locally. The runtime must never pull an image.
An explicitly network-enabled CI preparation step may preload a pinned test
image before the network-denied test begins; acquisition and reproduction must
remain separate phases.

## Change Requirements

- Keep behavior deterministic: integer scoring, explicit ordering, canonical
  JSON, and stable identities must not depend on locale, wall-clock time,
  filesystem enumeration order, network state, or a hosted service.
- Reject ambiguous or unsafe input rather than guessing.
- Preserve the clean-room snapshot boundary; do not index or execute directly
  from a mutating source repository.
- Keep reproduction steps as argv arrays. Do not add implicit shell parsing,
  SARIF instruction execution, image pulling, or host fallback.
- Add focused tests for success, abstention, malformed input, and boundary
  failure behavior.
- Update schemas and documentation whenever a public contract changes.
- Keep fixtures synthetic and Skylark-authored, or record their permissive
  licence and provenance explicitly.
- Do not add source snippets to SARIF export.

## Pull Request Checklist

Before requesting review, confirm that:

- tests and formatting checks pass;
- licence, secret, and dependency checks pass;
- new output is deterministic across repeated runs;
- no protected or customer material is present;
- security and privacy effects are described;
- schema and compatibility effects are described; and
- the change does not claim that a checkpoint or trained model exists.

Small, reviewable commits are preferred. Do not commit generated customer or
third-party evidence, local ad hoc Docker receipts, virtual environments, build
outputs, or repository snapshots. The sole exception is a versioned release
seal generated from the repository's licensed synthetic fixture, after public-
boundary checks, with every artifact covered by its seal manifest.

## Licensing Contributions

By contributing Skylark-owned work to this source repository, you agree that it
may be distributed under Apache-2.0. You must have the right to submit every
included file. Third-party material must retain its original licence and
required attribution and must be recorded in `THIRD_PARTY_NOTICES.md`.

This source-code licence does not license future weights or training data.
