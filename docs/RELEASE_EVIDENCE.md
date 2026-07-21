# V0.1 Release Evidence

The committed `evidence/v0.1.0` tree is a public-safe release seal built only
from the repository's Skylark-authored, Apache-2.0 synthetic fixture. V0.1
source publication was separately authorised after controlled internal review.
The seal is not customer evidence, training evidence, or authority to begin
`TRACE-001`.

## Seal Preconditions

- checkout `codex/lumi-trace-v0-1` at a clean implementation commit;
- install the exact development dependencies declared in `pyproject.toml`;
- use a local Linux Docker engine through a local socket or named pipe;
- preload the immutable image named below; and
- leave `evidence/v0.1.0` absent or empty.

The sealing command does not pull an image, mutate Git state, overwrite an
existing seal, contact a model provider, download weights, or access a customer
repository.

```powershell
$revision = git rev-parse HEAD
.\.venv\Scripts\python.exe scripts\seal_v0_1.py `
  --image 'alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1' `
  --source-revision $revision
```

## Sealed Contents

The seal contains:

- a manifest-bound `CONFIRMED` evidence package for the owned fixture;
- the network-denied sandbox qualification and immutable image identity;
- the zero-weight `skylark.lumi.trace` inventory record;
- a sanitized resolved dependency and licence inventory;
- twice-built, byte-reproducible wheel and source artifacts with hashes;
- release-check results;
- a fail-closed `DO_NOT_BEGIN_TRACE_001` readiness recommendation; and
- an exact tree manifest with SHA-256 digests and a stable seal identity.

No timestamps, elapsed durations, absolute host paths, credentials, output
previews, model weights, training data, historical Lumi evidence, customer
evidence, holdback material, or CyberGym material are permitted in the seal.

## Independent Verification

```powershell
.\.venv\Scripts\python.exe scripts\verify_v0_1_evidence.py evidence\v0.1.0
```

Verification checks exact tree membership, hashes, identities, cross-artifact
provenance, evidence classification, sandbox qualification, release artifact
layout, dependency inventory, and the training stop gate. The evidence package
inside the seal is also independently accepted by `lumi-trace verify`.

The bundle's `tool.source_revision` names the clean implementation commit. The
later evidence-only commit intentionally does not change that implementation
identity.
