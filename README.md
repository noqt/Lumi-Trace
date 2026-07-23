# Lumi Trace

> **V0.3 qualification build.** The V0.1 runtime remains the exact Trace Code
> system under test. Trace-Eval 0.3 adds location-role and safe-disposition
> contracts plus a separate, inert Trace IR feasibility lane. The governed
> natural store contains no admitted corpus, so V0.3 closes as
> `DATA_GATES_PENDING`; the owned-lab IR lane closes as
> `IR_FEASIBILITY_SUPPORTED`. Neither result authorises `TRACE-001` training,
> model-weight acquisition, live incident integration, or publication.

Lumi Trace is a customer-local vulnerability evidence instrument. It imports a
finding, creates a clean-room snapshot of a local repository or archive, builds
a deterministic file and symbol index, ranks relevant locations, optionally
attempts an explicitly supplied reproduction plan in a network-denied Docker
sandbox, and exports an auditable evidence package.

V0.1 has zero third-party Python runtime dependencies, zero model weights, no
hosted inference, and no API-key requirement. It is a deterministic software
baseline, not a trained ML model.

## Current Status and Hard Stops

- Runtime version: `0.1.0`; evaluator version: `0.3.0`.
- Inventory identity: `skylark.lumi.trace`.
- Model status: `PROPOSED_NOT_TRAINED`; checkpoint: none; active parameters: 0.
- V0.3 Trace Code state: `DATA_GATES_PENDING` (0 admitted natural groups).
- V0.3 Trace IR state: `IR_FEASIBILITY_SUPPORTED` on owned inert lab fixtures
  only; this is not a live attack-detection result.
- `TRACE-001` recommendation: `DO_NOT_BEGIN_TRACE_001`.
- Historical Lumi evidence, customer evidence, protected holdbacks, CyberGym
  tasks, and rejected V2.7 adapters are outside this build.

See the [model card](docs/MODEL_CARD.md), [training-readiness
record](docs/TRAINING_READINESS.md), and [open-source
boundary](docs/OPEN_SOURCE_BOUNDARY.md).

The owned-fixture V0.1 release seal and its controlled verification workflow
are documented in [V0.1 Release Evidence](docs/RELEASE_EVIDENCE.md).

The V0.2 evaluator, separated data boundary, public synthetic baseline, replay
protocol, and evidence limits are documented in [V0.2 Evaluation and
Qualification](docs/V0.2_EVALUATION.md). Evaluator commands are exposed by the
separate `skylark-lumi-trace-eval` package under `eval/`.

The disclosure-reviewed synthetic seal and exact verification command are in
[V0.2 Public Evaluation Evidence](docs/V0.2_EVIDENCE.md).

The V0.3 location-role contracts, natural-corpus decision, inert Trace IR lane,
and evidence limits are documented in [V0.3 Natural and Defensive Evidence
Qualification](docs/V0.3_QUALIFICATION.md). The disclosure-safe seal is
documented in [V0.3 Evidence](docs/V0.3_EVIDENCE.md).

## Runtime Flow

```text
finding import -> normalisation -> clean-room repository snapshot and identity
-> deterministic index -> deterministic candidate ranking
-> optional network-denied reproduction -> fail-closed classification
-> JSON and SARIF export
```

Lumi Trace does not generate repairs and does not automatically execute
instructions found in SARIF.

## Requirements

- Python 3.11 or newer.
- No third-party Python package is required at runtime.
- Docker is optional and is used only for reproduction.
- Reproduction requires a reachable Docker-compatible daemon configured for
  **Linux containers** and an immutable digest-form reference for an image
  already present locally: either `sha256:<64 lowercase hex characters>` or
  `NAME@sha256:<64 lowercase hex characters>`. Lumi Trace never pulls an image.
- The local reproduction image must provide `/bin/sh` so the sandbox can run
  its qualification probe. Qualification must pass before any plan step runs.

## Quickstart

Run directly from a checkout without installing the package:

```sh
PYTHONPATH=src python -m lumi_trace version

PYTHONPATH=src python -m lumi_trace trace \
  --finding tests/data/manual-finding.json \
  --finding-format manual \
  --repository tests/fixtures/demo-repository \
  --output out/quickstart
```

PowerShell uses the equivalent environment assignment:

```powershell
$env:PYTHONPATH = "src"
python -m lumi_trace version
python -m lumi_trace trace --finding tests/data/manual-finding.json --finding-format manual --repository tests/fixtures/demo-repository --output out/quickstart
```

The quickstart intentionally omits a reproduction plan, so its deterministic
classification is `INSUFFICIENT_EVIDENCE` with reason
`NO_REPRODUCTION_PLAN`. That is an abstention, not an error.

For local command help:

```sh
PYTHONPATH=src python -m lumi_trace --help
PYTHONPATH=src python -m lumi_trace trace --help
```

## Supported Inputs

- Strict `manual-finding-v1` JSON.
- SARIF 2.1.0. A complete trace selects exactly one result with
  `--run-index` and `--result-index` when the input contains more than one.
- An existing `normalized-finding-v1` JSON document.
- A local repository directory or immutable ZIP/TAR-family archive.
- An optional, user-authored `reproduction-plan-v1` plus a digest-form reference
  to a local Linux-container image.

Remote repository URLs and remote SARIF artifact locations are not supported.
Repository symlinks, special files, unsafe archive paths, encrypted ZIP members,
and archive links fail closed in V0.1.

## CLI

| Command | Purpose |
| --- | --- |
| `version` | Report version, inventory identity, and the zero-weight model status. |
| `status --image IMAGE_DIGEST` | Inspect Docker availability and whether an immutable digest-form image is already local. |
| `import-manual` | Convert one manual finding to `normalized-finding-v1`. |
| `import-sarif` | Convert selected or all SARIF 2.1.0 results to normalized findings. |
| `index` | Snapshot and deterministically index a directory or archive. |
| `rank` | Rank files and symbols from a normalized finding and repository index. |
| `reproduce` | Run an explicit plan in the qualified network-denied sandbox. |
| `trace` | Run the complete import-to-export pipeline. |
| `export-sarif` | Project a verified evidence bundle to SARIF 2.1.0. |
| `validate` | Apply built-in invariants and identity checks to a supported contract. |
| `verify` | Verify an evidence bundle or a packaged output manifest and hashes. |

All commands print a compact JSON summary on success and return a non-zero exit
status for invalid, unsupported, or integrity-failing inputs.

## Outputs

A successful `trace` writes:

- `normalized-finding.json`;
- `repository-index.json`;
- `candidates.json`;
- `evidence-bundle.json`;
- `evidence.sarif`;
- `reproduction-plan.json` and `reproduction-receipt.json` when reproduction
  was requested; and
- `manifest.json`, which records artifact hashes and package identity.

Identifiers and receipts use canonical JSON and SHA-256-derived identities.
SARIF output contains candidate paths, symbols, and source regions but never
source snippets.

## Deterministic Classification

Lumi Trace emits exactly one of:

- `CONFIRMED`: every declared witness matched in a qualified sandbox, network
  denial and snapshot immutability were attested, and no infrastructure reason
  forced abstention;
- `UNSUPPORTED`: the requested reproduction could not be performed within the
  V0.1 contract; or
- `INSUFFICIENT_EVIDENCE`: no reproduction was requested, a witness did not
  match, or a sandbox, timeout, output, immutability, or infrastructure
  condition prevented confirmation.

Confidence grades and basis points are deterministic evidence descriptors, not
probabilities.

## Privacy Warning

Keep output directories local and access-controlled. Even though SARIF omits
source snippets, output can contain customer finding text, repository paths,
symbol names, token vocabulary, source locations, hashes, reproduction
metadata, and opt-in bounded stdout/stderr previews. Do not commit or publish
customer evidence or third-party repository-derived output.

The only generated evidence permitted in this source repository is a
versioned release seal produced exclusively from the licensed,
Skylark-authored synthetic fixture. Every sealed artifact must be covered by
the release-seal manifest and pass the public-boundary checks. This narrow
exception never applies to customer or third-party-derived output.

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md),
[Schemas](docs/SCHEMAS.md), and [Reproduction](docs/REPRODUCTION.md) for the V0.1
contract and limits.

## Licence

Skylark-owned source code and documentation are licensed under Apache-2.0.
Future model weights, training data, customer evidence, protected evidence, and
third-party repository contents are not licensed by that source-code licence.
