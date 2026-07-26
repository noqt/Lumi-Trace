# Lumi Trace

> **V0.4.1 integrity recovery in development.** The V0.4 label-aware
> candidate-generation defect is recorded and its derived evidence is
> invalidated. V0.4.1 adds a label-blind product localizer, isolated
> builder/scorer/custodian roles, a private from-scratch linear development
> candidate, and fail-closed fresh-evidence gates. Fresh model selection,
> qualification, pilot activation, repository release, and weight publication
> remain unauthorised.

Lumi Trace is a customer-local vulnerability evidence instrument. It imports a
finding, creates a clean-room snapshot of a local repository or archive, builds
a deterministic file and symbol index, ranks relevant locations, optionally
attempts an explicitly supplied reproduction plan in a network-denied Docker
sandbox, and exports an auditable evidence package.

The package has zero third-party Python runtime dependencies, no packaged model
weights, no hosted inference, and no API-key requirement. The optional learned
V0.4.1 development route accepts only an explicitly supplied, hash-bound local
model artifact; the governed development checkpoint is not distributed.

## Current Status and Hard Stops

- Runtime version: `0.4.1-dev.0`; evaluator version: `0.4.1`.
- Inventory identity: `skylark.lumi.trace`.
- Model status: `PRIVATE_DEVELOPMENT_CANDIDATE_NOT_QUALIFIED`; one
  10,455-parameter sparse integer checkpoint is retained on governed private
  storage. Its loader and hybrid ranker are product-integrated, but the
  checkpoint is not packaged or publication-authorised.
- V0.4 governed corpus: 1,228 groups in family-disjoint training,
  engineering-development, model-selection, qualification, and protected
  holdback partitions.
- V0.3.1 Trace Code and the V0.3.2 evidence seal remain immutable. The spent
  V0.3.2 qualification partition was not used for V0.4 development.
- V0.3 Trace IR state: `IR_FEASIBILITY_SUPPORTED` on owned inert lab fixtures
  only; this is not a live attack-detection result.
- V0.4 qualification is spent and invalid for capability decisions after the
  controlled-review defect. Fresh V0.4.1 model-selection and qualification
  inputs remain custodian-closed and were not opened as executable partitions;
  the protected holdback remains unopened.
- V0.4.1 candidate generation is end-to-end label-blind and the isolated
  builder denies scorer/custodian filesystem access, sockets, and subprocesses.
- Fresh independent data supply is below the predeclared raw and family floors,
  so no V0.4.1 qualification claim or `DETERMINISTIC_ROUTE` claim is made.
- Historical Lumi evidence, customer evidence, protected holdbacks, CyberGym
  tasks, and rejected V2.7 adapters are outside this build.

See the [model card](docs/MODEL_CARD.md), [training-readiness
record](docs/TRAINING_READINESS.md), and [open-source
boundary](docs/OPEN_SOURCE_BOUNDARY.md).

The item-level corpus assurance, label-blind candidate baseline, training
decision, negative learned experiment, and single-use qualification are
documented in [V0.4 assurance](docs/V0.4_ASSURANCE.md). The disclosure-safe
seal and verification command are documented in [V0.4
evidence](docs/V0.4_EVIDENCE.md).

The V0.4.1 remediation, development result, evidence limits, and exact
ready-to-resume condition are documented in [V0.4.1
evidence](docs/V0.4.1_EVIDENCE.md).

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

The V0.3.1 proposal-before-fetch intake, separate rights decisions, inert
exact-revision acquisition, natural pair labels, repository-family splits,
predeclared baseline thresholds, and one-run qualification budget are
documented in [V0.3.1 Governed Natural Pilot](docs/V0.3.1_NATURAL_PILOT.md).
Its disclosure-safe result is documented in [V0.3.1
Evidence](docs/V0.3.1_EVIDENCE.md).

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

The V0.4.1 development localizer is a separate bounded command:

```sh
PYTHONPATH=src python -m lumi_trace import-manual \
  tests/data/manual-finding.json \
  --repository tests/fixtures/demo-repository \
  --output out/normalized.json

PYTHONPATH=src python -m lumi_trace localize \
  --finding out/normalized.json \
  --repository tests/fixtures/demo-repository \
  --ranker role-aware-sparse-v0.4.1.3 \
  --output out/localization.json
```

The learned ranker additionally requires `--model` with an explicitly supplied
local canonical JSON artifact. No model is bundled, downloaded, selected, or
qualified by the public package.

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
| `localize` | Run the bounded label-blind V0.4.1 localizer with a deterministic ranker or explicitly supplied hash-bound local model. |
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
