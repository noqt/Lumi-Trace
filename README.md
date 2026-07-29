# Lumi Trace

Lumi Trace is a local deterministic vulnerability-evidence instrument. Give it
an existing finding and a local repository or archive; it ranks relevant
implementation locations and writes reviewer-ready JSON and SARIF evidence.
An explicitly supplied reproduction plan can optionally run in a preloaded,
network-denied Docker container.

The runtime has zero third-party Python dependencies, no hosted-inference path,
no API-key requirement, and no packaged model weights. It does not discover
vulnerabilities, generate repairs or exploits, or execute instructions found in
SARIF or repository content.

## Step 1 release boundary

This branch is an unreleased `0.4.1-dev.0` release candidate. Public
publication remains blocked until the written ownership, example, approver,
distribution, contact/privacy, and signing decisions in
[the Step 1 release gate](docs/STEP_1_RELEASE_GATE.md) are closed.

The primary `trace` path uses the frozen deterministic
`role-aware-sparse-v0.4.1.3` ranker. The private learned-route work remains
non-default, unqualified development history; no checkpoint is distributed or
used by the primary workflow. Step 1 implementation-location ranking is
Python-only and freezes AST extraction to Python 3.11 grammar for identical
ranking behavior on supported Python 3.11 and 3.12 runtimes. Files using later
syntax remain file candidates without partial AST symbols. No broader
language-support claim is made.

Read the [product contract](docs/STEP_1_PRODUCT_CONTRACT.md),
[five-minute quickstart](docs/STEP_1_QUICKSTART.md), and
[privacy/data-handling statement](docs/PRIVACY_AND_DATA_HANDLING.md) first.
V0.4/V0.4.1 integrity and programme history remain in the source repository
but are deliberately excluded from Step 1 release artifacts.

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

Install the supplied candidate wheel in a clean environment:

```sh
python3 -m venv lumi-trace-env
. lumi-trace-env/bin/activate
python -m pip install ./skylark_lumi_trace-0.4.1.dev0-py3-none-any.whl

lumi-trace trace \
  --finding ./public-ghsa-8359-h9fx-j6v9/finding.json \
  --finding-format manual \
  --repository ./datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip \
  --output ./trace-evidence

lumi-trace verify ./trace-evidence
```

PowerShell:

```powershell
py -3.12 -m venv lumi-trace-env
.\lumi-trace-env\Scripts\Activate.ps1
python -m pip install .\skylark_lumi_trace-0.4.1.dev0-py3-none-any.whl
lumi-trace trace --finding .\public-ghsa-8359-h9fx-j6v9\finding.json --finding-format manual --repository .\datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip --output .\trace-evidence
lumi-trace verify .\trace-evidence
```

Acquire the pinned public archive directly from upstream with the example's
`fetch_example.py`. See the
[complete quickstart](docs/STEP_1_QUICKSTART.md) for Bash, PowerShell, expected
output, provenance, and common corrections.

The quickstart intentionally omits reproduction. It succeeds with
`INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`: an explicit abstention from
confirmation, not an operational failure.

## Supported Inputs

- Strict `manual-finding-v1` JSON.
- SARIF 2.1.0. A complete trace selects exactly one result with
  `--run-index` and `--result-index` when the input contains more than one.
- An existing `normalized-finding-v1` JSON document.
- A local repository directory, immutable ZIP, or bounded USTAR-compatible
  TAR-family archive.
- An optional, user-authored `reproduction-plan-v1` plus a digest-form reference
  to a local Linux-container image.

Remote repository URLs and remote SARIF artifact locations are not supported.
Repository symlinks, special files, unsafe archive paths, encrypted ZIP members,
and archive links fail closed.

## CLI

| Command | Purpose |
| --- | --- |
| `version` | Report version, inventory identity, and the zero-weight model status. |
| `status --image IMAGE_DIGEST` | Inspect Docker availability and whether an immutable digest-form image is already local. |
| `import-manual` | Convert one manual finding to `normalized-finding-v1`. |
| `import-sarif` | Convert selected or all SARIF 2.1.0 results to normalized findings. |
| `index` | Snapshot and deterministically index a directory or archive. |
| `rank` | Rank files and symbols from a normalized finding and repository index. |
| `localize` | Non-default development interface retained for V0.4.1 history; the learned option requires an explicitly supplied local artifact. |
| `reproduce` | Run an explicit plan in the qualified network-denied sandbox. |
| `trace` | Run the complete import-to-export pipeline. |
| `export-sarif` | Project a verified evidence bundle to SARIF 2.1.0. |
| `validate` | Apply built-in invariants and identity checks to a supported contract. |
| `verify` | Verify an evidence bundle or a packaged output manifest and hashes. |

All commands print a compact JSON summary on success and return a non-zero exit
status for invalid, unsupported, or integrity-failing inputs. `trace` also
prints a readable ranked-location/evidence summary.

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

See the standalone [privacy statement](docs/PRIVACY_AND_DATA_HANDLING.md),
[product contract](docs/STEP_1_PRODUCT_CONTRACT.md),
[Threat Model](docs/THREAT_MODEL.md), [Schemas](docs/SCHEMAS.md), and
[Reproduction](docs/REPRODUCTION.md).

## Licence

Skylark-owned source code and documentation are licensed under Apache-2.0.
Future model weights, training data, customer evidence, protected evidence, and
third-party repository contents are not licensed by that source-code licence.
