# Lumi Trace Schemas

## Contract Policy

Lumi Trace emits versioned JSON objects with strict field names, stable ordering
where order is meaningful, and canonical SHA-256-derived identities. Published
JSON Schemas use JSON Schema Draft 2020-12 and reject unknown fields unless a
contract explicitly states otherwise.

Schema names and `schema_version` values are part of the V0.1 compatibility
contract. A breaking change requires a new schema-version name; an existing v1
contract must not be silently reinterpreted.

## V0.4.1 Label-Blind Localization

- `localization-inference-request-v0.4.1.json` is the only inference-side
  request accepted by the isolated builder. It contains the normalized finding,
  immutable repository artifact identity, bounded configuration, and optional
  canonical model binding. Audit receipts, targets, fixed revisions, labels,
  and qualification state are not accepted.
- `localization-raw-ranking-v0.4.1.json` defines the bounded candidate
  inventory, exported ranking, source-visible role classes, telemetry,
  abstention, ranking identity, and raw-output seal.
- `localization-linear-model-v0.4.1.json` defines the safe JSON-only sparse
  integer model. It permits no foundation model, tokenizer, remote code, or
  hosted-service binding.

Runtime verification applies canonical identities and cross-field invariants
that JSON Schema alone cannot express, including ordered unique sparse weights,
request and model hash binding, inventory/ranking membership, sequential ranks,
candidate identities, and the complete raw-output seal.

## Published Schema Files

| Schema | Purpose |
| --- | --- |
| `schemas/manual-finding-v1.json` | Strict human-authored finding input accepted by `import-manual`. |
| `schemas/normalized-finding-v1.json` | Normalized manual or SARIF finding, including input hash, rule, severity, safe relative locations, keywords, and fingerprints. |
| `schemas/normalized-finding-collection-v1.json` | Manifest emitted when SARIF import writes multiple normalized findings. |
| `schemas/repository-index-v1.json` | Immutable repository identity plus deterministic file, token, exclusion, and symbol index. |
| `schemas/candidate-set-v1.json` | Ranked file and symbol candidates, integer scores, reason codes, and stable identities. |
| `schemas/evidence-bundle-v1.json` | Complete finding, repository provenance, candidate, reproduction, classification, telemetry, and limitation evidence. |
| `schemas/evidence-package-manifest-v1.json` | Exact artifact names, byte sizes, hashes, and identity for a trace package. |
| `schemas/reproduction-plan-v1.json` | Explicit argv-only plan, predicates, output-preview policy, and resource limits. |
| `schemas/reproduction-receipt-v1.json` | Local image and policy identity, qualification attestations, bounded step results, repository immutability, and receipt identity. |
| `schemas/resolved-dependency-inventory-v1.json` | Sanitized installed tool closure with canonical package name, version, licence, and direct/transitive relationship only. |
| `schemas/model-inventory-v1.json` | Skylark micro-model inventory record, including proposed, private experimental, and release states. |
| `schemas/localization-inference-request-v0.4.1.json` | Strict allowed-field request for the isolated V0.4.1 product localizer. |
| `schemas/localization-raw-ranking-v0.4.1.json` | Bounded candidate inventory, ranked head, telemetry, abstention, and raw seal. |
| `schemas/localization-linear-model-v0.4.1.json` | Safe bounded sparse integer model artifact with no executable serialization. |

At the time a release is sealed, every file named above must exist and validate
the corresponding generated fixture. Missing schema files are release blockers,
not permission to infer a contract from prose.

`candidate-set-v1` score reasons use one canonical match contract in V0.1.1:
`matches`, when present, contains 1 to 20 unique, non-empty strings in ascending
code-point order. Producers omit an empty match list. Runtime verification
enforces ordering in addition to the structural JSON Schema constraints.

## Accepted Input Contracts

### `manual-finding-v1`

A manual input is a strict JSON object with a required title and optional ID,
description, severity, rule metadata, locations, keywords, and fingerprints.
The importer rejects unknown fields and converts it to
`normalized-finding-v1`.

The standalone `schemas/manual-finding-v1.json` contract matches the runtime's
strict field and location validation.

### SARIF 2.1.0

SARIF input must declare version `2.1.0`. Each selected result becomes one
normalized finding. A complete `trace` must select one result when a SARIF
document contains multiple results. Remote artifact locations are unsupported.
No SARIF field is treated as a reproduction command.

### `reproduction-plan-v1`

Plans are separate from findings. They require at least one step and all
resource limits. Each step requires an argv array, safe relative `cwd`, and at
least one exact expected exit-code/stdout/stderr predicate. See
[Reproduction](REPRODUCTION.md).

## Derived Runtime Contracts

The runtime also emits:

- `normalized-finding-collection-v1` when SARIF import writes more than one
  normalized finding;
- `evidence-package-manifest-v1` for artifact names, hashes, sizes, and package
  identity; and
- SARIF 2.1.0 as a compatibility projection of an evidence bundle.

Standalone schemas for both derived JSON contracts are published under
`schemas/`. The CLI also verifies package-manifest identity, exact artifact
membership, hashes, sizes, cross-artifact provenance, classification, and SARIF
projection semantics.

## Canonical Identity

Identity input is serialised as compact JSON with:

- object keys sorted;
- ASCII escaping enabled;
- no insignificant whitespace;
- non-finite numbers rejected; and
- the object's self-identity field omitted where the contract requires it.

The canonical bytes are SHA-256 hashed. Content IDs use prefixes including
`finding:`, `repository:`, `index:`, `candidate:`, `candidate-set:`,
`evidence-bundle:`, and `evidence-package:`. Plan, policy, qualification, and
receipt identities use labelled `sha256:` digests. Pretty-printed artifact JSON
is not itself the identity encoding.

## Validation Layers

1. Importers reject unsafe or unknown input and normalise accepted data.
2. Runtime validators enforce required invariants and self-identities without a
   third-party runtime dependency.
3. `python -m lumi_trace validate` invokes those built-in checks for supported
   contract documents.
4. Draft 2020-12 validation against files in `schemas/` is a development and
   release check using the pinned development toolchain.
5. `python -m lumi_trace verify` checks a bundle identity or an exact package,
   including every hash/size and the semantic links among all artifacts.

The CLI `validate` command is not a general-purpose or complete JSON Schema
validator. Passing it does not replace release-time Draft 2020-12 validation.

## Trace-Eval V0.3 Records

Trace-Eval uses separately packaged, versioned canonical envelope schemas under
`eval/src/trace_eval/schemas/`. V0.3.3 retains every earlier record type and
adds:

- programme boundary, natural-corpus registry, and repository-lineage audit;
- Trace Code location labels, metric specifications, case results, and
  aggregates;
- Trace IR events, episodes, labels, results, metrics, and feasibility
  decisions; and
- the V0.3 closure record.

Payload invariants are enforced by evaluator code in addition to the envelope.
`trace-code-metric-specification-v2` defines hard-negative outrank over all
primary-metric groups that have both an accepted target and at least one
labelled hard negative. A missing retrieved negative remains in that
denominator as a non-outrank; a safe control with no target is ineligible.
Location labels require an explicit role, controlled-review receipt, and a
contiguous append-only correction history. Trace IR accepts only bounded inert
JSON, verifies owned immutable provenance and rights, rejects remote or
executable fields, and keeps labels outside runner input.

## Trace-Eval V0.4 Assurance Records

Trace-Eval 0.4.0 publishes the
`eval/src/trace_eval/schemas/trace-eval-contract-v0.4.0.json` canonical
envelope schema and enforces payload invariants in code. New identity-bearing
records include:

- source candidates and append-only data-state transitions;
- per-material, per-use rights matrices;
- quarantine scans and answer-leakage audits;
- controlled label passes and resolutions;
- group audit cards;
- partition seals, sample plans, and metric specifications;
- training-eligibility manifests; and
- final training-readiness decisions.

A `TRAINING_ELIGIBLE` card must be in the training partition, cite an approved
rights matrix whose model-input materials permit training, pass every item
audit, and appear in the final partition seal. Preprocessing is an exact
audit-card-identity allowlist operation. Evaluation-only, rejected, retired,
superseded, unsealed, or identity-mismatched records fail closed.

The private feature and experiment records used by the V0.4 build are not
public interchange schemas and are not included in package data. The public
V0.4 evidence seal contains aggregate projections only.

## Privacy Properties

Schemas require canonical repository-relative POSIX paths: absolute paths,
drive-qualified paths, traversal segments, backslashes, and NUL bytes are
rejected. SARIF output omits source snippets. These controls do not make an
evidence package public-safe: normalized findings, repository indexes,
candidates, receipts, and bundles can contain customer finding text, paths,
symbols, token vocabulary, hashes, command metadata, and opt-in output
previews. Keep customer and ad hoc packages local. Only the manifest-bound,
versioned release seal generated from the licensed Skylark-authored synthetic
fixture may be committed under the open-source boundary.
