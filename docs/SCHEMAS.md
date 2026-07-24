# Lumi Trace Schemas

## Contract Policy

Lumi Trace emits versioned JSON objects with strict field names, stable ordering
where order is meaningful, and canonical SHA-256-derived identities. Published
JSON Schemas use JSON Schema Draft 2020-12 and reject unknown fields unless a
contract explicitly states otherwise.

Schema names and `schema_version` values are part of the V0.1 compatibility
contract. A breaking change requires a new schema-version name; an existing v1
contract must not be silently reinterpreted.

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
| `schemas/model-inventory-v1.json` | Skylark micro-model inventory record, including the `PROPOSED_NOT_TRAINED`, zero-weight state. |

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

Trace-Eval uses a separately packaged canonical envelope schema under
`eval/src/trace_eval/schemas/trace-eval-contract-v0.3.json`. It retains every
V0.2 record type and adds:

- programme boundary, natural-corpus registry, and repository-lineage audit;
- Trace Code location labels, metric specifications, case results, and
  aggregates;
- Trace IR events, episodes, labels, results, metrics, and feasibility
  decisions; and
- the V0.3 closure record.

Payload invariants are enforced by evaluator code in addition to the envelope.
Location labels require an explicit role, controlled-review receipt, and a
contiguous append-only correction history. Trace IR accepts only bounded inert
JSON, verifies owned immutable provenance and rights, rejects remote or
executable fields, and keeps labels outside runner input.

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
