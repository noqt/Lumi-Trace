# Lumi Trace Schemas

## Contract Policy

Lumi Trace emits versioned JSON objects with strict field names, stable ordering
where order is meaningful, and canonical SHA-256-derived identities. Published
JSON Schemas use JSON Schema Draft 2020-12 and reject unknown fields unless a
contract explicitly states otherwise.

Schema names and `schema_version` values are part of the V0.1 compatibility
contract. A breaking change requires a new schema-version name; an existing v1
contract must not be silently reinterpreted.

## Step 1 deterministic profile

- `localization-inference-request-v0.4.1.json` is the only inference-side
  request accepted by the localizer. It contains the normalized finding,
  immutable repository artifact identity, and bounded configuration. Audit
  receipts, targets, fixed revisions, labels, and qualification state are not
  accepted.
- `localization-raw-ranking-v0.4.1.json` defines the bounded candidate
  inventory, exported ranking, source-visible role classes, telemetry,
  abstention, ranking identity, and raw-output seal.

The V0.6.1 product retains runtime identity `lumi-trace-runtime-v0.4.1-pre-release.11`,
candidate algorithm `label-blind-python-role-candidates-v0.4.1.7`, repository
index `deterministic-lexical-index-v4`, Python symbol extractor
`python-lexical-v1`, and uses deterministic ranker
`role-aware-sparse-v0.6.0.1`. The V0.6.1 package retains that ranker identity because its
local scoring and unique-path projection are unchanged. Its local scoring constants are the V0.5 profile;
V0.6 changes only the public projection so each candidate path is unique. The V0.5
ranker `role-aware-sparse-v0.5.0.2` and the V0.4.2 ranker
`role-aware-sparse-v0.4.1.3` and historical `.8` raw output remain verifiable.
Governed V0.4.1 reconstruction scripts explicitly pin `.8` and its historical
decision rule, and its execution is fail-closed outside CPython 3.12.

The superseded unreleased `.9`/candidate `.5`/index-v2 profile and the failed
AST remediation `.10`/candidate `.6`/index-v3 profile are accepted only for
validation of already-created evidence; constructors and runtime execution
reject both. The Step 1 CLI emits `.11` only. Runtime/candidate,
candidate/index and Python-extractor pairings cannot be mixed. Current v4
index paths, `.7` candidate paths, and `.11` raw inventory/ranked paths are
printable ASCII by contract. The v4 index records the fixed Python
grammar-projection bounds: 16,384 characters, 512 non-whitespace work units,
2,048 AST nodes and 128 AST levels. Current execution also requires CPython
3.11 or 3.12 with a recursion limit of at least 1,000.

`candidate-set-v1` and `evidence-bundle-v1` retain their strict legacy profile
and add distinguishable deterministic product profiles keyed by their algorithms.
Legacy documents remain valid. New product documents additionally bind the
candidate algorithm, ranker, role, ranking identity, confidence descriptor,
and fail-closed abstention, including `CANDIDATE_GENERATION_TRUNCATED` when a
bounded inventory is incomplete. Unknown or mixed-profile fields remain
invalid.

Runtime verification applies canonical identities and cross-field invariants
that JSON Schema alone cannot express, including inventory/ranking membership,
sequential ranks, candidate identities, ranking/bundle bindings, and the
complete raw-output seal.

## Published Schema Files

| Schema | Purpose |
| --- | --- |
| `schemas/manual-finding-v1.json` | Strict human-authored finding input accepted by `import-manual`. |
| `schemas/batch-triage-package-v1.json` | Exact artifact manifest for a multi-result local SARIF triage package. Runtime verification additionally checks every batch artifact, reference, queue entry, and SARIF projection. |
| `schemas/normalized-finding-v1.json` | Normalized manual or SARIF finding, including input hash, rule, severity, safe relative locations, keywords, and fingerprints. |
| `schemas/normalized-finding-collection-v1.json` | Manifest emitted when SARIF import writes multiple normalized findings. |
| `schemas/repository-index-v1.json` | Immutable repository identity plus deterministic file, token, exclusion, and symbol index. |
| `schemas/candidate-set-v1.json` | Ranked file and symbol candidates, integer scores/reasons, roles, ranker identity, confidence semantics, fail-closed abstention, and stable identities. |
| `schemas/evidence-bundle-v1.json` | Finding, repository provenance, ranking summary, candidates, reproduction, classification, telemetry, and limitations. |
| `schemas/evidence-package-manifest-v1.json` | Exact artifact names, byte sizes, hashes, and identity for a trace package. |
| `schemas/reproduction-plan-v1.json` | Explicit argv-only plan, predicates, output-preview policy, and resource limits. |
| `schemas/reproduction-receipt-v1.json` | Local image and policy identity, qualification attestations, bounded step results, repository immutability, and receipt identity. |
| `schemas/localization-inference-request-v0.4.1.json` | Strict allowed-field request for the deterministic product localizer. |
| `schemas/localization-raw-ranking-v0.4.1.json` | Bounded candidate inventory, ranked head, telemetry, abstention, and raw seal. |

Every product schema named above is included in the Step 1 wheel and source
distribution and validates its generated fixture. Development/evaluator
schemas retained elsewhere in the repository are intentionally outside the
Step 1 package boundary. A missing product schema is a release blocker, not
permission to infer a contract from prose.

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
Artifact `uriBaseId` must be omitted or explicitly use `%SRCROOT%`; unresolved
or alternative bases fail closed. No SARIF field is treated as a reproduction
command.

### `reproduction-plan-v1`

Plans are separate from findings. They require at least one step and all
resource limits. Each step requires an argv array, safe relative `cwd`, and at
least one exact expected exit-code/stdout/stderr predicate. See
[Reproduction](../REPRODUCTION.md).

## Derived Runtime Contracts

The runtime also emits:

- `normalized-finding-collection-v1` when SARIF import writes more than one
  normalized finding;
- `batch-triage-package-v1` for a local multi-result SARIF package. Its published schema describes the manifest; the runtime verifies the strict typed root, per-result, queue, error, and SARIF artifacts bound by that manifest; and
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
