# Lumi Trace Step 1 Product Contract

Status: release-candidate contract; publication is blocked by
`STEP_1_RELEASE_GATE.md`.

## Product job

`lumi-trace trace` accepts one already-known vulnerability finding and one local
repository snapshot. It returns ranked implementation locations and a
reviewer-ready JSON/SARIF evidence package. An explicitly supplied reproduction
plan may also be run in a preloaded, network-denied Docker container.

Trace does not discover vulnerabilities, generate patches or exploits, execute
instructions found in a finding, upload inputs, or call hosted inference.

## Supported primary inputs

- one strict `manual-finding-v1` JSON object;
- one `normalized-finding-v1` JSON object;
- exactly one selected SARIF 2.1.0 result;
- one regular local directory, safe ZIP archive, or bounded USTAR-compatible
  TAR-family archive whose repository-relative paths are printable ASCII
  (U+0020–U+007E); and
- optionally, one strict `reproduction-plan-v1` and one immutable digest-form
  image already present in a local Linux-container engine.

If a SARIF document contains more than one result, the user must select one
with `--run-index` and `--result-index`. Remote repository URLs and remote SARIF
artifact locations are not inputs to `trace`.

Repository symbolic links, junctions/reparse points, special files, path
collisions, unsafe or non-portable archive names, archive links, encrypted ZIP
members, PAX/GNU TAR extension headers, oversized inputs, and mutable archives
fail closed.

## Frozen deterministic route

The Step 1 product default is `role-aware-sparse-v0.4.1.3`. It uses
label-blind, deterministic Python file/symbol candidate generation and integer
score components. The ranker name, candidate algorithm, stable ranking
identity, score components, and abstention state are emitted in the evidence
package.

New Step 1 requests use
`lumi-trace-runtime-v0.4.1-pre-release.11`, candidate algorithm
`label-blind-python-role-candidates-v0.4.1.7`, repository index
`deterministic-lexical-index-v4`, and Python symbol extractor
`python-lexical-v1`. Python declaration extraction uses a fixed lexical front
end and passes only declaration, decorator and f-string expression projections
to a Python 3.11 grammar validator. Each projection is capped at 16,384
characters, 512 non-whitespace work units, 2,048 AST nodes and 128 AST levels.
The AST never supplies symbols or ranges. Non-Python symbol patterns use fixed
ASCII semantics, and current-profile repository paths are printable ASCII.
Current execution is pinned to CPython 3.11/3.12 with a recursion limit of at
least 1,000, and exact index/candidate bytes are a cross-runtime release gate.

Unsupported or ambiguous declaration, string, f-string, bracket,
continuation or indentation structure, a projection over the fixed bound, and
context-sensitive `await`/`yield` projections leave the file indexed without
partial Python symbols. This is a declaration extractor, not a whole-file
Python validity oracle: a lexical declaration may still be recorded when an
unrelated statement is semantically invalid. A symbol is therefore a review
landmark, not evidence that its file imports or compiles.

The sealed V0.4.1 development evidence retains
`lumi-trace-runtime-v0.4.1-pre-release.8`; that historical identity remains
verifiable and is named explicitly by the governed reconstruction scripts and
Python builder interface. Historical execution is fail-closed outside its
pinned CPython 3.12 environment. The Step 1 CLI never emits it. The
superseded, unreleased `lumi-trace-runtime-v0.4.1-pre-release.9` is retained
for validation of already-created failed release-candidate evidence only:
constructors and runtime execution reject it. The subsequent
`lumi-trace-runtime-v0.4.1-pre-release.10` AST remediation is also retained
for verification only because `ast.parse(feature_version=...)` did not freeze
PEP 701 behavior across the supported runtimes.

The ordering score is a retrieval heuristic. It is not a probability, a
vulnerability verdict, or proof that a candidate is the correct repair
location. When the top-ranked candidate has no positive finding-guided signal,
the product fails closed with the machine-readable abstention
`NO_POSITIVE_FINDING_GUIDED_SIGNAL`. Candidate generation is bounded at
100,000 entries for the Step 1 runtime. If the complete universe would exceed
that bound, no ranking is presented as complete and the product emits
`CANDIDATE_GENERATION_TRUNCATED`.

The learned localizer remains non-default development history. No checkpoint,
model weight, remote model, tokenizer, API key, or hosted service is used by
`trace`.

## Evidence separation

The output directory separates four kinds of information:

1. Observed or supplied facts: the normalized finding, repository snapshot
   identity, and deterministic repository index.
2. Deterministic ranking: the canonical candidate set and bundle ranking
   summary, including ranker identity, score basis, stable ranking identity,
   and abstention.
3. Reproduction: an optional canonical plan and receipt. No plan means no
   repository code is executed.
4. Evidence decision: `CONFIRMED`, `UNSUPPORTED`, or
   `INSUFFICIENT_EVIDENCE`, with reason codes and a deterministic confidence
   descriptor.

`CONFIRMED` applies only to every declared witness in a supplied plan, against
the identified snapshot, after the sandbox controls attest successfully. It
does not establish that the repository is otherwise safe.

With no reproduction plan, `trace` succeeds and returns
`INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`. That is an explicit abstention
from confirmation, not an operational error.

Confidence grades and basis points describe the evidence state. They are not
probabilities and do not measure candidate-ranking accuracy.

## Output and verification

Current Step 1 output contains:

- `normalized-finding.json`;
- `repository-index.json`;
- `candidates.json`;
- `evidence-bundle.json`;
- `evidence.sarif`;
- optional `reproduction-plan.json` and `reproduction-receipt.json`; and
- `manifest.json`, which binds every output artifact by SHA-256 and size.

`lumi-trace verify OUTPUT_DIRECTORY` checks the contracts, canonical
identities, cross-artifact bindings, hashes, manifest membership, and
reproduction/classification consistency. It does not independently establish
that the finding is true.

Repeated no-reproduction runs over byte-identical inputs preserve canonical
identities and deterministic artifacts. Runtime-duration measurements used
during internal construction are observational and are not packaged into the
stable product evidence.

## Privacy and local-execution boundary

Core `trace` operation makes zero external network calls and records that fact
in the evidence. No usage telemetry is sent. Potentially sensitive finding
text, paths, symbols, token vocabulary, source regions, repository hashes, and
optional bounded reproduction output can appear in local output files.

The public-example fetch helper is a separate acquisition utility and does use
the network when invoked. It is not called by `trace`.

See `PRIVACY_AND_DATA_HANDLING.md` for handling and retention guidance.

## Claims boundary

The release candidate may be described only as a local deterministic
vulnerability-evidence instrument. It is not qualified, production-ready,
AI-powered, a vulnerability scanner, a repair generator, or evidence of
general localisation improvement.
