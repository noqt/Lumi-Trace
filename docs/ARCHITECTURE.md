# Lumi Trace V0.1.1 Architecture

## Design Goal

Lumi Trace turns one supplied vulnerability finding and one local repository
snapshot into deterministic, auditable location and reproduction evidence. The
runtime is useful without learned inference and keeps customer source local.

```text
manual / SARIF / normalized finding
                |
                v
       finding normalisation
                |
                v
 clean-room snapshot + content identity
                |
                v
 deterministic file and symbol index
                |
                v
 deterministic candidate ranking
                |
                v
 optional qualified Docker reproduction
                |
                v
 fail-closed evidence classification
                |
                v
 JSON package + SARIF-compatible report
```

No stage requires a model provider, model weights, an API key, or external
network access.

## Components

### Finding Import and Normalisation

`findings.py` accepts strict manual JSON, SARIF 2.1.0, or an existing normalized
finding. It normalises severity, rule metadata, CWE identifiers, relative
locations, source regions, symbols, fingerprints, and input provenance into
`normalized-finding-v1`.

Remote artifact URIs fail closed. Absolute finding locations are accepted only
when the supplied repository allows them to be reduced to safe relative paths.
A full pipeline run requires exactly one selected SARIF result.

### Clean-Room Repository Workspace

`repository.py` never indexes or reproduces directly from the supplied
directory or archive. It materialises a disposable clean-room workspace:

1. enumerate and hash the source in stable path order;
2. reject symlinks, special files, unsafe archive paths, case/Unicode
   collisions, and configured size/count violations;
3. copy a directory or safely extract a ZIP/TAR-family archive;
4. re-hash directory sources before and after copying to detect mutation; and
5. compute a host-path-free `lumi-tree-sha256-v1` repository identity.

Snapshot files are normalized to mode `0644`, directories to `0755`, and mtimes
to 2000-01-01T00:00:00Z. Those constants remove behavior-visible metadata that
is intentionally absent from the content identity. Reproduction plans invoke
repository scripts through an explicit interpreter supplied by the image.

Git administration data is excluded and no Git command is executed against the
supplied repository. Repository-local Git configuration is therefore never a
host-execution surface. Content identity, not VCS metadata, is the provenance
anchor in V0.1.

### Deterministic Index

`indexing.py` creates `repository-index-v1` using
`deterministic-lexical-index-v1`.

- Files, hashes, sizes, language labels, line counts, token counts, exclusions,
  and extracted symbols use stable ordering.
- Python symbols use the standard-library AST.
- C, C++, Go, Java, JavaScript, TypeScript, Rust, Ruby, and PHP use bounded
  lexical extractors.
- Oversized, binary, and unsupported-encoding files remain in the manifest but
  are not content-indexed.
- Per-file text, token, symbol, and Python-AST traversal limits bound work.
  Global file-record, token-entry, symbol, JSON-byte, and symbol-token budgets
  keep the emitted index below its JSON loader limits; every configured limit
  and any global budget exhaustion are recorded in the index.

The index stores token vocabulary and symbol metadata, so it is customer data
even though it does not store complete source files.

### Candidate Ranking

`ranking.py` creates `candidate-set-v1` using transparent integer scores. Exact
reported paths, symbols, and overlapping source regions receive the strongest
weights, followed by path, identifier, symbol, and message-token matches. Test
paths receive a deterministic penalty unless directly reported.

Candidates are sorted by score and explicit stable tie-breakers before `top_k`
selection. Scores and confidence basis points are evidence descriptors, not
probabilities.

Score-reason match evidence has a single producer, verifier, and schema bound
of 20. Match arrays are unique, non-empty, and canonically sorted; empty match
arrays are omitted. V0.1.1 formalises the evidence already emitted by the
ranking algorithm without changing its integer scores or candidate ordering.

### Qualified Docker Reproduction

`sandbox.py` accepts only an explicit `reproduction-plan-v1`. SARIF content is
never converted into a command. Plan steps use argv arrays and canonical
relative working directories; Lumi Trace does not apply host-shell parsing.

The selected digest-form image reference must already exist in a Linux
Docker-compatible daemon reached through a local Unix socket or local-machine
Windows named pipe. The sandbox resolves it to an immutable image ID, uses
`--pull never` and `--network none`, mounts the snapshot read-only at `/repo`, removes
capabilities, sets no-new-privileges and a non-root identity, bounds resources,
forces the declared executable as entrypoint, disables image healthchecks and
daemon logs, rejects image volumes, and provides only a temporary `/tmp`.

Before any step, the same image is qualified through `/bin/sh`. The probe
requires non-root execution, no non-loopback IPv4 or IPv6 route, a non-writable
`/repo`, no exposed engine socket or host credential mount, cleared sensitive
environment, and a zero core-file limit. Qualification or setup failure
produces structured unsupported evidence; there is no host fallback.

### Classification and Reporting

`reporting.py` classifies evidence deterministically:

- `CONFIRMED` requires a qualified sandbox, attested `none` network mode,
  unchanged repository identity, completed steps, and every explicit witness;
- `UNSUPPORTED` records a reproduction outside the V0.1 support boundary; and
- `INSUFFICIENT_EVIDENCE` records no plan, missing evidence, witness failure,
  timeout, output limit, immutability failure, or infrastructure failure.

`reporting.py` builds `evidence-bundle-v1` and exports SARIF 2.1.0. SARIF
contains relative paths, symbols, source regions, ranks, scores, and reason
codes, but no source snippets.

### CLI and Packaging

`cli.py` exposes import, index, rank, reproduce, full trace, export, validation,
and verification commands. `pipeline.py` writes the normalized finding,
repository index, candidates, evidence bundle, SARIF report, optional
normalized reproduction plan and receipt, and a manifest of artifact hashes.

## Deterministic Identities

`canonical.py` serialises canonical identity input as compact, sorted, ASCII
JSON with non-finite numbers rejected. SHA-256-derived IDs bind findings,
repository manifests, indexes, candidates, plans, receipts, bundles, and
packages to their content. Human-facing JSON is pretty printed, while identity
calculation always uses the canonical representation.

Determinism excludes runtime-specific provenance such as the Python version
from cross-host identity only where the relevant contract defines that
exclusion. Repeated claims should compare artifact hashes, not assume that all
runtime telemetry is cross-platform identical.

## Data Boundary

The disposable clean-room snapshot is deleted after the operation. Evidence
outputs remain in the user-selected local directory. No output is uploaded.

Outputs can still reveal customer finding text, relative paths, symbols, token
vocabulary, hashes, reproduction metadata, and optional
bounded process output. They must remain local and access-controlled unless the
customer separately approves disclosure.

## V0.1 Limits and TODOs

- Non-Python symbol extraction is lexical and incomplete.
- V0.1 does not discover vulnerabilities or generate repairs.
- No learned ranker exists; deterministic recall must be established before
  `TRACE-001` can be reconsidered.
- The CLI's built-in `validate` command checks runtime invariants and canonical
  identities; full Draft 2020-12 schema validation remains a release/CI check.
- Container isolation depends on the local kernel and Docker-compatible daemon;
  it is not a virtual-machine boundary.
