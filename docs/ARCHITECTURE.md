# Lumi Trace architecture

## Design Goal

Lumi Trace turns one supplied known security finding and one local repository
snapshot into deterministic, auditable location and reproduction evidence. The
released runtime uses deterministic ranking and keeps repository source local.

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
A full `trace` pipeline run requires exactly one selected SARIF result. `triage.py` is the bounded batch composition: it normalises all selected report results, materialises and indexes the repository once, calls the unchanged product localisation projection for each valid result, then aggregates only the already-emitted candidate paths. It does not compare or sum scores from separate findings.

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
anchor.

### Deterministic Index

`indexing.py` creates `repository-index-v1` using
`deterministic-lexical-index-v4`. Python declaration extraction implements a
fixed lexical front end with ASCII declaration identifiers and explicit Python
3.11 f-string exclusions. It passes only declaration, decorator and f-string
expression projections to the CPython grammar validator. Each projection is
capped at 16,384 characters, 512 non-whitespace work units, 2,048 AST nodes and
128 AST levels. AST nodes never supply symbols, names or ranges. Current
execution requires CPython 3.11 or 3.12 with a recursion limit of at least
1,000.
Historical index profiles remain verification-only and are documented in the
[schema compatibility reference](reference/SCHEMA_COMPATIBILITY.md).

- Files, hashes, sizes, language labels, line counts, token counts, exclusions,
  and extracted symbols use stable ordering.
- Python symbols use `python-lexical-v1`. Files with unsupported or ambiguous
  declaration, string, f-string, bracket, continuation or indentation
  structure, over-limit projections, and context-sensitive `await`/`yield`
  projections remain indexed as files without partial symbols. The extractor
  is not a whole-file Python compiler: a lexical declaration may still be
  recorded when an unrelated statement is semantically invalid.
- C, C++, Go, Java, JavaScript, TypeScript, Rust, Ruby, and PHP use bounded
  lexical extractors with fixed ASCII regular-expression semantics.
- Successful current-profile runs require printable-ASCII repository paths.
  This keeps path normalization and classification independent of the Unicode
  database bundled with the host Python runtime.
- Oversized, binary, and unsupported-encoding files remain in the manifest but
  are not content-indexed.
- Per-file text, token, symbol, Python-source-line, bracket-depth and f-string
  nesting limits bound lexical work. Parser projections are separately capped
  at 16,384 characters, 512 non-whitespace work units, 2,048 AST nodes and 128
  AST levels. Global
  file-record, token-entry, symbol,
  JSON-byte, JSON-item and symbol-token budgets keep the emitted index below
  its loader limits; every configured limit and any global budget exhaustion
  are recorded in the index.
- Global token and symbol budgets are allocated in a deterministic role-aware
  order: implementation source, then test/example source, other text, and
  finally documentation/localisation observations. Records return to canonical
  path order before identity calculation. This prevents early observational
  text from starving later implementation files while retaining hard ceilings.

The index stores token vocabulary and symbol metadata, so it is customer data
even though it does not store complete source files.

### Candidate Ranking

`ranking.py` creates `candidate-set-v1` using transparent integer scores. Exact
reported paths, symbols, and overlapping source regions receive the strongest
weights, followed by path, identifier, symbol, and message-token matches.
Unreported test, fixture, generated, and vendor candidates receive a visible,
scale-aware `ROLE_PRECISION` demotion. Exact reported paths and symbols are
exempt, strong source signals can outweigh the demotion in ranking, and no
candidate is excluded by this rule.

Candidates are sorted by score and explicit stable tie-breakers before `top_k`
selection. The current profile admits at most two candidates from any one path, preventing
symbols from one lexical decoy from consuming the bounded file-retrieval set
while retaining both file and symbol evidence. Scores and confidence basis
points are evidence descriptors, not probabilities.

Score-reason match evidence has a single producer, verifier, and schema bound
of 20. Match arrays are unique, non-empty, and canonically sorted; empty match
arrays are omitted. The current `deterministic-candidate-ranking-v2` profile
uses path-diverse selection.

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
- `UNSUPPORTED` records a reproduction outside the supported boundary; and
- `INSUFFICIENT_EVIDENCE` records no plan, missing evidence, witness failure,
  timeout, output limit, immutability failure, or infrastructure failure.

`reporting.py` builds `evidence-bundle-v1` and exports SARIF 2.1.0. SARIF
contains relative paths, symbols, source regions, ranks, scores, and reason
codes, but no source snippets.

### CLI and Packaging

`cli.py` exposes import, index, rank, reproduce, full trace, batch triage, export, validation,
and verification commands. `pipeline.py` writes the normalized finding,
repository index, candidates, evidence bundle, SARIF report, optional
normalized reproduction plan and receipt, and a manifest of artifact hashes.
`triage.py` writes one shared index, per-result candidates and bundles, a unique-path review queue, combined SARIF, bounded result-local errors, and a manifest that binds the aggregate package. `verify` recomputes queue and SARIF projections from the per-result evidence.

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

## Current limitations

- Non-Python symbol extraction is lexical and incomplete.
- Lumi Trace does not discover vulnerabilities or generate repairs.
- No learned ranker or model weights are part of the released product.
- The CLI's built-in `validate` command checks runtime invariants and canonical
  identities; full Draft 2020-12 schema validation remains a release/CI check.
- Container isolation depends on the local kernel and Docker-compatible daemon;
  it is not a virtual-machine boundary.
