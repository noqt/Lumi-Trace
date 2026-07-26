# Skylark Lumi Trace Eval

Trace-Eval is the isolated deterministic evaluation and training-readiness
qualification harness for Lumi Trace. It verifies and invokes the exact V0.1
runtime as a subprocess, enforces governed registry and exposure policy, seals
raw outputs before scoring, computes locked metrics, and supports replay.

V0.3 adds exact location-role semantics, vulnerable/safe dispositions,
safe-control and hard-negative accounting, repository and repository-family
macro views, and a separate Trace IR lane for inert copied event packages. The
IR lane has no live integration or response-action interface.

V0.3.1 adds proposal-before-fetch intake, separate use-rights dimensions,
inert exact-revision Git acquisition controls, revision-pair and cue contracts,
controlled natural-group review, corpus distributions, pre-run seals,
predeclared threshold decisions, and a one-run qualification budget. The
package contains no repository catalogue or natural corpus; those remain on
governed private storage.

V0.4 adds enforceable data-state transitions, item-level rights matrices,
bounded quarantine, controlled blind labels, audit cards, lineage and
cross-partition duplicate checks, disclosure-safe projections, strengthened
family-aware metrics, label-blind candidates, frozen lexical and sparse
comparators, and a final audit-card allowlist for preprocessing.

V0.4 also contains a bounded from-scratch linear `TRACE-001` experiment. It has
no foundation model, tokenizer, hosted service, remote code, or download path.
The training entry point remains fail-closed unless every final Section 17 gate
is identity-matched and passed. V0.4 fulfilled that gate once, retained a
reproducible eight-parameter private checkpoint, and recorded
`NO_MODEL_ADVANTAGE` after it underperformed sparse on model selection. Sparse
then failed four locked gates in single-use qualification. Any checkpoint,
private features, natural
corpus, qualification result, and protected partition remain on governed
private storage and are not package data.

There is no protected-holdback execution command.

The V0.3-only command additions are:

```text
trace-eval code metric-specification --output FILE
trace-eval ir normalise INPUT --output PACKAGE
trace-eval ir rank PACKAGE --output RESULT_PACKAGE
```

Trace IR labels remain evaluator-only and are not accepted by either runner
command.

V0.4 assurance commands are:

```text
trace-eval assurance sample-plan --output FILE
trace-eval assurance metric-specification --output FILE
trace-eval assurance scan-quarantine ENTRIES --subject-id ID --output FILE
trace-eval assurance verify-transitions RECORDS
trace-eval assurance validate-card CARD [--rights RIGHTS]
trace-eval assurance seal-partitions CARDS ... --output FILE
trace-eval assurance training-admission CARDS ... --output DIRECTORY
```

Skylark-owned source is licensed under Apache-2.0. See the repository root
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
