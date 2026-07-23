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

Trace-Eval contains no learned model, weights, training data, trainer, or
frozen-holdback execution command. Its V0.3 recommendation is
`DO_NOT_BEGIN_TRACE_001`.

The V0.3-only command additions are:

```text
trace-eval code metric-specification --output FILE
trace-eval ir normalise INPUT --output PACKAGE
trace-eval ir rank PACKAGE --output RESULT_PACKAGE
```

Trace IR labels remain evaluator-only and are not accepted by either runner
command.

Skylark-owned source is licensed under Apache-2.0. See the repository root
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
