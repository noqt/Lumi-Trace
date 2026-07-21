# Skylark Lumi Trace Eval

Trace-Eval is the isolated deterministic evaluation and training-readiness
qualification harness for Lumi Trace. It verifies and invokes the exact V0.1
runtime as a subprocess, enforces governed registry and exposure policy, seals
raw outputs before scoring, computes locked metrics, and supports replay.

Trace-Eval contains no learned model, weights, training data, trainer, or
frozen-holdback execution command. Its V0.2 recommendation is
`DO_NOT_BEGIN_TRACE_001`.

Skylark-owned source is licensed under Apache-2.0. See the repository root
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
