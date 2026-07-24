# Lumi Trace V0.3.2 Model Card

## Status

Lumi Trace V0.3.2 evaluates the separately versioned V0.1.2 deterministic
local vulnerability-evidence instrument. It is **not an ML model**.

| Field | Value |
| --- | --- |
| Inventory identity | `skylark.lumi.trace` |
| Model status | `PROPOSED_NOT_TRAINED` |
| Checkpoint | None |
| Weight files | None |
| Active learned parameters | 0 |
| Skylark-trained parameters | 0 |
| Training data | None |
| Hosted inference | No |
| API keys required | No |

This document reserves an inventory identity and records the absence of a
model. It must not be used to imply that a Lumi Trace checkpoint, learned
ranker, or trained AI artefact exists.

## Runtime and Evaluation Behaviour

V0.1 imports a SARIF or manually supplied vulnerability finding, indexes a
user-supplied local repository, retrieves and ranks candidate files, symbols,
and locations with deterministic rules, optionally attempts bounded local
reproduction, and emits an auditable evidence package.

The candidate ranking is a deterministic baseline. Its scores are produced by
documented program logic and are not probabilities or learned predictions.
The runtime does not call a model provider, use hosted inference, or require an
API key.

V0.2 through V0.3.2 add no learned component. Trace-Eval measures each pinned
runtime wheel in a separate environment using rights-bound registries,
label-blind subprocess runs, raw-output sealing, reproducible metrics, and
replay. V0.3.1 natural labels and source snapshots are private evaluation
evidence. They are not training data and are not included in this repository.

V0.3.2 preserves the failed V0.3.1 result, repairs its runtime contract and
bounded resource envelope, establishes a valid 40-group baseline, and evaluates
the V0.1.2 deterministic recovery under a separately versioned metric
specification. The exact development and qualification outcome is recorded in
the disclosure-safe V0.3.2 evidence seal. No deterministic result is evidence
that a learned model exists.

## Intended Use

Lumi Trace V0.1 is intended to help an authorised user collect local evidence
about an existing vulnerability finding. It may be used to:

- normalise SARIF or manual findings;
- locate potentially relevant files and symbols;
- run explicitly bounded reproduction instructions in a network-denied local
  sandbox; and
- export JSON and SARIF-compatible evidence for human review.

The user remains responsible for repository access, permission to execute any
reproduction instruction, and interpretation of the resulting evidence.

## Out-of-Scope Use

V0.1 does not scan for new vulnerabilities, generate repairs, act as a SIEM,
make an exploitability guarantee, or replace human security review. It must not
be represented as a trained vulnerability model.

## Training and Lineage

No training or fine-tuning was performed for V0.1 through V0.3.2. No model
weights were downloaded. No training dataset, learned adapter, or checkpoint
is included. Governed V0.3.1 evaluation labels have
`future_training_use_permitted: false` and do not satisfy the 500-group,
25-repository-family, holdback, rights, or lineage gates.

Lumi Trace does **not** inherit or incorporate:

- `CKPT-003`;
- rejected Lumi V2.7 adapters;
- protected V2.7 holdback material;
- customer evidence; or
- CyberGym tasks or task contents.

The proposed future `TRACE-001` direction is a compact code-location ranker.
V0.3.2 supplies conditional programme authority only after every evidence gate
passes. Those data, rights, lineage, and holdback gates remain unmet, so
training must not begin until every gate in
[`TRAINING_READINESS.md`](TRAINING_READINESS.md) is satisfied and separate
execution authority is recorded for the resulting locked experiment.

## Limitations

The deterministic baseline can miss relevant implementations, rank unrelated
locations highly, or be unable to reproduce a finding. A `CONFIRMED` result is
limited to the recorded command, environment, repository identity, and
observations. `UNSUPPORTED` and `INSUFFICIENT_EVIDENCE` are abstentions, not
proof that a repository is safe.

Reproduction executes untrusted repository content. Network denial reduces
one class of risk but does not make execution harmless. Users should run Lumi
Trace only on systems and repositories they are authorised to test and should
review the local sandbox boundary before execution.

## Licensing

Skylark-owned V0.1 source code is licensed under Apache-2.0. That source-code
licence does not license future weights, checkpoints, training data, customer
data, third-party repository content, or protected Lumi evidence. See
[`OPEN_SOURCE_BOUNDARY.md`](OPEN_SOURCE_BOUNDARY.md) and the repository's
third-party notices.
