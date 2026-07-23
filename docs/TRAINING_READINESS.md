# TRACE-001 Training Readiness

## Recommendation

`DO_NOT_BEGIN_TRACE_001`

As of Lumi Trace V0.3.1, the V0.2 and V0.3 evidence seals and exact V0.1
runtime identity remain verified. A governed pilot admitted 58
evaluation-only groups from 10 unrelated repository families. The full
unchanged V0.1 development run reproduced, but 32 of 40 attempts failed
closed: 28 on a runtime score-reason contract mismatch and 4 on declared
resource limits. The completion-integrity gate declined the baseline,
qualification remained unopened, and the programme closes
`NOT_QUALIFIED / REMEDIATION_REQUIRED`.

The owned-lab Trace IR fixture result `IR_FEASIBILITY_SUPPORTED` establishes
only that the evidence architecture can parse, rank, replay, and score inert
events with matched benign controls. It does not count as natural
candidate-ranking evidence or training data. V0.3 sealing is not training
authority. No training, fine-tuning, weight download, model acquisition,
CyberGym task consumption, or protected-holdback opening is authorised.

## Candidate-Ranking Evidence Gates

| Gate | State | Evidence required before the gate can pass |
| --- | --- | --- |
| At least 500 useful labelled candidate-ranking groups | `UNMET / EVIDENCE_REQUIRED` | 58 evaluation-only groups were admitted; at least 442 additional useful, rights-cleared groups and separate future-training rights are still required. |
| At least 25 unrelated training repositories | `UNMET / EVIDENCE_REQUIRED` | 10 unrelated evaluation repository families were admitted; at least 15 additional unrelated repositories and training rights are still required. |
| Repository-disjoint development and holdback sets | `UNMET / EVIDENCE_REQUIRED` | The pilot has a repository-family-disjoint development/qualification split with zero overlap. It does not create an approved training split or open the protected holdback. |
| Meaningful hard negatives and controls | `UNMET / EVIDENCE_REQUIRED` | The pilot includes natural hard negatives and fixed safe controls, but the invalid development baseline and subscale corpus cannot establish training sufficiency. |
| Audited location and reproduction labels | `UNMET / EVIDENCE_REQUIRED` | Pilot location labels have controlled-review provenance. Reproduction labels were intentionally absent, future training use is false, and full-scale audit evidence is still required. |
| Adequate deterministic candidate recall | `UNMET / REMEDIATION_REQUIRED` | The run produced diagnostic file recall at 20 of 0.15 and target indexability of 0.20, but only 8 of 40 attempts completed. Runtime and resource failures invalidate a capability conclusion. |

The 58 pilot groups are private evaluation evidence, not training data.
Future training use was not granted. No item may be inferred from aggregate
counts alone: rights, provenance, quality, exposure, repository independence,
audit evidence, and a valid deterministic baseline must all be available
before a gate is marked satisfied.

## Future Weight and Release Gates

| Gate | State | Evidence required before the gate can pass |
| --- | --- | --- |
| Explicit weight licence | `UNMET / EVIDENCE_REQUIRED` | A reviewed licence that expressly applies to the proposed `TRACE-001` weights. Apache-2.0 on source code is not sufficient. |
| Trained-model card | `UNMET / EVIDENCE_REQUIRED` | A model card describing the actual trained checkpoint, intended use, limitations, metrics, lineage, and licences. The V0.1 no-model card does not satisfy this gate. |
| Training code | `UNMET / EVIDENCE_REQUIRED` | Rights-cleared, reviewable training code with a reproducible configuration and environment. |
| Training-data provenance and data information | `UNMET / EVIDENCE_REQUIRED` | Dataset manifests, source and licence provenance, collection and labelling methods, filtering, exposure controls, and data information sufficient for audit. |
| Evaluation manifests | `UNMET / EVIDENCE_REQUIRED` | Immutable development and holdback manifests, metric definitions, evaluation configuration, and result receipts. |
| Foundation-model licence verification | `UNMET / EVIDENCE_REQUIRED` | A documented verification of the selected foundation model and every inherited artefact, including compatibility with the intended training and weight release. |
| Reproducible local inference instructions | `UNMET / EVIDENCE_REQUIRED` | Versioned local inference code, environment and hardware requirements, model hashes, commands, and an independently reproducible receipt. |

## Authority Gate

Separate, explicit user approval to begin `TRACE-001` is also
`UNMET / EVIDENCE_REQUIRED`. Completing V0.1, qualifying the V0.2 environment,
completing V0.3 contracts, admitting the V0.3.1 evaluation pilot, opening a
review, or later making the source repository public does not satisfy this
authority gate.

## Reconsideration Rule

The recommendation may change only in a new, reviewable evidence record that:

1. evaluates every gate above individually;
2. cites immutable supporting artefacts and their hashes;
3. confirms that no protected holdback, historical Lumi evidence, customer
   evidence, or unauthorised task material was used; and
4. records separate approval for the proposed training objective.

Until then, the binding recommendation remains `DO_NOT_BEGIN_TRACE_001`.
