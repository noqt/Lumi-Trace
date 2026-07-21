# TRACE-001 Training Readiness

## Recommendation

`DO_NOT_BEGIN_TRACE_001`

As of Lumi Trace V0.1.0, every training-readiness and future-weight release
gate is `UNMET / EVIDENCE_REQUIRED`. V0.1 sealing is not training authority.
No training, fine-tuning, weight download, dataset acquisition, or CyberGym
task consumption is authorised by this repository.

## Candidate-Ranking Evidence Gates

| Gate | State | Evidence required before the gate can pass |
| --- | --- | --- |
| At least 500 useful labelled candidate-ranking groups | `UNMET / EVIDENCE_REQUIRED` | An immutable, rights-cleared manifest demonstrating at least 500 useful groups, their group construction, labels, provenance, and audit status. |
| At least 25 unrelated training repositories | `UNMET / EVIDENCE_REQUIRED` | A rights and provenance manifest demonstrating at least 25 unrelated repositories, including the method used to assess repository independence. |
| Repository-disjoint development and holdback sets | `UNMET / EVIDENCE_REQUIRED` | Immutable split manifests and an overlap audit showing repository-level disjointness across training, development, and holdback partitions. |
| Meaningful hard negatives and controls | `UNMET / EVIDENCE_REQUIRED` | A documented hard-negative and control taxonomy, selection procedure, distribution report, and audit demonstrating that they test ranking rather than repository memorisation. |
| Audited location and reproduction labels | `UNMET / EVIDENCE_REQUIRED` | Label provenance, reviewer receipts, correction history, and an audit covering both source locations and reproduction outcomes. |
| Adequate deterministic candidate recall | `UNMET / EVIDENCE_REQUIRED` | A separately approved recall threshold, repository-disjoint evaluation manifest, reproducible baseline run, and evidence that the deterministic index and retrieval stage meets that threshold. |

No item may be inferred from aggregate counts alone. Rights, provenance,
quality, exposure, repository independence, and audit evidence must all be
available before a gate is marked satisfied.

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
`UNMET / EVIDENCE_REQUIRED`. Completing V0.1, creating a repository, opening a
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
