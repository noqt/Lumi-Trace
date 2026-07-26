# TRACE-001 Training Readiness and Outcome

## Decisions

V0.4 recorded the binding entry recommendation:

`TRACE_001_EXECUTION_AUTHORISED`

That conditional authority was fulfilled by one bounded, local, from-scratch
experiment. The post-experiment decision is:

`NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE`

V0.4 grants no authority for further training, qualification reuse, pilot
activation, product integration, repository release, or weight publication.

## Section 17 Entry Gate

Every gate was recomputed from identity-bearing evidence before optimisation:

| Gate | Final state |
| --- | --- |
| At least 500 useful training groups | Passed: 541 |
| At least 25 unrelated training families | Passed: 317 |
| Item-level audit cards | Passed |
| Training rights | Passed |
| Lineage and cross-partition duplicate audit | Passed |
| Controlled blind labels | Passed |
| Poisoning, secret, privacy, provenance, and leakage audits | Passed |
| Target indexability at least 0.95 | Passed: 1.000 |
| Candidate presence | Passed |
| Remaining ordering or role gap | Passed |
| Deterministic and simple baselines locked | Passed |
| Objective and metrics locked | Passed |
| Family-disjoint partitions sealed | Passed |
| Model and tokenizer supply chain | Passed: neither used |
| Training code, dependency, resource, and checkpoint locks | Passed |
| Qualification and protected holdback blind | Passed |

The corpus contains 1,228 accepted groups across sealed training,
engineering-development, model-selection, qualification, and protected
holdback partitions. There are zero cross-partition family collisions.

## Execution Record

The first authorised command failed during training-data identity construction,
before optimisation, because one monolithic canonical object exceeded the
hardened one-million-item bound. No checkpoint was written. The failure was
retained as governed evidence.

The remediation preserved the safety limit and changed only identity
construction: each validated group is canonicalised separately, then the
ordered group identities are bound by one aggregate identity. The execution
lock and final gate record were superseded before training resumed.

The remediated experiment:

- trained an eight-parameter pairwise linear ranker from scratch;
- used 541 groups from 317 families;
- ran 12 epochs and 1,522,092 pair updates;
- reproduced exactly across two clean CPU runs;
- used no foundation model, tokenizer, external weights, download, remote
  code, hosted service, API key, CyberGym task, customer evidence, historical
  holdback, or protected V0.4 holdback;
- retained its checkpoint only on governed private storage; and
- left qualification unopened until grouped model selection finished.

The int8 projection failed its 0.95 top-one-agreement gate at 0.93.

## Grouped Selection Decision

TRACE-001 did not beat the locked sparse comparator.

| Model-selection metric | Sparse | TRACE-001 |
| --- | ---: | ---: |
| File Recall@20 | 0.809 | 0.718 |
| Location-role Recall@20 | 0.450 | 0.313 |
| MRR | 0.549 | 0.465 |
| Family-macro Recall@20 | 0.725 | 0.672 |
| Zero-recall families | 3 | 3 |

TRACE-001 improved two families and regressed five. Identifier ablation File
Recall@20 was 0.275. It did not satisfy the locked material-gain,
safety-preservation, and cue-ablation rule, so sparse advanced to
qualification.

## Single-Use Qualification

Qualification was consumed once on 202 groups across 10 families with 202
matched safe controls. No run remains.

| Locked metric | Gate | Sparse result | State |
| --- | ---: | ---: | --- |
| Valid attempts | 1.00 | 1.000 | Passed |
| Target indexability | ≥0.95 | 1.000 | Passed |
| File Recall@5 | ≥0.65 | 0.644 | Failed |
| File Recall@10 | ≥0.75 | 0.767 | Passed |
| File Recall@20 | ≥0.85 | 0.866 | Passed |
| Location-role Recall@20 | ≥0.70 | 0.559 | Failed |
| MRR | ≥0.35 | 0.509 | Passed |
| Hard-negative outrank | ≤0.20 | 0.211 | Failed |
| Wrong-role top one | ≤0.15 | 0.252 | Failed |
| Family-macro Recall@20 | ≥0.80 | 0.978 | Passed |
| Minimum-family Recall@20 | ≥0.60 | 0.855 | Passed |
| Zero-recall families | 0 | 0 | Passed |

False supported disposition, false vulnerability on matched safe controls,
and unsafe non-abstention were zero observed. The sealed Wilson intervals
remain the appropriate uncertainty statement.

## Current Recommendation

Do not integrate or publish TRACE-001. Do not reuse qualification, open the
protected holdback, or begin another training run under V0.4.

The ready continuation route is deterministic and evidence-led:

1. retain the sparse and learned negative results;
2. improve early precision, role discrimination, and hard-negative ordering
   using engineering-development evidence only;
3. source and seal a new independent qualification partition before making a
   new claim; and
4. obtain new user authority before training, qualification, pilot activation,
   release, or weight publication.

## Weight and Release Gates

| Gate | State |
| --- | --- |
| Explicit public weight licence | Unmet |
| Model card for the actual private experiment | Met |
| Reproducible training code and lock | Met |
| Training-data provenance and data information | Met for governed internal evaluation |
| Evaluation manifests | Met |
| Foundation-model licence verification | Not applicable; trained from scratch |
| Reproducible local inference instructions | Met for governed private evaluation |
| Product integration approval | Unmet |
| Public weight release approval | Unmet |

Apache-2.0 covers source code only. The private checkpoint remains
`INTERNAL_EVALUATION_ONLY_PENDING_USER_RELEASE_DECISION`.
