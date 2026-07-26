# Lumi Trace V0.4 Model Card

## Status

Lumi Trace V0.4 produced one governed private TRACE-001 experiment. It was not
selected for qualification or product integration because it did not beat the
locked sparse comparator on grouped model selection.

| Field | Value |
| --- | --- |
| Inventory identity | `skylark.lumi.trace` |
| Model status | `EXPERIMENTAL_PRIVATE_NOT_SELECTED` |
| Product runtime | Deterministic Lumi Trace 0.1.2 |
| Checkpoint | Private governed canonical JSON; not packaged or published |
| Active learned parameters | 8 |
| Skylark-trained parameters | 8 |
| Training groups | 541 |
| Training repository families | 317 |
| Foundation model | None |
| Tokenizer | None |
| External or downloaded weights | None |
| Hosted inference | No |
| API keys required | No |
| Public weight release | Not authorised |

The Apache-2.0 repository licence applies to Skylark-owned source code, not to
the private checkpoint or governed training corpus.

## Model and Product Boundary

TRACE-001 is a from-scratch pairwise linear candidate reranker. It receives
eight numeric features from the deterministic, finding-guided Python candidate
pipeline. It does not snapshot repositories, execute reproduction plans,
classify evidence, generate repairs, discover vulnerabilities, or make final
product decisions.

The shipped Lumi Trace runtime remains deterministic. No checkpoint is present
in the repository, wheel, or source distribution, and runtime commands do not
load TRACE-001.

## Training

Every Section 17 entry gate passed before training. The training partition was
sealed before feature design and contains 541 rights-approved groups across
317 repository families. Every group is bound to an item-level audit card,
controlled blind-label review, immutable source and revision evidence, and
poisoning, secret, privacy, provenance, leakage, lineage, and duplicate checks.

Training ran locally on CPU for 12 epochs with at most 2,000 candidates and 256
pairs per group per epoch. Two clean runs reproduced the same checkpoint:

- 1,522,092 pair updates;
- 336.36 CPU seconds and 340.41 wall seconds for both clean runs;
- 210,632,567 bytes peak Python-traced memory;
- 1,115-byte canonical full checkpoint; and
- eight active numeric parameters.

The first authorised command failed before optimisation because a monolithic
training-data identity exceeded the hardened canonical JSON item bound. No
checkpoint was written. The failure was recorded, identity construction was
changed to bounded per-group identities plus one aggregate identity, the code
lock and Section 17 gate were superseded, and the successful run used that
remediated lock.

The int8 projection achieved 0.93 top-one agreement against a required 0.95
and therefore failed its regression gate.

## Evaluation

The strongest deterministic comparator was sparse.

| Partition and candidate | File Recall@20 | Role Recall@20 | MRR | Family-macro Recall@20 |
| --- | ---: | ---: | ---: | ---: |
| Development, sparse | 0.728 | 0.316 | 0.405 | 0.762 |
| Development, TRACE-001 | 0.620 | 0.215 | 0.328 | 0.783 |
| Model selection, sparse | 0.809 | 0.450 | 0.549 | 0.725 |
| Model selection, TRACE-001 | 0.718 | 0.313 | 0.465 | 0.672 |

On model selection, TRACE-001 improved two families and regressed five.
Identifier ablation reduced File Recall@20 to 0.275. The learned candidate did
not meet the material-gain, safety-preservation, or cue-ablation selection
rule, so sparse—not TRACE-001—was locked for qualification.

The single-use qualification partition contained 202 groups from 10 families
and 202 matched safe controls. Sparse achieved:

- target indexability 1.000;
- File Recall@5/10/20 of 0.644, 0.767, and 0.866;
- location-role-correct Recall@20 of 0.559;
- MRR 0.509;
- hard-negative outrank 0.211;
- wrong-location-role top one 0.252;
- family-macro Recall@20 0.978; and
- minimum-family Recall@20 0.855 with zero zero-recall families.

It failed the locked Recall@5, location-role, hard-negative, and wrong-role
gates. False supported disposition, false vulnerability on matched safe
controls, and unsafe non-abstention were zero observed; confidence intervals
in the evidence seal must be used instead of interpreting zero observations
as zero underlying risk.

## Intended and Out-of-Scope Use

The checkpoint is retained only as a negative private experiment for audit and
future research comparison. It is not authorised for customer use, product
integration, pilot deployment, public inference, weight release, or further
training under V0.4.

Lumi Trace 0.1.2 remains intended for authorised, customer-local finding
normalisation, deterministic location ranking, bounded network-denied
reproduction, and evidence export. It does not certify repositories as safe,
generate repairs, detect attacks, or replace human security review.

## Lineage and Exclusions

TRACE-001 was trained from scratch and does not inherit or incorporate:

- `CKPT-003`;
- rejected Lumi V2.7 adapters or protected holdback material;
- CyberGym tasks or task contents;
- customer evidence;
- hosted inference output; or
- an external model, tokenizer, adapter, or weight file.

The protected V0.4 holdback remains sealed and unopened.

## Limitations

The experiment is Python-only, finding-guided, and limited to candidates
produced by the deterministic index. Training and evaluation families are
public-source-heavy and are not evidence of every customer repository shape.
Role discrimination, hard-negative ordering, and early precision remain below
the locked product gates. The negative result does not show that all learned
rankers are ineffective; it shows that this exact eight-parameter experiment
did not justify advancement under the frozen V0.4 design.

## Licensing and Release

The checkpoint licence is
`INTERNAL_EVALUATION_ONLY_PENDING_USER_RELEASE_DECISION`. There is no public
weight licence, no packaged weight file, and no weight-publication authority.
Any future release requires a separate explicit licence, publication review,
model card, reproducible inference package, data information, evaluation
manifests, and user approval.
