# Lumi Trace V0.4.1 Development Model Card

## Status

Lumi Trace V0.4.1 contains product support for a private development ranker,
but no model weight is included in the repository, wheel, or source
distribution. The candidate has not entered fresh model selection or
qualification and is not authorised for customer or public use.

| Field | Value |
| --- | --- |
| Inventory identity | `skylark.lumi.trace` |
| Model status | `PRIVATE_DEVELOPMENT_CANDIDATE_NOT_QUALIFIED` |
| Product runtime | `lumi-trace-runtime-v0.4.1-pre-release.8` |
| Product package | `0.4.1` |
| Checkpoint | Private governed canonical JSON; not packaged or published |
| Active learned parameters | 10,455 |
| Skylark-trained parameters | 10,455 |
| Training groups | 506 |
| Training repository families | 303 |
| Foundation model | None |
| Tokenizer | None |
| External or downloaded weights | None |
| Hosted inference | No |
| API keys required | No |
| Public weight release | Not authorised |

The Apache-2.0 repository licence applies to Skylark-owned source code. It does
not license the private checkpoint or governed training corpus.

## Architecture and Product Boundary

The candidate is a from-scratch sparse integer pairwise linear ranker over
16,384 deterministic hash buckets. Features are built only from the normalized
finding, repository-visible paths and symbols, source-visible role classes,
and deterministic baseline score components.

Product inference first generates and ranks deterministic candidates. The
learned route may rerank only the deterministic top 1,000 candidates—the same
support used for training—and applies a fixed bounded hybrid contribution.
The remaining deterministic tail cannot be promoted by unseen learned
features. The model is loaded from canonical JSON, verified by artifact
identity, and hash-bound into the inference request.

The model does not:

- receive target paths, target symbols, fixed-revision data, scorer labels, or
  qualification state;
- execute repository code;
- use a tokenizer, external model, remote code, hosted inference, or network;
- snapshot repositories, reproduce findings, classify final evidence, generate
  repairs, or discover vulnerabilities; or
- provide a safety, exploitability, or remediation decision.

The isolated evaluation builder denies out-of-root file access, sockets, and
subprocess creation after installing its inference policy. Labels are revealed
only to a separate scorer after the raw ranking seal verifies.

## Training

Training used regenerated, label-blind candidates from the governed V0.4
training sources after the contaminated V0.4 derivatives were invalidated.
Only groups whose accepted target was present in the deterministic top-1,000
support were used. The resulting training set contained 506 groups across 303
repository families.

The family-balanced pairwise integer perceptron ran for 16 epochs and recorded
10,806 pair updates. Two clean CPU runs produced byte-identical canonical model
artifacts. The private receipt records:

- exact training replay: true;
- active parameters: 10,455;
- foundation model and tokenizer: none;
- external weights downloaded: false;
- network required: false; and
- public weight release authorised: false.

The checkpoint identity is
`lumi-trace-localization-model:c04f15d502040bb0a18715d367a58b16726ecf4a331e27e77de46e58dcff1745`.
This identity is disclosed for traceability; the checkpoint contents remain
private.

## Development Evaluation

All reported V0.4.1 development runs use the product implementation and seal
raw rankings before scorer labels are opened. Early learned-only inference was
retained as a failed experiment because it allowed candidates outside the
training support to compete and materially regressed capability.

The remediated hybrid route restricts learned scoring to the trained support
and preserves deterministic score authority. Its guarded product run completed
148 of 158 scheduled engineering-development groups; nine attempts reached the
bounded runtime timeout and one failed closed in semantic review. Final
evidence counts all ten unsuccessful attempts in the capability denominators.

Two larger, stricter-margin sparse variants were reproduced and screened over
the 151 current deterministic base rankings. Neither reached the predeclared
0.03 material-gain threshold without a greater than 0.01 regression on a
protected metric, so the smaller 10,455-parameter reference was retained. This
is a development recommendation, not model selection.

Development results are not model-selection or qualification evidence. No
fresh partition was opened, no qualification capacity was consumed, and the
protected holdback remains sealed and unopened.

## Intended and Out-of-Scope Use

The checkpoint is retained for governed V0.4.1 development and future fresh
model selection once the independent data-supply gate is satisfied. It is not
authorised for customer use, pilot deployment, public inference, publication,
weight release, or qualification.

The packaged deterministic Lumi Trace commands remain intended for authorised,
customer-local finding normalization, location ranking, bounded
network-denied reproduction, and evidence export. They do not certify a
repository as safe, generate repairs, detect attacks, or replace human
security review.

## Lineage and Exclusions

The candidate was trained from scratch and does not inherit or incorporate:

- `CKPT-003`;
- the V0.4 eight-parameter checkpoint;
- rejected Lumi V2.7 adapters or protected holdback material;
- CyberGym tasks or task contents;
- customer evidence;
- hosted-inference output; or
- an external model, tokenizer, adapter, or weight file.

## Limitations

The route is Python-only, finding-guided, and bounded by deterministic
candidate recall. Its evidence is development-only and public-source-heavy.
Fresh model-selection and qualification partitions do not yet meet the
predeclared supply floors. Role discrimination, early precision, family
minimums, confidence bounds, and adversarial readiness must be established on
fresh independent evidence before any capability claim.

## Licensing and Release

The checkpoint licence is
`INTERNAL_EVALUATION_ONLY_PENDING_USER_RELEASE_DECISION`. There is no public
weight licence and no weight-publication authority. Any future release
requires explicit user approval, a public weight licence, disclosure review,
reproducible inference package, training-data information, evaluation
manifests, and verification that every release dependency and foundation
artifact is appropriately licensed.
