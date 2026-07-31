# Lumi Trace V0.4.1 - Integrity Remediation and Qualification Recovery Build Brief

Status: `AUTHORISED / POSITIVE-OBJECTIVE RECOVERY`

Date: 2026-07-26

Starting branch:
`codex/lumi-trace-v0-4`

Starting implementation:
`c93d3c792190435cb82e28f01af532be97d9a06a`

Starting draft PR:
`noqt/Lumi-Trace#9`

Starting evidence:
`lumi-trace-v0.4-public-evidence:d5404d104a946046cfce4439e338c8bef9223331f93057a2c3e87e47a4553c3`

Reported V0.4 closure:
`NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE`

Controlled-review disposition:
`REVIEW_FAIL / REMEDIATION_REQUIRED`

## 1. Mission

V0.4.1 must recover a genuinely label-blind, deployable, and independently
defensible Lumi Trace candidate-ranking capability from the useful work in
V0.4.

The primary objective is not to finish another version, produce another seal,
or consume another qualification set. The primary objective is to produce the
strongest honest finding-guided vulnerability-localisation capability that:

- operates on information available during real inference;
- has a credible, evidence-backed probability of passing qualification;
- improves the correct location-role ranking behavior that V0.4 exposed as
  weak;
- is integrated into the actual Lumi Trace runtime rather than existing only
  in evaluation code;
- remains local, bounded, reproducible, secure, and disclosure-safe; and
- survives an adversarial review that attempts to invalidate its evidence.

Codex has authority to hand-hold this objective through ordinary engineering,
data, audit, model, resource, and validation problems. It must remain in the
development loop while a safe, general, in-scope route remains.

Codex must not manufacture a favourable result. It may not rescue a known
answer, weaken a metric, inspect protected evidence, retrofit a case-specific
rule, change a denominator, or spend qualification merely to complete the
milestone.

## 2. Objective hierarchy

When instructions, convenience, schedule, and evidence appear to compete,
Codex must use this hierarchy:

1. Preserve experimental and product integrity.
2. Build a capability that can operate without evaluation-only information.
3. Achieve the locked development and model-selection gates with a credible
   qualification margin.
4. Integrate and validate the selected route in the product runtime.
5. Consume independent qualification evidence only after steps 1 through 4
   pass.
6. Seal and report the result.
7. Treat version completion, branch completion, and PR completion as
   subordinate administrative milestones.

A lower item may never be used to justify compromising a higher item.

## 3. What V0.4 established

V0.4 produced useful evidence and infrastructure:

- 1,228 admitted vulnerable groups with matched controls;
- 367 repository families;
- training, development, model-selection, qualification, and unopened
  holdback partitions;
- item-level rights, provenance, lineage, duplicate, secret, privacy, and
  poisoning records;
- a 541-group, 317-family training partition;
- reproducible CPU-only training of an eight-parameter pairwise linear
  reranker;
- exact replay and a sealed public evidence package;
- zero observed false-supported, false-vulnerability, and unsafe
  non-abstention safety-floor events;
- passing packaging, dependency, licence, secret, formatting, lint, live
  Docker, public-boundary, and evidence-verification checks; and
- a deterministic sparse comparator that outperformed the V0.4 learned
  candidate on grouped model selection.

The narrow model result remains informative:

- sparse model-selection File Recall@20 was 0.809;
- TRACE-001 File Recall@20 was 0.718;
- sparse location-role Recall@20 was 0.450;
- TRACE-001 location-role Recall@20 was 0.313;
- sparse MRR was 0.549; and
- TRACE-001 MRR was 0.465.

This supports only the conclusion that the specific eight-parameter V0.4
ranker did not beat sparse under the V0.4 candidate sets. It does not establish
that compact learned models generally lack advantage.

V0.4 qualification also showed that the selected sparse comparator was close
on some file-ranking measures but materially weak on role discrimination:

- File Recall@5 was 130 of 202, or 0.644, against 0.65;
- File Recall@20 was 175 of 202, or 0.866;
- location-role Recall@20 was 113 of 202, or 0.559, against 0.70;
- hard-negative outrank was 28 of 133, or 0.211, against a maximum of 0.20;
- wrong-location-role top-one was 51 of 202, or 0.252, against a maximum of
  0.15;
- family-macro Recall@20 was 0.978; and
- minimum-family Recall@20 was 0.855.

Those numbers identify role discrimination and top-rank precision as the
primary capability problems, but they are not clean qualification evidence
because of the defect in section 4.

## 4. Controlled-review defect

### 4.1 Ground-truth target access

The V0.4 experiment runner passed `receipt["private_targets"]` into
`_effective_quarantine` before `_candidate_files` and
`build_candidate_features` ran.

The resulting policy,
`v0.4-path-quarantine-except-labelled-target-v2`, removed a quarantined path
when that path was already known to be a ground-truth target.

The ranker did not receive a target bit, but candidate generation received
ground-truth target identity. Therefore:

- the candidate set was label-aware;
- the evaluation path was not end-to-end label-blind;
- the behavior was not deployable because production inference has no target
  label with which to rescue a path;
- target indexability of 1.000 was not established independently of labels;
  and
- qualification outputs were influenced before their raw ranking was sealed.

### 4.2 Observed extent

The final V0.4 artifacts record:

- 114 target-path quarantine overrides in training preprocessing;
- 11 overrides across 10 of 158 development groups;
- 37 overrides across 23 of 131 model-selection groups; and
- 21 overrides across 20 of 202 qualification groups.

Among the 20 affected qualification groups, sparse recorded:

- 19 File Recall@5 successes;
- 19 File Recall@20 successes; and
- 14 location-role Recall@20 successes.

An exact counterfactual has not been run and must not be inferred by simply
subtracting all affected successes. The observed concentration is nevertheless
large enough that the qualification result cannot support a capability
decision.

### 4.3 Root cause

This was not a lack of authority. It was an objective-discipline failure:

- a local indexability gate was optimized using evaluation-only information;
- a policy test blessed the exception instead of challenging its information
  flow;
- the build treated withholding labels from the ranker as equivalent to
  withholding labels from the complete inference path;
- development failures did not stop qualification consumption;
- the eight-parameter model result caused a procedural route change instead of
  a continued bounded development loop; and
- the evaluator-only sparse comparator was described as a deterministic route
  before runtime integration or qualification.

V0.4.1 must correct both the implementation defect and the decision process
that allowed it.

## 5. Binding interpretation of label blindness

Label blindness applies to the entire inference computation, not only the
final scoring function.

Before raw ranked output is sealed, no component may access, derive, compare
against, branch on, or be configured using:

- target paths;
- target symbols;
- target regions;
- candidate target bits;
- vulnerable/fixed diffs;
- fixed-revision-only information;
- private scoring labels;
- reviewer conclusions;
- reproduction outcomes;
- partition outcomes;
- qualification metrics;
- case-specific quarantine exceptions; or
- any stable identity whose membership reveals one of the above.

The inference-side allowed inputs are:

- the normalized finding available to the product;
- the exact repository snapshot presented to the product;
- the declared general candidate policy;
- the locked runtime and model artifacts;
- non-case-specific configuration fixed before the run; and
- bounded system facts required for safe execution.

If a field would not exist when a customer invokes Lumi Trace, it may not
influence candidate generation or ranking.

Labels may be revealed only to a separate scoring process after the raw ranked
candidate artifact has been sealed.

## 6. V0.4 artifact disposition

V0.4.1 must preserve V0.4 unchanged as historical evidence. It must not rewrite
or silently replace the existing seal.

### 6.1 Provisionally reusable

The following may be reused after identity and integrity verification:

- immutable repository objects;
- public-source acquisition receipts;
- rights and licence evidence;
- source-candidate registers;
- advisory and fixing-evidence records;
- repository-family lineage records;
- exact and near-duplicate fingerprints;
- poison, secret, privacy, and public-boundary audit records;
- group-level source provenance; and
- unopened protected-holdback assignments.

Labels are provisionally reusable only after the controlled semantic audit in
section 11. Algorithmic agreement alone is not an independent semantic review.

### 6.2 Must be invalidated and regenerated

The following are derived from a target-aware candidate pipeline and must not
be reused as clean evidence:

- candidate caches;
- candidate-set identities;
- target-indexability results;
- training feature records;
- development feature records and baseline outputs;
- model-selection feature records and baseline outputs;
- TRACE-001 training pairs;
- the private TRACE-001 checkpoint and int8 projection;
- model-selection comparisons;
- qualification raw rankings, aggregates, and decision;
- qualification readiness claims based on those artifacts; and
- pilot-readiness claims.

Retain these artifacts with an explicit `SUPERSEDED_INVALID_EVIDENCE` state.
Do not delete or relabel them as clean.

### 6.3 Partition treatment

- The V0.4 qualification partition is spent and invalid for any future
  qualification. Preserve it sealed as audit evidence.
- Do not inspect its case-level content or use it to tune V0.4.1.
- Aggregate V0.4 qualification observations may be used only to define general
  risk controls, never case-specific features or acquisition targeting.
- The V0.4 model-selection partition is exposed. It may be designated
  `EXPOSED_ENGINEERING_DIAGNOSTIC`, but it may not serve as fresh model
  selection again.
- The V0.4 development and training sources may remain development and
  training sources after label-blind regeneration and audit.
- The protected holdback must remain unopened, unmaterialized for inference,
  and outside every development decision.
- V0.4.1 must acquire new family-disjoint model-selection and qualification
  partitions.

## 7. Codex working contract

### 7.1 Hand-hold the positive objective

Codex must:

- maintain a short current-status record;
- explain in plain language which capability problem is being solved;
- keep resumable queues and immutable receipts for long work;
- diagnose failures at the earliest layer that can explain them;
- choose and execute the next safe bounded experiment without asking the user
  to select routine engineering alternatives;
- prefer measured evidence over assumptions about models or hardware;
- preserve failed experiments as evidence;
- continue through ordinary dependency, data, performance, and implementation
  problems;
- reassess the most direct route to qualification after every material result;
  and
- stop itself from consuming qualification when readiness is not established.

The status record must distinguish:

- evidence integrity;
- data readiness;
- candidate-generation readiness;
- ranking readiness;
- product-runtime readiness;
- model-selection readiness;
- qualification readiness; and
- release readiness.

Passing one state must never imply another.

### 7.2 Broad implementation authority

Within the governed F:/G: workspace, Codex may:

- create a V0.4.1 branch and private work roots;
- edit runtime, evaluator, schemas, tests, scripts, documentation, and CI;
- create or retire derived artifacts;
- rebuild all affected candidate and feature records;
- acquire additional public, permissively usable repository families;
- perform controlled semantic data review;
- improve general secret and quarantine policies;
- implement deterministic role-aware ranking;
- train multiple bounded development candidates;
- use classical statistical, tree, neural, encoder, and hybrid approaches;
- download an external model or tokenizer only after the supply-chain gate;
- use CPU and available local GPU resources when measured and justified;
- install locked dependencies in the approved environment;
- create private checkpoints and quantized projections;
- run local network-denied inference and live Docker tests;
- create evidence, seals, and a draft PR; and
- retry transient failures or replace ineligible data.

Codex need not ask the user to choose hyperparameters, feature variants,
candidate budgets, dependency versions, sampling mechanics, or other routine
bounded engineering decisions.

### 7.3 Prohibited actions

This brief does not authorize Codex to:

- merge a PR;
- create a release or public tag;
- publish or upload weights;
- publish private data or protected evidence;
- change repository visibility;
- inspect or open the protected holdback;
- reuse the spent V0.4 qualification partition;
- weaken a locked metric or threshold after seeing results;
- add case-specific exceptions;
- use target identity anywhere in inference preprocessing;
- execute untrusted repository code during intake or ranking;
- train on customer data without explicit training permission; or
- claim vulnerability discovery, attack detection, exploitability, repair, or
  prevention beyond the tested finding-guided localisation envelope.

## 8. Integrity-remediation architecture

### 8.1 Allowed-field projection

Create a schema-validated inference request containing only allowed fields.
Candidate generation and ranking must run in a process that receives that
projection, not a complete audit card or receipt.

The projection must not contain private labels, fixed-revision data, target
identities, review state, or partition outcome.

Use explicit construction rather than deleting forbidden keys from a larger
object.

### 8.2 Process separation

Use three logical roles with separate workspaces and receipts:

1. **Builder**: creates the inference artifact using only the allowed
   projection.
2. **Scorer**: receives the sealed raw ranking plus private labels and computes
   metrics.
3. **Qualification custodian**: controls the single-use partition, verifies
   locks, invokes the builder without exposing labels, and releases only
   approved aggregate output.

The roles may all be performed by Codex at this stage, but their inputs,
outputs, state, and sequence must be technically separated. The builder may
not read scorer or custodian stores.

### 8.3 Information-flow proof

Produce a machine-verifiable dependency manifest showing every field and
artifact that can influence:

- repository enumeration;
- path quarantine;
- file selection;
- symbol extraction;
- feature construction;
- model input;
- ranking;
- abstention; and
- raw-output sealing.

The manifest must show no path from a forbidden field to an inference output.

Add tests that:

- permute every target and label field while holding allowed inputs constant
  and prove byte-identical candidate and ranking outputs;
- remove all labels and prove inference still completes identically;
- inject canary target paths into forbidden fields and prove they never appear
  in logs, configuration, cache keys, or branch behavior;
- deny filesystem access from the builder to label and fixed-revision roots;
- fail if a builder function accepts an audit receipt or private target field;
- fail if a candidate cache key contains target or scoring identity; and
- verify that scoring begins only after the raw ranking seal exists.

### 8.4 Quarantine policy

Quarantine decisions must be target-agnostic.

If a legitimate production path is incorrectly quarantined:

1. reproduce the false positive using development material;
2. identify a general scanner or classification defect;
3. implement a rule based only on source-visible, non-label facts;
4. test the rule against positive and negative fixtures;
5. rerun secret, privacy, and poison controls;
6. version the policy and invalidate affected caches; and
7. accept the improvement only if it applies equally to target and non-target
   paths.

If no safe general rule exists, the path remains quarantined and the group is
recorded as non-indexable. A target may never be rescued because it is a
target.

## 9. Product-runtime requirement

The selected capability must not exist only under `eval/`.

Before qualification, the exact candidate generator, ranker, model loader,
resource policy, and abstention behavior must be integrated into the Lumi
Trace product runtime with:

- a new runtime and algorithm identity;
- a supported CLI or API invocation;
- schema-validated bounded output;
- deterministic replay;
- offline operation;
- path and output sanitization;
- model and dependency inventory;
- measured CPU latency and peak memory;
- optional GPU acceleration that does not change semantic output;
- packaging in the reproducible wheel and source distribution; and
- compatibility tests against the frozen V0.1.2 behavior.

Evaluation wrappers must call the product implementation. They may not carry a
second private implementation of the selected route.

V0.1.2 remains a frozen comparator. V0.4.1 may assign a new pre-release product
identity, but no release is authorized by this brief.

## 10. Data recovery and new evidence

### 10.1 Rebuild from immutable inputs

Regenerate candidate sets and features from:

- the normalized finding;
- the vulnerable repository snapshot;
- the new target-agnostic quarantine policy; and
- the locked general candidate algorithm.

Only after raw candidates and rankings are sealed may the scorer apply the
private labels.

Every regenerated record must bind:

- source and repository revision identity;
- allowed-field projection identity;
- quarantine-policy identity;
- candidate-algorithm identity;
- runtime identity;
- model or deterministic-ranker identity;
- raw-ranking seal;
- scoring-label identity;
- metric-specification identity; and
- predecessor and invalidation records.

### 10.2 New model-selection evidence

Acquire a fresh model-selection partition with:

- at least 200 useful groups;
- at least 15 unrelated repository families;
- matched safe controls;
- meaningful location-role labels;
- hard negatives in enough groups to support the error-rate gate;
- no family, vulnerability lineage, fixing event, fork, near duplicate, or
  target overlap with training, development, spent qualification, or
  holdback; and
- a predeclared sample and family-balance plan.

Model-selection data may be opened only after the development shortlist and
selection rule are locked.

No more than three candidates may be submitted to one model-selection slice.
If no candidate passes, that slice becomes engineering evidence and a new
independent model-selection slice is required for the next final shortlist.

### 10.3 New qualification evidence

Acquire a fresh single-use qualification partition with:

- at least 250 useful groups unless the sealed power calculation requires
  more;
- at least 15 unrelated repository families;
- matched safe controls;
- adequate hard-negative and role-labelled denominators;
- family-balance controls that prevent a large family from deciding the
  aggregate result;
- no overlap with any development, training, exposed model-selection, spent
  qualification, or holdback material; and
- labels held only by the qualification custodian.

Seal its membership, metric definitions, thresholds, candidate identity,
runtime, dependencies, and decision policy before any inference run.

Qualification may be consumed once. A failed or interrupted run is exposed and
must be retired unless the interruption occurred before any case was opened
and the evidence proves no output or label was revealed.

### 10.4 Protected holdback

Keep the existing protected holdback unopened. Do not generate candidates,
features, previews, counts that reveal case substance, or per-family metrics
from it during V0.4.1.

Opening the holdback requires a separately authorized post-qualification
decision.

## 11. Controlled label audit

The two V0.4 deterministic label functions are algorithmic consistency checks,
not independent semantic reviewers.

V0.4.1 must add controlled semantic review:

- every new model-selection and qualification label receives two blind
  semantic passes;
- each pass runs in a separate workspace and cannot view the other output;
- the reviewer receives source/diff evidence but no candidate ranking, model
  output, partition metric, or earlier conclusion;
- disagreements are adjudicated in a third workspace;
- adjudication records the reasoning and cannot silently overwrite either
  pass;
- all anomalous, override-affected, multi-target, ambiguous-role, parser-edge,
  secret-scan, and large-family groups are reviewed;
- the training and development corpus receives at least one semantic review
  per repository family plus a seeded stratified sample;
- every family with a sampled disagreement expands to a larger audit; and
- unresolved ambiguity causes quarantine or evaluation-only status.

The review process must test:

- whether the fixing diff identifies a vulnerable production implementation;
- whether the selected old-side region is actually security-relevant;
- whether path, symbol, region, and location role are correct;
- whether a test, fixture, wrapper, generated file, vendor copy, or
  documentation path was mistaken for the implementation;
- whether the advisory and fixing event describe the same vulnerability;
- whether multiple valid targets are represented; and
- whether hard negatives are plausible rather than trivial.

Codex must audit the data as if it were deciding whether to train its own
security product on it. Missing, contradictory, or weak evidence remains
quarantined.

## 12. Development ladder

Codex must pursue the capability through the following ladder. It may skip a
stage only when retained evidence proves that stage cannot address the active
failure.

### 12.1 Stage A - clean deterministic candidate generation

Restore label-blind target indexability using only general rules.

Measure:

- repository and file enumeration completion;
- file and role target indexability;
- candidate-set size;
- truncation;
- quarantine false positives and false negatives;
- latency and memory;
- indexability by repository family and tree-size band; and
- candidate-generation failures by reason.

Do not proceed to ranking optimization if target indexability remains below
0.95 overall or has unexplained family-specific collapse.

### 12.2 Stage B - role-aware deterministic ranking

Develop general, interpretable improvements using training and engineering
development evidence. Candidate approaches include:

- separate file-relevance and location-role scoring;
- AST-defined implementation, wrapper, test, fixture, generated, and vendor
  roles;
- structured use of finding evidence;
- role-compatible symbol and call-context features;
- hard-negative penalties;
- calibration and abstention;
- family-balanced feature selection; and
- bounded feature interactions.

Every feature must be available during real inference and pass the answer-
leakage audit.

### 12.3 Stage C - stronger classical learned candidates

If deterministic development remains below readiness, train bounded candidates
such as:

- regularized linear models with explicit feature interactions;
- pairwise or listwise rankers;
- calibrated role classifiers;
- small multilayer perceptrons;
- gradient-boosted or equivalent bounded tree models; and
- hybrid file-ranker plus role-classifier systems.

Use family-balanced training, nested development validation, hard-negative
mining from training/development only, and reproducible seeds.

The V0.4 eight-parameter checkpoint is not a mandatory architecture and must
not constrain the next credible model.

### 12.4 Stage D - compact encoder

If stages B and C establish that structured lexical features are insufficient
and the audited corpus supports the experiment, Codex may evaluate a compact
encoder or equivalent micro-model.

Requirements:

- begin with the smallest architecture justified by a written capacity
  analysis;
- remain at or below one billion active parameters;
- prefer a from-scratch or authoritatively sourced model with reviewable
  lineage;
- pass licence, file-hash, tokenizer, dependency, serialization,
  remote-code, and offline-loading controls;
- remain CPU-capable on a 16 GB workstation, with quantization if needed;
- use GPU only for measured training benefit;
- retain bounded structured output and deterministic policy authority; and
- compare against the strongest clean deterministic route.

### 12.5 Iteration rule

A failed development experiment is evidence, not closure.

After each experiment Codex must:

1. identify whether the limiting layer is indexing, file ranking, role
   discrimination, hard negatives, family generalisation, data quality, model
   capacity, calibration, or infrastructure;
2. record the smallest general remediation;
3. run it on development evidence;
4. compare family-level gains and regressions;
5. check leakage, safety, resource, and reproducibility gates; and
6. continue while a credible bounded route remains.

Codex may not respond to failure by lowering the final gates.

## 13. Metrics and locked capability gates

Retain the V0.4 final capability thresholds unless a stricter threshold is
adopted before new model selection is opened.

At minimum report:

- valid-attempt completion;
- file target indexability;
- role target indexability;
- File Recall@5, @10, and @20;
- location-role-correct Recall@5, @10, and @20;
- MRR;
- hard-negative outrank rate;
- wrong-location-role top-one rate;
- family-macro metrics;
- minimum-family metrics;
- zero-recall family count;
- matched-safe-control false-vulnerability rate;
- false-supported disposition;
- unsafe non-abstention;
- abstention and coverage;
- CPU and optional GPU latency;
- peak memory;
- artifact size; and
- exact replay.

The final locked floors include:

- File Recall@5 at least 0.65;
- File Recall@20 at least 0.85;
- location-role Recall@20 at least 0.70;
- hard-negative outrank no more than 0.20;
- wrong-location-role top-one no more than 0.15;
- family and safety floors no weaker than V0.4; and
- zero false-supported, false-vulnerability, and unsafe-non-abstention events.

File-level performance may not compensate for a failed role, hard-negative,
family, or safety gate.

## 14. Qualification-readiness margins

Being the best available candidate is not qualification readiness.

Before qualification, the selected candidate must pass all final gates on the
fresh model-selection partition and meet the following guard bands:

- File Recall@5 at least 0.68;
- File Recall@20 at least 0.88;
- location-role Recall@20 at least 0.73;
- hard-negative outrank no more than 0.17;
- wrong-location-role top-one no more than 0.12;
- no zero-recall family;
- no unexplained material family regression; and
- all safety floors at zero.

In addition:

- the point estimate must meet the guard band;
- the one-sided 90% confidence bound must remain on the passing side of the
  final qualification threshold;
- two clean product-runtime runs must match exactly;
- resource measures must remain inside the locked envelope;
- no candidate-generation label access may exist;
- the product and evaluator outputs must match by identity; and
- all pre-qualification adversarial-review findings must be closed.

If sample size is insufficient to establish the confidence condition, Codex
must acquire more independent model-selection evidence. It must not spend
qualification to resolve ordinary readiness uncertainty.

## 15. Pre-qualification adversarial review

Before the qualification lock is created, Codex must conduct a stop-the-line
review whose purpose is to invalidate the candidate.

The reviewer role must begin from the source, schemas, runtime, locks, and
allowed aggregate development evidence. It must not rely on the builder's
claim that a control passes.

The review must attempt to prove:

- target or label information can influence preprocessing;
- fixed-revision information reaches inference;
- a cache key leaks target identity;
- scoring occurs before output sealing;
- family, fork, advisory, diff, or target overlap crosses partitions;
- a large family dominates a passing aggregate;
- metric denominators omit failures;
- invalid attempts are excluded favourably;
- matched controls are not actually matched;
- qualification data influenced development;
- evaluator behavior differs from packaged runtime behavior;
- model or dependency identity differs between evidence and runtime;
- nondeterminism is hidden by semantic-only comparison;
- role labels are algorithmic artifacts rather than correct targets;
- resource limits fail on large repositories;
- public evidence leaks protected substance; or
- a claimed product behavior exists only in evaluation code.

Each finding must have a severity, evidence reference, disposition, and
retest. Any unresolved critical or high-severity finding blocks qualification.

## 16. Qualification consumption contract

Qualification is a protected action, but the user need not hand-manage it.
Codex may consume the new partition without further routine approval only when
it has created and verified a qualification-readiness case containing:

- the exact candidate, runtime, dependency, model, policy, and metric locks;
- clean label-blind information-flow evidence;
- model-selection point estimates and confidence bounds;
- guard-band results;
- family and hard-negative coverage;
- two exact product-runtime replays;
- closed adversarial-review findings;
- an unchanged qualification threshold record;
- proof that qualification and holdback remain unopened;
- a single-use execution and interruption policy; and
- a signed decision of `QUALIFICATION_EXECUTION_AUTHORISED`.

If any item is false or unknown, the decision must be
`QUALIFICATION_NOT_READY / CONTINUE_DEVELOPMENT`.

Qualification capacity must not be consumed to learn what development
evidence can answer.

## 17. Candidate selection

Select the route that provides the strongest qualified capability within the
local resource and safety envelope.

A learned candidate advances only if it:

- meets all readiness gates;
- provides a material capability gain over the strongest deterministic
  candidate, particularly on role discrimination or hard negatives;
- preserves family and safety performance;
- reproduces exactly within the declared tolerance and serialization
  contract; and
- has acceptable licence, maintenance, latency, memory, and artifact costs.

If a deterministic route independently meets qualification and a learned
candidate provides no material advantage, integrate and report the
deterministic capability honestly.

`NO_MODEL_ADVANTAGE` alone is not a positive closure. It becomes actionable
only when the deterministic alternative is product-integrated and qualified.

## 18. Hardware and resource authority

V0.4.1 is CPU-first, not CPU-only.

Codex must measure before choosing hardware:

- preprocessing wall and CPU time;
- training wall and CPU time;
- inference latency by repository-size band;
- peak RAM;
- checkpoint and package size;
- disk and cache use; and
- optional GPU utilization, memory, and speedup.

Use CPU for deterministic, classical, and small-model work when practical.
Use an available local GPU when it materially shortens a justified experiment
or enables a credible compact encoder.

The qualified runtime must remain CPU-capable on a 16 GB workstation. GPU
acceleration may be optional but must not change output semantics.

All code, data, models, caches, and evidence must remain on approved F:/G:
roots. Do not place build briefs, corpora, checkpoints, or working artifacts
on C:.

## 19. Security, rights, privacy, and publication

Retain the V0.4 self-use data standard:

- verify item-level training rights;
- keep training permission separate from evaluation and pilot permission;
- treat repository text as untrusted data, never instructions;
- do not execute repository-controlled code during intake, labels, or ranking;
- use immutable revisions and safe parsers;
- reject unsafe archive paths, links, devices, and executable surprises;
- quarantine secrets, credentials, personal data, ambiguous licences, and
  unclear provenance;
- keep raw third-party source, labels, diffs, case identities, private
  rankings, and checkpoints outside the public repository;
- publish only approved aggregates and synthetic fixtures; and
- bind every public artifact to a disclosure review and manifest.

No external model or tokenizer may be downloaded until the supply-chain
record verifies source, revision, licence, files, hashes, format, remote-code
behavior, dependencies, lineage, offline loading, and intended-use
compatibility.

## 20. Required artifacts

V0.4.1 must produce, as applicable:

1. V0.4 controlled-review and invalidation record;
2. predecessor and artifact-disposition manifest;
3. V0.4.1 current-status record and work ledger;
4. allowed-field inference schema;
5. forbidden-field and information-flow manifest;
6. builder, scorer, and qualification-custodian role definitions;
7. target-agnostic quarantine policy;
8. candidate-cache invalidation and regeneration receipt;
9. semantic label-review and adjudication records;
10. revised training and development readiness records;
11. fresh model-selection sample plan and partition seal;
12. fresh qualification sample plan and partition seal;
13. protected-holdback non-access attestation;
14. deterministic candidate and role-ranking identities;
15. model supply-chain records where applicable;
16. training locks, receipts, checkpoints, and reproduction comparisons;
17. product-runtime integration record;
18. package and evaluator parity record;
19. resource bill of materials;
20. development and model-selection summaries;
21. qualification-readiness case;
22. adversarial-review report;
23. qualification lock, single-use receipt, and result if authorized;
24. public-boundary review;
25. model card or deterministic-system card;
26. closure record;
27. reproducible wheel and source distribution;
28. evidence manifest and verifier; and
29. controlled pilot or continuation package.

Every artifact must be identity-bearing, schema-validated where appropriate,
and traceable to immutable inputs.

## 21. Required tests

### 21.1 Label-blind information flow

- inference accepts only the allowed-field projection;
- labels and targets can be absent without changing output;
- permuted labels produce byte-identical candidates and rankings;
- target canaries cannot affect branches, logs, caches, or output;
- builder filesystem access to label and fixed-revision roots is denied;
- candidate generation contains no target allowlist or exception;
- scoring cannot begin before raw-output sealing; and
- qualification labels remain custodian-only.

### 21.2 Quarantine and candidate generation

- generic false-positive remediation applies equally to all paths;
- target and non-target fixtures receive the same policy;
- secrets, credentials, personal data, generated code, vendors, tests, and
  fixtures remain safely classified;
- non-indexable targets are counted, not rescued;
- maximum-candidate truncation is deterministic;
- large trees retain bounded file coverage; and
- cache invalidation follows every policy or algorithm identity change.

### 21.3 Labels and data

- two semantic review workspaces cannot view one another;
- disagreement requires adjudication;
- ambiguous labels fail closed;
- family, fork, lineage, diff, advisory, path, symbol, and near-duplicate
  overlap checks pass;
- rights and licence states fail closed;
- family-balanced sampling verifies;
- matched controls verify; and
- spent and protected partitions cannot enter development.

### 21.4 Models and ranking

- training uses only allowlisted training records;
- family-balanced sampling and seeds reproduce;
- checkpoints use safe bounded serialization;
- no external network is required after acquisition;
- inference is bounded and deterministic;
- feature ablations expose path and identifier shortcuts;
- hard-negative and wrong-role behavior is explicitly tested;
- quantization preserves locked agreement; and
- CPU and optional GPU outputs satisfy the semantic identity contract.

### 21.5 Product integration

- packaged runtime invokes the selected implementation;
- evaluator and product outputs match exactly;
- V0.1.2 comparator remains unchanged;
- CLI and API outputs validate;
- network-denied operation passes;
- wheel and source distributions reproduce;
- installed-package tests pass outside the source tree; and
- Windows and Linux/Docker lanes pass where supported.

### 21.6 Qualification and evidence

- readiness cannot pass while a development gate fails;
- readiness cannot pass without guard bands and confidence bounds;
- readiness cannot pass with an open adversarial finding;
- qualification can be consumed only once;
- interruption behavior fails closed;
- invalid attempts remain in denominators;
- evidence seals bind exact source and artifact membership;
- private paths and substance are excluded from public evidence; and
- the holdback non-access attestation verifies.

## 22. Problem-response matrix

| Problem | Required Codex response |
| --- | --- |
| A target is quarantined | Fix a general source-visible policy or count the group as non-indexable; never use target identity. |
| Label-blind indexability is below 0.95 | Diagnose enumeration and generic quarantine on development data, remediate, and rerun. |
| Development Recall@5 fails | Continue ranking development; do not open model selection or qualification. |
| Role recall or wrong-role top-one fails | Prioritize role-aware features/classification and hard negatives. |
| The linear model fails | Retain the result and advance to the next justified bounded candidate. |
| Sparse beats learned but fails gates | Continue development; do not call it a deterministic route. |
| Deterministic passes and learned adds no value | Integrate, qualify, and report the deterministic capability. |
| Model-selection point estimates pass without confidence | Acquire more independent model-selection evidence. |
| A family dominates results | Rebalance, report macro/minimum metrics, and expand independent families. |
| Label reviewers disagree | Adjudicate independently or quarantine the group. |
| Rights or provenance are unclear | Quarantine or reject; replace with eligible data. |
| CPU is slow | Profile, optimize, quantize, or use GPU for training while retaining CPU inference. |
| GPU is unavailable | Continue deterministic and classical CPU experiments; record the constrained route. |
| A dependency or model needs remote code | Reject it or isolate and separately review it; do not silently enable it. |
| Product and evaluator differ | Block qualification and make the evaluator call the product path. |
| Adversarial review finds leakage | Stop, invalidate affected derivatives, remediate, and repeat the review. |
| Qualification fails | Seal the failure, retire the partition, and do not retry or inspect the holdback. |
| Holdback is accidentally opened | Retire it and acquire a new protected holdback. |
| Public evidence leaks protected data | Stop publication, remediate, rescan, and reseal. |
| A safe bounded route remains | Continue without asking the user to manage routine engineering. |
| Only an external permission or product-scope choice remains | Prepare a precise ready-to-resume package and ask the user. |

## 23. Closure states

### `INTEGRITY_RESTORED / DEVELOPMENT_CONTINUES`

The label-aware path is removed, derived artifacts are invalidated, the clean
pipeline verifies, and capability development remains active.

### `QUALIFICATION_NOT_READY / CONTINUE_DEVELOPMENT`

The system is valid but one or more capability, margin, confidence, runtime, or
adversarial-review gates remain unmet. This is an active state, not completion.

### `QUALIFICATION_READY / LOCKED_CANDIDATE`

All integrity, product, metric, guard-band, confidence, replay, resource, and
adversarial-review gates pass. The single-use qualification package is ready
or authorized to execute.

### `DETERMINISTIC_CAPABILITY_QUALIFIED / CONTROLLED_PILOT_READY`

The product-integrated deterministic route passes independent qualification
and no learned candidate provides necessary additional value.

### `LEARNED_CAPABILITY_QUALIFIED / CONTROLLED_PILOT_READY`

The product-integrated compact learned route provides material advantage,
passes independent qualification, and satisfies local resource and safety
requirements.

### `NARROW_CAPABILITY_QUALIFIED / CONTROLLED_PILOT_READY`

A narrower predeclared repository, finding, role, or vulnerability envelope
passes and is enforced in the runtime.

### `EXTERNAL_BLOCKER / READY_TO_RESUME`

All safe in-scope work is complete and progress requires an external right,
credential, customer approval, unavailable resource, or material product-scope
decision. The exact continuation package is ready.

### `TECHNICAL_ROUTES_EXHAUSTED / USER_DECISION_REQUIRED`

This state is permitted only when Codex has:

- restored clean label-blind inference;
- completed the deterministic role-aware route;
- completed at least one stronger classical learned route;
- evaluated a compact encoder when data and hardware make it credible, or
  recorded evidence that it is not credible;
- acquired the independent evidence that can reasonably be obtained;
- performed root-cause and adversarial reviews; and
- shown that no safe bounded route remains under the declared envelope.

Completing one small failed model is insufficient for this closure.

`NO_MODEL_ADVANTAGE / DETERMINISTIC_ROUTE` is not a permitted final V0.4.1
closure unless the deterministic route is product-integrated and independently
qualified. Use the deterministic qualified closure instead.

## 24. Acceptance criteria

V0.4.1 is complete only when:

1. The V0.4 source and evidence seal verify unchanged.
2. The target-aware candidate-generation defect is recorded and the affected
   artifacts are explicitly invalidated.
3. The inference builder accepts only an allowed-field projection.
4. Candidate generation and ranking are invariant to missing, permuted, and
   canary labels.
5. The builder cannot access labels, targets, fixed revisions, or scoring
   stores.
6. Quarantine policy is general, target-agnostic, versioned, and tested.
7. All affected candidate, feature, model, development, and model-selection
   artifacts are regenerated or retired.
8. V0.4 qualification remains spent and unused for V0.4.1 development.
9. The protected holdback remains unopened.
10. Reused source, rights, lineage, and label records pass the new audit.
11. New model-selection and qualification partitions meet the sample,
    family, control, hard-negative, and independence plans.
12. Controlled semantic label review and adjudication verify.
13. The strongest candidate is integrated into the product runtime.
14. Evaluation invokes the packaged product implementation.
15. V0.1.2 remains an unchanged comparator.
16. Development and fresh model selection pass all final gates.
17. Model selection also passes the qualification-readiness guard bands.
18. Confidence bounds remain on the passing side of final thresholds.
19. Two clean product-runtime runs reproduce exactly.
20. CPU inference fits the declared 16 GB local envelope.
21. Any GPU use is optional for inference and fully recorded.
22. Any external model or tokenizer passes supply-chain review.
23. The adversarial review has no unresolved critical or high finding.
24. A qualification-readiness case verifies before qualification begins.
25. Qualification is consumed no more than once.
26. Invalid attempts and non-indexable targets remain in the proper
    denominators.
27. Family-macro, minimum-family, role, hard-negative, wrong-role, coverage,
    and safety gates are enforced independently.
28. Public evidence contains no protected source, labels, paths, case
    identities, customer data, secrets, or private checkpoints.
29. The closure uses one permitted state from section 23.
30. The user receives a plain-language result and controlled pilot or precise
    continuation package.

Passing tests, producing a seal, or finishing a PR does not by itself satisfy
these criteria.

## 25. Immediate execution order

Codex should begin without further routine design approval:

1. verify the V0.4 head, public evidence seal, private artifact identities, and
   protected-holdback non-access state;
2. create a V0.4.1 branch and approved F:/G: private work roots;
3. preserve V0.4 unchanged and create the controlled-review invalidation
   record;
4. classify V0.4 artifacts as reusable, provisionally reusable, invalid
   derivative, spent, exposed engineering, or protected;
5. implement the allowed-field inference projection and builder/scorer/
   custodian separation;
6. remove the target-path quarantine exception and every equivalent target-
   aware cache or control path;
7. implement information-flow, canary, filesystem-denial, and output-sequencing
   tests;
8. remediate quarantine false positives only through general source-visible
   rules;
9. regenerate training and development candidates from immutable allowed
   inputs;
10. run the controlled semantic audit and quarantine unresolved labels;
11. measure clean indexability and candidate-generation performance;
12. continue the deterministic role-aware development ladder until its
    capability gates pass or retained evidence justifies the next model stage;
13. train and compare stronger bounded learned candidates as needed;
14. integrate each serious finalist into the product runtime before final
    model selection;
15. acquire and seal fresh family-disjoint model-selection evidence;
16. submit the locked shortlist and apply the metric, guard-band, confidence,
    family, safety, and resource rules;
17. if the shortlist fails, convert that slice to engineering evidence,
    diagnose, iterate, and acquire a new fresh slice;
18. acquire and seal the new qualification partition without exposing labels
    to the builder;
19. complete the adversarial review and close every blocking finding;
20. create and verify the qualification-readiness case;
21. consume qualification once only if the decision is
    `QUALIFICATION_EXECUTION_AUTHORISED`;
22. seal the result, system/model card, resource record, public-boundary
    review, and reproducible packages;
23. prepare a controlled-pilot or ready-to-resume package;
24. leave the protected holdback unopened; and
25. create a draft PR if appropriate, but do not merge, tag, release, publish
    weights, or change repository visibility without user approval.

The immediate goal is not another qualification run. It is a clean,
product-real capability with enough independent development evidence that
qualification is the confirmation of a strong candidate rather than an
expensive development experiment.
