# Lumi Trace V0.2 - Evaluation and Training-Readiness Qualification Build Brief

Date: 2026-07-21

Prepared for: Skylark.AI Lumi Trace

Public repository: `noqt/Lumi-Trace`

Source baseline:

- Release: `v0.1.0`
- Release commit: `04bee651f6347ec3b4b5d3a941029ef8f6bfc48d`
- Inventory identity: `skylark.lumi.trace`
- Model state: `PROPOSED_NOT_TRAINED`; checkpoint none; active parameters 0

## 1. Status and authority

- **Version:** V0.2
- **Version title:** Evaluation and Training-Readiness Qualification
- **Product status:** Research and development; deterministic baseline evaluation
- **Primary environment:** A dedicated `Trace-Eval` environment
- **Training state:** Not authorised
- **Binding training recommendation:** `DO_NOT_BEGIN_TRACE_001`

This brief authorises and bounds the construction of a robust evaluation
environment for Lumi Trace. It does not authorise model training, fine-tuning,
weight acquisition, weight publication, protected-holdback opening, customer
data use, or CyberGym task use.

V0.2 must measure the released deterministic system, establish the quality and
limits of its candidate retrieval and evidence pipeline, and produce the
controlled evidence needed to reconsider the gates listed in
`docs/TRAINING_READINESS.md`.

Completing V0.2 does not itself authorise `TRACE-001`. Training may begin only
after every readiness gate is supported by immutable evidence and a separate,
explicit authority record approves the exact training objective, data,
foundation, environment, and intended weight licence.

## 2. Mission

V0.2 must answer, with reproducible evidence:

1. Does the deterministic snapshot and index contain the labelled source
   location when the repository content is within the supported boundary?
2. How often does deterministic ranking place an accepted target at ranks 1,
   5, 10, 20, and the maximum evaluated depth?
3. How do results vary by repository, repository family, language, CWE,
   finding-input quality, target kind, repository size, and natural versus
   constructed case?
4. Which failures arise in snapshotting, indexing, candidate generation,
   ranking, reproduction, classification, or infrastructure?
5. Do hard negatives distinguish genuine retrieval from path, token, fixture,
   or repository memorisation shortcuts?
6. Are repeated runs and replays identical where the contract requires
   identity, and explicitly comparable where runtime telemetry may vary?
7. What CPU, memory, disk, wall-time, file-count, token-count, and optional
   sandbox resources does each stage consume?
8. Is the available corpus rights-cleared, sufficiently large, audited, and
   repository-disjoint for a later `TRACE-001` decision?
9. Does reproduction remain fail-closed, avoid false confirmation, and abstain
   safely when the evidence contract cannot be satisfied?

The V0.2 outcome is an evaluated deterministic baseline and a readiness
decision record. It is not a trained-model claim.

## 3. Governing decisions

### 3.1 V0.2 is evaluation, not training

V0.2 must not add a learned ranker, download model weights, create adapters,
export training examples to a trainer, or optimise model parameters. The
future-training candidate pool is a governed dataset partition, not permission
to consume it in training.

### 3.2 Trace receives its own environment

Do not run V0.2 inside Yumi's training environment or Lumi Scout's product
environment. `Trace-Eval` must have its own runtime, storage namespace, caches,
environment lock, run root, evidence root, and access policy.

Separation means logical and evidentiary isolation, not rebuilding every sound
control from first principles. Generic control patterns may be reimplemented
for Trace as described in section 5.

### 3.3 The V0.1 release is the first system under test

The first baseline must execute the exact V0.1 release artifact or source
identity recorded above. Evaluation code must not monkey-patch the runtime or
silently substitute local source.

If evaluation exposes a defect or requires a public-runtime change, that
change must be made in the Lumi Trace repository, tested, versioned, and
sealed. Results from different runtime identities must not be combined into a
single baseline.

### 3.4 Public code and governed evaluation material remain separate

Reusable evaluator code, schemas, metric definitions, and synthetic tests may
be public when they pass the Lumi Trace publication boundary. Third-party
repository snapshots, labels, private manifests, run evidence derived from
those repositories, qualification data, and protected holdback material must
remain outside the public source repository.

Public reports may contain only aggregate, disclosure-reviewed results and
non-sensitive identifiers. They must not expose source text, protected task
substance, private paths, customer findings, or information that reconstructs
reserved labels.

### 3.5 Review independence is produced through controls

V0.2 does not require a separate external reviewer merely to create the
appearance of independence. It must create credible separation between
construction and verification through controls:

- labels are created from source evidence, not from Lumi Trace output;
- label and split artifacts are sealed before the scored run;
- the runner cannot read evaluator-only labels;
- a second, blinded review pass checks target and reproduction labels;
- review receipts identify the role, method, input hashes, and decision;
- disagreements and corrections are retained rather than overwritten; and
- automated overlap, leakage, schema, identity, and consistency checks fail
  closed.

The same person or tool may perform more than one role only in separate passes
with sealed inputs and an auditable role-transition receipt. Reports must call
this a **controlled review**, not claim organisational independence that did
not occur.

## 4. System boundary

V0.2 consists of three separated layers:

```text
Lumi Trace runtime under test
    exact versioned wheel/source identity
                |
                v
Trace-Eval runner and verifier
    registry + orchestration + receipts + metrics + replay
                |
                v
Governed evaluation store
    repository snapshots + findings + labels + split manifests
```

The runner should call the installed `lumi-trace` CLI as a subprocess for the
authoritative end-to-end path. Direct Python imports may be used only in
unit-level evaluator tests or through an expressly versioned public interface.

The evaluator must never import the Lumi Scout runtime, read Scout registries,
or discover Yumi model/cache directories.

## 5. Reuse policy

### 5.1 Lumi Scout

The following Scout concepts may be reimplemented in Trace-owned code after a
licence and provenance check:

- immutable registries and registry snapshots;
- development, qualification, and frozen operating modes;
- per-run configuration and provenance receipts;
- replay verification;
- schema-validated run, attempt, result, and aggregate records;
- failure taxonomies;
- split-separated metrics and benchmark reports; and
- fail-closed rights, provenance, and holdback controls.

V0.2 must not reuse or copy:

- CyberGym tasks or task metadata;
- Scout protected holdbacks or fresh evaluation material;
- historical Scout evidence or customer evidence;
- task-specific recognisers, payloads, adapters, or policies;
- patch-generation or repair-outcome contracts; or
- a Scout registry merely renamed as a Trace registry.

Any reusable implementation extracted later should be a small neutral library
with no product data or protected identifiers. Direct dependency on the Scout
repository is not a V0.2 requirement.

### 5.2 Yumi

V0.2 may reuse Yumi's infrastructure principles:

- dedicated environment and storage roots;
- dependency and environment locking after qualification;
- hardware and runtime bill of materials;
- cache and artifact separation;
- resource telemetry;
- immutable evaluation definitions; and
- retained recreation instructions.

V0.2 must not install or require Yumi's GPU training stack, share foundation
weights, adapters, checkpoints, datasets, or caches, or run under `Yumi-Train`.
GPU availability is not a V0.2 success condition.

If `TRACE-001` is later authorised, it should receive a separate `Trace-Train`
environment derived from the Yumi infrastructure blueprint. `Trace-Eval` must
remain separate from that future trainer and retain final scoring authority.

## 6. Environment and storage requirements

### 6.1 Runtime isolation

Create a dedicated environment named `Trace-Eval` or an equivalently explicit
Trace-only name. It must:

- use Python 3.11 as the first reference runtime;
- install the exact system-under-test artifact by hash;
- install evaluator dependencies separately from Lumi Trace runtime
  dependencies;
- avoid system Python and shared editable installs;
- begin offline evaluation only after all approved artifacts are locally
  staged;
- record OS, architecture, Python, package, Docker, and filesystem facts;
- sanitise environment variables and explicitly allow required variables;
- use read-only repository inputs and disposable workspaces;
- set per-case time, output, file, memory, and disk bounds; and
- retain a recreation script and exact dependency lock after qualification.

The primary reference run should use a stable Linux environment, such as a
dedicated WSL2 distribution, because reproduction targets Linux containers.
A Windows compatibility lane should separately verify the supported non-
reproduction runtime. Results from unlike environments must be stratified, not
silently pooled.

### 6.2 Intended storage topology

Evaluation data must not live in the public repository, Yumi directories,
Scout directories, or a synchronised publication path. The preflight may
adjust drive letters, but the roles must remain separate.

```text
F:\Data\skylark-lumi-trace-eval\runtime\       # pinned installed runtime
F:\Data\skylark-lumi-trace-eval\runner\        # evaluator checkout
F:\Data\skylark-lumi-trace-eval\workspace\     # disposable staged cases
F:\Data\skylark-lumi-trace-eval\cache\         # recoverable evaluator cache
F:\Data\skylark-lumi-trace-eval\runs\          # active run outputs
F:\WSL\Trace-Eval\                              # dedicated reference runtime

G:\Data\skylark-lumi-trace-eval\repositories\ # governed immutable snapshots
G:\Data\skylark-lumi-trace-eval\manifests\    # rights, split, and labels
G:\Data\skylark-lumi-trace-eval\artifacts\    # retained seals and reports
G:\Data\skylark-lumi-trace-eval\archives\     # superseded reproducible records
```

Active cases may be staged from retained storage to SSD before execution.
Recoverable caches may be deleted at closure; unique manifests, receipts,
labels, decisions, and aggregate evidence must be retained.

## 7. Operating modes and exposure states

### 7.1 Public-fixture mode

Uses only Skylark-authored or explicitly distributable synthetic fixtures. It
supports CI, schema tests, metric tests, tutorials, and release sealing. It is
not evidence of performance on natural repositories.

### 7.2 Development mode

Uses rights-cleared, development-visible repositories and labels. Ranking and
evaluator changes may be diagnosed here. Every exposure is recorded. Results
must be reported as development results and never as holdback results.

### 7.3 Qualification mode

Uses repository-disjoint cases that were not used to select ranking weights,
rules, thresholds, hard-negative construction, or metric definitions. The
runner is label-blind. Configuration, code, dependencies, metrics, and decision
thresholds are sealed before a qualification run begins.

Qualification labels may be revealed to the scoring service after raw outputs
are sealed. A failed qualification set becomes exposed and must not be reused
as a fresh qualification set for the same decision.

### 7.4 Frozen-holdback mode

Uses a protected, repository-disjoint set whose substance remains unopened to
the builder and runtime. The mode must require a separate authority receipt,
verify every precondition, execute a sealed configuration, and produce a
tamper-evident result package.

This build brief does not authorise opening or running the frozen holdback. No
ordinary CLI flag, environment variable, or file copy may bypass that gate.

### 7.5 Exposure states

Every repository, group, label set, and split manifest must have one of:

- `CONSTRUCTION_VISIBLE`
- `DEVELOPMENT_VISIBLE`
- `EVALUATOR_ONLY`
- `FROZEN_UNOPENED`
- `EXPOSED_AFTER_SEALED_RUN`
- `RETIRED`

State transitions must be append-only, signed or hash-bound to a decision
receipt, and valid only in the permitted direction. `FROZEN_UNOPENED` content
must never transition to a training-eligible state.

## 8. Corpus and split contract

### 8.1 Unit of evaluation

The primary unit is a **candidate-ranking group**. A group binds:

- one immutable repository snapshot;
- one normalized finding input or a reproducible source from which it is
  normalized;
- one or more accepted source-location targets;
- optional reproduction ground truth;
- case taxonomy and difficulty metadata;
- rights and provenance records;
- split and exposure state; and
- label-construction and review receipts.

Multiple accepted targets are allowed when the authoritative evidence supports
multiple equivalent or jointly necessary locations. The matching rule must be
declared before scoring and must not be changed case by case after results are
seen.

### 8.2 Required partitions

The governed corpus must support these repository-disjoint partitions:

- `public_regression`
- `future_training_candidate`
- `development`
- `qualification`
- `frozen_holdback`

A repository, fork, vendored copy, release branch, or near-duplicate lineage
must not cross partitions. Repository independence must be established using
declared origin, fork/lineage evidence, content overlap, shared-history checks
where available, and a recorded manual or controlled-review decision.

Within a partition, a group may be classified as `positive`, `hard_negative`,
or `safety_control`. These case classes are not separate data splits: they
inherit the repository's split and exposure state. This allows each scored
partition to test hard negatives without duplicating a repository across
splits.

No split ratios are to be chosen from convenience alone. V0.2 preflight must
inventory the eligible corpus, model the available strata, and lock a split
plan before labels or results from reserved partitions are exposed.

### 8.3 Training-readiness scale targets

The evaluator must be able to prove or disprove the existing readiness gates:

- at least 500 useful labelled candidate-ranking groups;
- at least 25 unrelated repositories eligible for the future-training
  candidate partition;
- repository-disjoint future-training, development, qualification, and
  holdback partitions;
- meaningful hard negatives and controls; and
- audited location and reproduction labels.

These are evidence targets, not assumptions and not automatic V0.2 release
criteria. If the corpus does not meet them, V0.2 must close with the relevant
gate still `UNMET / EVIDENCE_REQUIRED` rather than inflate counts or weaken the
definition of useful, unrelated, audited, or rights-cleared.

### 8.4 Required group metadata

Each group manifest must include at least:

- stable group, repository, finding, and label-set identifiers;
- repository tree identity and upstream revision or acquisition identity;
- source, acquisition method, licence, rights basis, redistribution status,
  and review status;
- split, exposure state, and lineage/family identifiers;
- natural, constructed, or transformed origin;
- language, CWE, finding format, repository-size band, target kind, and
  difficulty features;
- hashes of every governed input;
- label method, accepted-target semantics, review receipts, and correction
  history;
- hard-negative or control classification where applicable; and
- optional reproduction-plan and expected-outcome identities.

Repository contents and private findings must be referenced by controlled
location and hash, not embedded into a public registry.

## 9. Labels, hard negatives, and controls

### 9.1 Location labels

Location truth should be grounded, in preference order, in:

1. a maintainer-authored fixing revision or reviewed security change;
2. a locally reproduced witness tied to the vulnerable source path;
3. an authoritative advisory plus source inspection; or
4. a constructed fixture with a known source-of-truth generator.

Every target must declare whether it is file, symbol, or source-region truth.
A fix touching many files is not sufficient by itself; the label must identify
the vulnerable or causally relevant location rather than every changed file.

Labels must not be inferred from Lumi Trace's ranking. The labeler should be
blind to candidate order during initial construction and controlled review.

### 9.2 Reproduction labels

Where reproduction is evaluated, the record must distinguish:

- vulnerability reproduced with the declared witness;
- plan valid but witness not observed;
- reproduction unsupported by the V0.1 sandbox contract;
- infrastructure failure;
- intentionally absent plan; and
- insufficient authoritative evidence.

An expected `CONFIRMED` result requires a specific witness and immutable local
container identity. A crash or non-zero exit alone is not confirmation unless
the declared label contract makes it a bounded, unambiguous witness.

### 9.3 Hard negatives

The corpus should contain documented negative families such as:

- same identifier or token in the wrong production file;
- test, example, fixture, generated, or vendored lookalikes;
- neighbouring safe functions with similar symbols;
- common vulnerability vocabulary unrelated to the target;
- paths or symbols mentioned in the finding but absent from the snapshot;
- findings with insufficient location evidence;
- repositories containing the same library name without the vulnerable code;
  and
- transformed cases that preserve irrelevant lexical cues while changing the
  accepted target.

Natural and constructed negatives must be reported separately. A negative is
useful only when its provenance and expected behavior are auditable.

### 9.4 Positive and safety controls

Required controls include:

- exact reported-path cases to verify the strongest documented ranking cue;
- message-only cases with path and symbol fields withheld;
- symbol-only and region-only cases where supported;
- known unindexable targets to test coverage accounting;
- malformed or unsupported inputs that must fail closed;
- no-plan cases that must abstain with `NO_REPRODUCTION_PLAN`; and
- witness-mismatch cases that must never classify as `CONFIRMED`.

## 10. Metrics and variables

### 10.1 Denominators and aggregation

Every metric must state its denominator. Reports must show both:

- micro averages across groups; and
- macro averages across repositories.

The primary decision view is repository-macro performance so a repository with
many similar findings cannot dominate the result. Group-micro performance is
retained for operational capacity planning.

Results must be stratified where sample size permits by repository family,
language, CWE, finding format, target kind, repository-size band, label source,
natural/constructed origin, hard-negative family, and operating environment.
Small strata must show counts and uncertainty rather than a misleading point
estimate.

### 10.2 Snapshot and index metrics

- repository materialisation success rate;
- labelled-target indexability rate;
- exclusion rate by reason;
- file, byte, line, token, and symbol counts;
- index budget exhaustion rate;
- index identity stability across repeats; and
- failures caused by mutation, unsafe paths, encoding, size, or platform.

**Labelled-target indexability** is a prerequisite metric. Ranking recall must
not hide failures by silently dropping unindexable targets from the principal
end-to-end denominator. A conditional indexable-only view may be reported in
addition to, not instead of, the end-to-end view.

### 10.3 Ranking metrics

- file Recall@1, @5, @10, @20, and maximum evaluated depth;
- symbol Recall@1, @5, @10, @20, and maximum evaluated depth for
  symbol-eligible groups;
- accepted-region hit rate under a predeclared overlap rule;
- mean reciprocal rank;
- first-relevant-rank distribution;
- no-relevant-candidate rate;
- target coverage at the maximum evaluated candidate depth;
- hard-negative outrank rate; and
- score-reason distribution for successes and failures.

The maximum evaluated depth, `K_max`, must be locked in the metric
specification, applied consistently, and remain within Lumi Trace's supported
`top_k` bound. Changing `K_max` after reserved results are seen invalidates the
affected comparison.

File, symbol, and region metrics must not be conflated. A file hit is not an
exact symbol or line hit. When several targets are accepted, the group score is
based on the first accepted hit, while target-level coverage is reported
separately.

### 10.4 Reproduction and classification metrics

- sandbox qualification rate;
- plan applicability rate;
- witness observation rate;
- classification agreement with audited ground truth;
- false-confirmation count and rate;
- safe-abstention rate by reason;
- unsupported classification precision;
- timeout, output-limit, setup, cleanup, and infrastructure failure rates; and
- repository-identity preservation rate.

False confirmation is a safety event and must always be reported as an
absolute count as well as a rate.

### 10.5 Reproducibility and reliability metrics

- exact artifact-identity agreement across repeated same-host runs;
- semantic agreement across approved cross-host runs;
- replay verification pass rate;
- schema and manifest verification pass rate;
- unhandled-exception and incomplete-run rate;
- resume/retry accounting; and
- result-package completeness.

Runtime telemetry may vary and must not be forced into cross-host content
identities where the Lumi Trace contract excludes it. Comparisons must identify
which fields are identity-bearing and which are observational.

### 10.6 Resource metrics

Capture per stage and per group:

- wall-clock and CPU time;
- peak resident memory;
- bytes read and written where observable;
- workspace and retained-artifact size;
- file, token, symbol, and candidate counts;
- subprocess and container exit state;
- sandbox setup and execution time; and
- cache state and cold/warm-run classification.

GPU metrics are out of scope unless a future, separately authorised learned
component is under evaluation.

### 10.7 Threshold policy

Metric definitions, decision rules, and thresholds must be locked using only
public-fixture and development evidence. They must be sealed before the first
qualification run and may not be changed after qualification or holdback
results are seen without invalidating that decision run.

The following integrity floors are fixed for V0.2:

- zero unauthorised corpus or split access;
- zero protected-holdback exposure;
- zero false `CONFIRMED` results in audited safety controls;
- 100% manifest, hash, and schema verification for retained decision evidence;
- 100% repository-disjointness under the approved independence procedure; and
- 100% deterministic identity agreement for fields required by the same-host
  repeatability contract.

Ranking-performance thresholds are not invented by this brief. V0.2 must
produce the development evidence and decision record needed to approve them
before qualification. The readiness gate remains unmet if no threshold is
approved or if the sealed run does not meet it.

## 11. Required contracts and artifacts

V0.2 must define schema-validated, canonical identity-bearing records for:

1. environment qualification and dependency lock;
2. repository and rights manifest;
3. candidate-ranking group manifest;
4. label set and correction history;
5. split manifest and repository-independence audit;
6. exposure state and transition receipt;
7. evaluator configuration and metric specification;
8. run, attempt, and case result;
9. raw-output seal;
10. replay-verification result;
11. aggregate metrics and failure taxonomy;
12. controlled-review receipt;
13. qualification decision; and
14. training-readiness decision.

Canonical identities must exclude observational fields only where the schema
expressly declares that exclusion. Every aggregate result must resolve to the
exact runtime, evaluator, registry, split, label, configuration, and raw-output
identities from which it was calculated.

## 12. Runner and command surface

The exact package name may be chosen during implementation. The functional
command surface should include equivalents of:

```text
trace-eval environment qualify
trace-eval registry validate
trace-eval rights verify
trace-eval splits audit
trace-eval labels verify
trace-eval run --mode public-fixture|development|qualification
trace-eval replay RUN_PACKAGE
trace-eval verify ARTIFACT_OR_PACKAGE
trace-eval report RUN_PACKAGE
trace-eval readiness evaluate EVIDENCE_ROOT
```

Frozen-holdback execution must be a separately guarded workflow, not an
ordinary mode selectable by the commands above.

The runner must:

- verify the runtime artifact and all inputs before execution;
- present only runner-visible fields to Lumi Trace;
- run cases in disposable workspaces from read-only immutable sources;
- default to offline operation and record any separately authorised endpoint;
- bound resources and terminate cases deterministically where possible;
- seal raw outputs before labels are available to scoring;
- calculate metrics from sealed raw outputs and sealed labels;
- preserve failures as results rather than omit them; and
- support verification and replay without the original mutable checkout.

## 13. Failure taxonomy

At minimum, failures must be classified into:

- `RIGHTS_OR_PROVENANCE_REJECTED`
- `SPLIT_OR_LINEAGE_VIOLATION`
- `EXPOSURE_POLICY_VIOLATION`
- `INPUT_OR_LABEL_INVALID`
- `SNAPSHOT_FAILED`
- `TARGET_NOT_INDEXABLE`
- `INDEX_BUDGET_EXHAUSTED`
- `TARGET_NOT_GENERATED`
- `TARGET_RANKED_BELOW_CUTOFF`
- `HARD_NEGATIVE_OUTRANKED_TARGET`
- `REPRODUCTION_UNSUPPORTED`
- `REPRODUCTION_INFRASTRUCTURE_FAILURE`
- `WITNESS_NOT_OBSERVED`
- `FALSE_CONFIRMATION`
- `DETERMINISM_MISMATCH`
- `REPLAY_MISMATCH`
- `RESOURCE_LIMIT_REACHED`
- `RUNNER_OR_SCHEMA_FAILURE`
- `METRIC_OR_REPORT_INCONSISTENCY`

One case may carry a primary failure and multiple contributing codes. Reports
must retain the pipeline stage so retrieval failures are not confused with
reproduction or infrastructure failures.

## 14. Work packages

### WP0 - Preflight and boundary seal

- confirm storage, runtime, and access-control roots;
- create the dedicated `Trace-Eval` environment;
- record the V0.1 system-under-test artifact and hashes;
- prove there is no dependency on Scout or Yumi data, caches, or runtimes;
- define public versus governed-private outputs; and
- issue an environment and boundary preflight record.

**Exit:** The evaluator can run the public synthetic fixture in isolation and
retain a verified environment receipt.

### WP1 - Schemas, identities, and policy engine

- implement the contracts in section 11;
- implement canonical identities and verification;
- implement exposure-state transitions;
- implement rights, split, lineage, and holdback fail-closed policy; and
- add public synthetic policy tests.

**Exit:** Invalid, incomplete, overlapping, or unauthorised material cannot be
scheduled.

### WP2 - Corpus inventory and split design

- inventory rights-cleared candidate repositories without opening protected
  holdbacks;
- record licence, provenance, redistribution, lineage, and content identity;
- assess available languages, CWEs, sizes, target kinds, and label sources;
- define useful-group criteria and hard-negative families;
- select and seal repository-disjoint partitions; and
- publish a private corpus sufficiency and overlap audit.

**Exit:** Every eligible case has a governed status, and the split plan is
locked before reserved labels are exposed.

### WP3 - Label construction and controlled review

- construct location and optional reproduction labels from authoritative
  evidence;
- keep construction blind to Lumi Trace rankings;
- perform the separate controlled review pass;
- resolve disagreements through append-only decisions;
- verify accepted-target matching semantics; and
- seal label and correction manifests.

**Exit:** Audited labels and review receipts exist for every scheduled scored
case.

### WP4 - Runner, sealing, and replay

- implement subprocess orchestration around the pinned Lumi Trace CLI;
- enforce label blindness and disposable read-only staging;
- capture run, attempt, resource, and failure records;
- seal raw outputs before scoring;
- implement package verification and replay; and
- test interruption, partial output, timeout, and cleanup behavior.

**Exit:** A multi-case development run is complete, tamper-evident, and
replay-verifiable.

### WP5 - Metrics and reports

- implement the metrics in section 10 with tested denominators;
- produce repository-macro and group-micro views;
- produce strata, hard-negative, failure, reproduction, reproducibility, and
  resource reports;
- cross-check aggregate results against case records; and
- create a disclosure-reviewed public-summary template.

**Exit:** Two calculations from the same sealed inputs produce the same
identity-bearing aggregate result.

### WP6 - Development baseline and threshold decision

- run the exact V0.1 release on public-fixture and development partitions;
- repeat the baseline under the same-host determinism protocol;
- run the approved cross-environment compatibility sample;
- analyse failures without touching qualification or holdback labels;
- approve or decline ranking thresholds; and
- seal the evaluator, runtime, metrics, configuration, and decision rules.

**Exit:** A signed or hash-bound threshold decision exists. If thresholds
cannot be justified, V0.2 records that fact and does not proceed to a claimed
qualification result.

### WP7 - Qualification run

- verify all seals and preconditions;
- run the repository-disjoint qualification partition once per approved
  protocol;
- seal raw outputs before evaluator-only labels are used;
- score, verify, replay, and report the run; and
- retire or reclassify exposed qualification material correctly.

**Exit:** A reproducible qualification decision states which readiness gates
are met, failed, or still evidence-required.

### WP8 - V0.2 closure and next-direction record

- reconcile corpus counts against the 500-group and 25-repository gates;
- reconcile every candidate-ranking and future-weight gate individually;
- retain private evidence and publish only a boundary-reviewed summary;
- record defects and proposed V0.3 work without silently changing V0.2
  results; and
- preserve `DO_NOT_BEGIN_TRACE_001` unless a later, separate authority process
  changes it.

**Exit:** The V0.2 closure state in section 18 is explicit and evidence-backed.

## 15. Required tests

V0.2 must include tests for:

- schema acceptance and rejection;
- canonical identities and tamper detection;
- rights and provenance fail-closed behavior;
- direct, fork, vendored, and near-duplicate cross-split overlap;
- invalid exposure-state transitions;
- label leakage into runner inputs, paths, logs, and environment variables;
- protected-holdback access attempts;
- exact runtime artifact verification;
- public-fixture end-to-end execution;
- metric denominators, ties, multiple accepted targets, missing targets, and
  empty strata;
- file versus symbol versus region scoring separation;
- indexable-only versus end-to-end recall accounting;
- macro versus micro aggregation;
- hard-negative scoring;
- false-confirmation controls;
- timeout, resource, interruption, retry, and partial-output handling;
- raw-output sealing before scoring;
- same-host deterministic repeats;
- approved cross-host semantic comparison;
- replay and report reconstruction;
- private-path and source-content redaction; and
- public-boundary scanning of releaseable outputs.

Metric tests must use small hand-calculated fixtures. At least one adversarial
test must demonstrate that a seemingly improved aggregate score is rejected
when it changes the denominator or omits failures.

## 16. Required retained artifacts

Retain, under governed access as applicable:

- environment recreation instructions and exact lock;
- hardware, OS, Python, Docker, and filesystem qualification report;
- exact Lumi Trace wheel/source hashes and model inventory;
- evaluator source revision and dependency inventory;
- rights, repository, lineage, and split manifests;
- overlap and repository-independence audit;
- group, label, review, and correction records;
- hard-negative and control taxonomy with distribution report;
- metric specification and threshold decision;
- run configuration, raw-output seal, case results, and resource telemetry;
- replay and determinism verification;
- failure analysis and aggregate reports;
- V0.2 qualification decision;
- updated training-readiness record; and
- a public-boundary review for any publication candidate.

Protected or third-party-derived artifacts must remain private even when their
hashes or aggregate results are retained.

## 17. Non-objectives

V0.2 must not:

- train, fine-tune, distil, prune, or otherwise modify model weights;
- select or download a foundation model;
- publish a dataset, label set, or third-party repository snapshot;
- consume historical Lumi evidence, Scout evidence, customer evidence,
  CyberGym tasks, rejected V2.7 adapters, or protected holdbacks;
- generate or apply vulnerability repairs;
- turn Trace into a vulnerability-discovery claim;
- tune rules or thresholds on qualification or holdback results;
- use aggregate counts as a substitute for rights, independence, usefulness,
  or audit evidence;
- claim probabilistic confidence from deterministic score descriptors;
- make GPU availability a requirement; or
- claim that controlled review is organisationally independent.

## 18. Closure states

V0.2 must close in exactly one of these states:

### `ENVIRONMENT_QUALIFIED / DATA_GATES_PENDING`

The runner, controls, metrics, and replay system are qualified, but corpus
scale, rights, labels, splits, or threshold evidence remains incomplete.
`TRACE-001` remains stopped.

### `BASELINE_QUALIFIED / TRACE_001_NOT_READY`

The sealed deterministic baseline and qualification evidence are valid, but
one or more training-readiness or future-weight gates remain unmet, or the
deterministic baseline misses the approved threshold. `TRACE-001` remains
stopped.

### `CANDIDATE_RANKING_EVIDENCE_COMPLETE / TRACE_001_DESIGN_REQUIRED`

Every candidate-ranking evidence gate is individually supported, including
corpus scale, repository independence, hard negatives, audited labels, and
deterministic recall. Future-weight gates, the exact training design, and the
separate authority gate remain for a later decision. No training may begin on
the strength of this closure state.

### `NOT_QUALIFIED / REMEDIATION_REQUIRED`

The environment, evidence, controls, metrics, or result package cannot support
a trustworthy decision. Defects are recorded and affected results are not
used.

V0.2 itself must never emit `TRACE_001_AUTHORISED`.

## 19. Acceptance criteria

The V0.2 build is complete when:

1. `Trace-Eval` is isolated from Scout, Yumi, system Python, shared caches, and
   the public data boundary.
2. The exact V0.1 system-under-test artifact is pinned and verified.
3. Rights, provenance, split, lineage, exposure, and holdback controls fail
   closed.
4. Labels are runner-blind, sealed, controlled-reviewed, and correction-aware.
5. The runner produces complete, schema-valid, identity-bound case and run
   packages without omitting failures.
6. All metrics have tested denominators and separate file, symbol, region,
   reproduction, reliability, and resource views.
7. Repository-macro, group-micro, stratified, hard-negative, and failure
   reports are reproducible from sealed inputs.
8. Same-host identity and approved cross-environment comparison protocols pass
   their declared requirements.
9. Metric definitions and decision thresholds are locked before qualification.
10. A qualification result, or an explicit evidence-insufficiency result, is
    recorded without opening the frozen holdback.
11. Every training-readiness gate is marked individually as met, failed, or
    `UNMET / EVIDENCE_REQUIRED` with cited artifacts.
12. Any public summary passes the Lumi Trace publication boundary and contains
    no protected or third-party-derived substance.
13. The final record uses one closure state from section 18 and preserves the
    separate `TRACE-001` authority gate.

## 20. Direction after V0.2

The next direction is selected from evidence, not assumed in advance:

- If deterministic target coverage is weak, improve snapshot/index support
  before considering a learned ranker.
- If coverage is strong but ranking recall is weak, define a narrowly bounded
  `TRACE-001` candidate-ranking objective and seek separate training authority.
- If ranking is strong but exact localization is weak, improve symbol and
  source-region representations and labels before training.
- If reproduction or classification produces unsafe results, remediate the
  deterministic evidence contract before any learning work.
- If corpus rights, independence, scale, or audit quality is insufficient,
  continue governed corpus construction without weakening the gates.
- If all evidence gates pass, prepare a separate `Trace-Train` build brief and
  explicit authority decision. Do not convert this V0.2 brief into training
  authority after the fact.

The intended product progression is therefore:

```text
V0.1 deterministic public baseline
        -> V0.2 isolated evaluation and qualification
        -> evidence-backed readiness decision
        -> separately authorised Trace-Train work, if justified
```
