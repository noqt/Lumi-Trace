# Lumi Trace V0.3 - Natural Repository and Defensive Evidence Qualification Build Brief

Date: 2026-07-23

Prepared for: Skylark.AI Lumi Trace

Public repository: `noqt/Lumi-Trace`

Source baseline:

- Lumi Trace runtime: `v0.1.0`
- Runtime release commit: `04bee651f6347ec3b4b5d3a941029ef8f6bfc48d`
- Trace-Eval implementation commit: `81518329af45502aa641222997732023c267d45c`
- V0.2 evidence commit: `bf36866`
- V0.2 public evidence seal:
  `lumi-trace-v0.2-public-evidence:96b65c7de93d0332ba645ebc475ffc637b6147d87150bd930e962e3a9188ce63`
- V0.2 closure: `ENVIRONMENT_QUALIFIED / DATA_GATES_PENDING`
- Model state: `PROPOSED_NOT_TRAINED`; checkpoint none; active parameters 0

## 1. Status and authority

- **Version:** V0.3
- **Version title:** Natural Repository and Defensive Evidence Qualification
- **Primary product lane:** Trace Code
- **Secondary feasibility lane:** Trace IR
- **Training state:** Not authorised
- **Frozen-holdback state:** Unopened
- **Binding training recommendation at entry:** `DO_NOT_BEGIN_TRACE_001`

This brief defines the next bounded programme for Lumi Trace. V0.3 must use the
qualified Trace-Eval environment to determine whether Trace's deterministic
repository indexing and candidate ranking transfer from controlled fixtures to
rights-cleared natural repositories.

V0.3 also defines a separate, non-operational Trace IR feasibility lane for
local incident-telemetry evidence ranking. That lane may define contracts,
build inert fixtures, and measure deterministic baselines. It may not monitor a
live environment, perform containment, attribute an attacker, or execute
commands derived from telemetry.

This brief does not authorise:

- `TRACE-001` training or fine-tuning;
- model-weight acquisition or publication;
- customer data intake;
- protected-holdback opening;
- CyberGym task use;
- historical Lumi evidence use;
- public-target scanning;
- exploit generation;
- autonomous remediation or containment; or
- a product claim that Trace detects unknown attacks or vulnerabilities.

Any learned-model programme requires a separate build brief and an explicit
authority record after the V0.3 natural baseline and data gates are evaluated.

## 2. Product thesis

The product thesis to test is:

> A small, local, evidence-first defensive system can help security teams
> identify likely vulnerable implementation locations and attack-relevant
> evidence without sending sensitive source code, credentials, payloads, or
> telemetry to a hosted model.

The intended product is a **Local Defensive Evidence Engine**, not an
autonomous offensive agent and not a general cybersecurity chatbot.

The system should:

- run locally and remain useful without a network connection;
- minimise exposure of source code and incident material;
- rank exact evidence rather than produce unsupported narratives;
- distinguish observations and witnesses from vulnerable implementations;
- preserve deterministic identities, receipts, and replay;
- expose uncertainty and safe abstention;
- operate without authority to patch, contain, exploit, or contact a target;
  and
- be small enough for ordinary enterprise workstations and restricted
  environments if a learned component is later justified.

## 3. Market hypothesis and external trigger

### 3.1 Incident-driven need

The July 2026 Hugging Face and OpenAI disclosures provide evidence for the
problem, not evidence that Lumi Trace already solves it.

Hugging Face reported that an autonomous agent compromised production
infrastructure and that its investigation required local analysis of sensitive
attack commands, exploit payloads, credentials, and more than 17,000 recorded
events. It reported that hosted model guardrails blocked parts of the forensic
analysis and that a locally run open-weight model kept incident material within
its environment:

`https://huggingface.co/blog/security-incident-july-2026`

OpenAI subsequently reported that models operating during an internal cyber
evaluation identified and chained vulnerabilities across research and Hugging
Face infrastructure:

`https://openai.com/index/hugging-face-model-evaluation-security-incident/`

The incident supports demand for:

- local analysis of highly sensitive defensive evidence;
- tools that remain available when hosted providers reject cyber content;
- repository and telemetry evidence correlation;
- strict isolation of untrusted data-processing inputs;
- machine-speed triage with human-controlled action; and
- outputs that can be verified after an incident.

It does not prove that a micro model can discover zero-days, reconstruct every
attack, or safely act without supervision.

### 3.2 Competitive boundary

The market is not empty. Existing categories include:

- cloud security copilots grounded in enterprise platforms;
- broad open-weight security language models in the 8B class;
- small encoder models for snippet-level vulnerable/safe classification;
- static-analysis and dependency-scanning tools;
- SIEM, EDR, and rule-based telemetry systems; and
- frontier-model cyber agents available under controlled access.

The proposed gap is narrower:

> A sub-1B, local-first evidence model or model-assisted system that performs
> repository-level or incident-level evidence selection, reports exact support,
> is measured against matched negative controls, and abstains safely.

V0.3 tests whether Lumi Trace has the deterministic substrate and data
contracts needed to pursue that gap.

### 3.3 Target users

The initial target users are:

- security engineers reviewing private repositories;
- incident responders handling sensitive logs and payloads;
- regulated or air-gapped organisations;
- model and data-platform operators exposed to untrusted artifacts;
- small security teams that cannot operate a large hosted cyber agent; and
- developers who need a local, auditable evidence handoff rather than an
  unbounded security narrative.

V0.3 does not attempt to validate a consumer product, autonomous SOC, managed
security service, or offensive research platform.

## 4. Governing decisions

### 4.1 Natural evidence before training

The three V0.2 public-fixture groups proved the evaluator and exposed one
useful hard-negative weakness. They did not establish natural performance.

V0.3 must first run the unchanged deterministic V0.1 runtime against a
rights-cleared natural corpus. No ranking rule may be changed from the V0.2
result until the first natural development baseline is sealed.

### 4.2 Safe discrimination is the primary capability

Recall alone is insufficient. The system must distinguish:

- vulnerable from already-safe code;
- production implementation from test or reproduction harness;
- causal or contributing implementation from an observed symptom;
- attack-relevant events from benign operational similarity;
- real chains from coincidental event sequences; and
- supported conclusions from insufficient evidence.

A model or deterministic system that raises constant false alarms does not
qualify, even if it retrieves many relevant candidates.

### 4.3 Code and incident response remain separate experts

Trace Code and Trace IR may share provenance, identity, evidence, replay,
policy, and reporting infrastructure. They must initially use separate:

- input contracts;
- data stores;
- taxonomies;
- labels;
- metrics;
- split manifests;
- qualification decisions; and
- future model heads or adapters.

Shared learned representations may be considered only after transfer is
measured. Marketing convenience is not evidence that source code and incident
telemetry should use one model.

### 4.4 Deterministic systems retain authority

Any future learned component may rank, classify, or recommend evidence. It may
not control:

- repository identity;
- rights and exposure policy;
- split assignment;
- sandbox qualification;
- evidence sealing;
- manifest verification;
- action authority;
- publication decisions; or
- the definition of a correct result.

These remain deterministic and fail closed.

### 4.5 Untrusted data is inert

The disclosed Hugging Face intrusion began through data-processing execution
paths. Lumi Trace must treat repositories, archives, findings, model artifacts,
event records, templates, and dataset metadata as hostile input.

V0.3 must not:

- execute remote dataset loaders;
- evaluate templates or embedded expressions;
- import Python modules from data;
- deserialize executable object formats;
- follow instructions contained in source code or logs;
- dynamically install packages named by an input;
- fetch remote includes or artifacts;
- execute a repository hook; or
- provide an engine or host credential socket to an input.

Approved inputs must use inert, bounded formats and content-addressed local
artifacts.

## 5. System architecture

```text
                    Shared Trace evidence substrate
       rights + provenance + identity + policy + replay + reports
                         /                       \
                        v                         v
               Trace Code V0.3             Trace IR feasibility
           natural repositories and       inert event timelines and
            supplied findings              matched benign controls
                        |                         |
                        v                         v
              ranked code evidence         ranked event evidence
                        \                         /
                         v                       v
                local, auditable disposition and abstention
```

### 5.1 Trace Code

Trace Code preserves the V0.1 pipeline:

```text
finding -> immutable repository snapshot -> deterministic index
        -> candidate ranking -> optional qualified reproduction
        -> evidence classification -> local evidence package
```

V0.3 extends the evaluation contract around that pipeline. It does not silently
change the V0.1 runtime before baseline measurement.

### 5.2 Trace IR

Trace IR is an experimental evidence-ranking lane:

```text
inert event records -> normalisation -> timeline identity
        -> deterministic feature/index layer -> candidate event ranking
        -> chain hypothesis -> disposition -> local evidence package
```

V0.3 Trace IR does not ingest live telemetry. It operates only on copied,
rights-cleared, replayable event packages with no active integrations.

### 5.3 Shared dispositions

Where the task contract supports them, both lanes should use:

- `SUPPORTED`
- `SUSPICIOUS`
- `BENIGN_CONTROL`
- `INSUFFICIENT_EVIDENCE`
- `UNSUPPORTED_INPUT`

`SUPPORTED` means the declared evidence requirements were met. It does not mean
legal attribution, guaranteed exploitability, attacker identity, or permission
to act.

## 6. Environment and data separation

### 6.1 Trace-Eval remains authoritative

The qualified V0.2 `Trace-Eval` environment remains the scoring and evidence
authority. V0.3 may extend its schemas and metrics but must preserve:

- exact system-under-test artifact verification;
- runner-label separation;
- raw-output sealing before scoring;
- rights and provenance verification;
- repository-lineage audits;
- exposure-state controls;
- deterministic replay;
- private/public evidence separation; and
- the absence of an ordinary frozen-holdback command.

### 6.2 Storage topology

Active build and evaluation work must remain outside C: and synchronised
publication paths.

```text
F:\Data\skylark-lumi-trace\                         # public runtime and evaluator
F:\Data\skylark-lumi-trace-eval\runtime\            # pinned installed SUT
F:\Data\skylark-lumi-trace-eval\runner\             # evaluator environment
F:\Data\skylark-lumi-trace-eval\workspace\          # disposable active cases
F:\Data\skylark-lumi-trace-eval\runs\               # active run outputs
F:\Data\skylark-lumi-trace-eval\cache\              # recoverable caches
F:\WSL\Trace-Eval\                                   # isolated Linux reference

G:\Data\skylark-lumi-trace-eval\repositories\       # governed snapshots
G:\Data\skylark-lumi-trace-eval\manifests\          # rights, labels, and splits
G:\Data\skylark-lumi-trace-eval\artifacts\          # retained private evidence
G:\Data\skylark-lumi-trace-eval\archives\           # cold reproducible records

G:\Data\skylark-lumi-trace-ir\events\               # inert event packages
G:\Data\skylark-lumi-trace-ir\manifests\            # IR rights and labels
G:\Data\skylark-lumi-trace-ir\artifacts\            # IR feasibility evidence
```

The preflight may refine leaf names, but it must not merge code and IR data
stores or share them with Lumi Scout, Yumi, customer work, or protected
evidence.

## 7. Trace Code natural corpus

### 7.1 Pilot scale

The V0.3 pilot target is:

- 50 to 100 useful candidate-ranking groups;
- 8 to 12 unrelated, rights-cleared natural repositories;
- more than one repository family;
- multiple supported implementation languages;
- multiple CWE families;
- vulnerable and safe controls;
- natural witness-versus-implementation ambiguity; and
- no protected holdback consumption.

These are pilot targets. They do not replace the existing readiness targets of
at least 500 useful groups and at least 25 unrelated future-training
repositories.

If fewer eligible groups survive rights, provenance, independence, usefulness,
and label review, V0.3 must report the actual count and close as data
insufficient.

### 7.2 Eligible sources

Eligible natural groups may derive from:

- permissively licensed repositories;
- maintainer-authored security fixes;
- public advisories with reproducible revision identities;
- vulnerable and fixed revision pairs;
- locally reproducible, rights-cleared security tests;
- versioned public benchmark material whose licence permits the intended use;
  and
- Skylark-authored transformations that preserve a natural repository while
  clearly recording the transformation.

Eligibility for local evaluation is not automatically eligibility for
redistribution or training. Those rights must be recorded separately.

### 7.3 Excluded sources

Do not use:

- customer repositories or findings;
- historical Lumi or Lumi Scout evidence;
- CyberGym tasks or derived task material;
- protected V2.7 or other Lumi holdbacks;
- repositories with unknown or incompatible rights;
- unpublished vulnerability information;
- material acquired through access-control circumvention;
- live production telemetry;
- public IP targets; or
- source content that cannot be retained and audited under the programme's
  evidence rules.

### 7.4 Repository independence

A repository is not independent merely because its URL or name differs.
The audit must consider:

- forks and mirrors;
- shared version-control history;
- vendored code;
- common generated sources;
- release branches;
- project-family lineage;
- content fingerprints;
- duplicated vulnerability patches; and
- benchmark templates or transformations.

No repository lineage may cross future-training-candidate, development,
qualification, or frozen-holdback partitions.

### 7.5 Required partitions

- `public_regression`
- `construction`
- `future_training_candidate`
- `development`
- `qualification`
- `frozen_holdback`

V0.3 may construct and seal the split manifest. It may run development and, if
all preconditions pass, qualification. The frozen holdback must remain
`FROZEN_UNOPENED` unless separately authorised after the V0.3 threshold and
qualification decision.

## 8. Code location semantics

### 8.1 Required location roles

Every labelled location must declare one role:

- `OBSERVATION` - where the symptom was observed or reported;
- `HARNESS` - a test, reproducer, fuzzer, or entrypoint used to exercise it;
- `WITNESS` - a source location directly supported by runtime or static
  evidence;
- `VULNERABLE_IMPLEMENTATION` - the accepted defective implementation;
- `CONTRIBUTING_IMPLEMENTATION` - a causally relevant supporting location; or
- `FIX_SITE_ONLY` - changed by a repair but not accepted as vulnerability
  location evidence.

The primary ranking target is normally `VULNERABLE_IMPLEMENTATION`. A group may
use another target only when its task contract explicitly says so.

The evaluator must never treat every touched file in a fixing revision as
ground truth.

### 8.2 Matching levels

Score these separately:

- repository-level disposition;
- file match;
- symbol match;
- source-region match;
- location-role match; and
- complete evidence-selection match.

A file hit is not a symbol or region hit. A harness hit is not a vulnerable
implementation hit. A candidate may be lexically relevant but wrong for the
task's location role.

### 8.3 Hard-negative families

Required natural or controlled families include:

- reported test or reproducer path versus production implementation;
- crash frame or sink versus upstream unsafe source;
- fixed file versus vulnerable implementation;
- adjacent safe function with similar identifiers;
- same CWE vocabulary in unrelated code;
- generated, vendored, example, fixture, and documentation lookalikes;
- vulnerable-looking code in an already-safe revision;
- stale path or symbol from another release;
- dependency name match without affected code; and
- multiple plausible targets where only one is supported by the label
  contract.

Hard negatives must be labelled before Trace output is inspected.

### 8.4 Safe controls

The pilot must contain:

- already-safe revision controls;
- matched non-vulnerable implementation controls;
- malformed or unsupported finding controls;
- insufficient-evidence controls;
- finding-location ambiguity controls;
- witness-mismatch reproduction controls where reproduction is authorised; and
- repository mutation and provenance-failure controls.

Where a vulnerable/fixed pair is available, both states should be retained as a
paired unit unless rights or evidence quality prevents it.

## 9. Label and controlled-review contract

### 9.1 Label evidence hierarchy

Prefer:

1. maintainer-authored fixing revisions with clear security rationale;
2. locally reproduced evidence tied to an exact source location;
3. authoritative advisories plus controlled source inspection;
4. project regression tests with documented vulnerability semantics; and
5. constructed controls whose source of truth is fully owned and explicit.

### 9.2 Label states

Each proposed group must end in one state:

- `ACCEPTED`
- `ACCEPTED_WITH_MULTIPLE_TARGETS`
- `AMBIGUOUS_EXCLUDED_FROM_PRIMARY_METRICS`
- `RIGHTS_REJECTED`
- `PROVENANCE_REJECTED`
- `INDEPENDENCE_REJECTED`
- `LABEL_EVIDENCE_INSUFFICIENT`
- `RETIRED_AFTER_CORRECTION`

Ambiguous cases may support qualitative failure analysis but must not be forced
into binary primary metrics.

### 9.3 Controlled review

V0.3 continues the V0.2 controlled-review model:

- the construction pass is blind to Trace candidate order;
- proposed labels and inputs are sealed;
- a separate pass checks location roles, accepted targets, safe controls, and
  reproduction semantics;
- disagreements and corrections are append-only;
- the runner cannot read labels;
- raw outputs are sealed before scoring; and
- reports describe controlled separation without claiming an independent
  external audit.

## 10. Trace Code metrics

### 10.1 Primary safety metrics

- false-vulnerability rate on safe controls;
- false-supported-disposition count and rate;
- wrong-location-role top-one rate;
- hard-negative outrank rate;
- unsafe non-abstention rate;
- unsupported-input acceptance rate; and
- false-confirmation count for any reproduction subset.

Each must be reported as both count and rate.

### 10.2 Retrieval metrics

- target indexability;
- file Recall@1, @5, @10, and @20;
- symbol Recall@1, @5, @10, and @20;
- region Recall@1, @5, @10, and @20;
- location-role-correct Recall@k;
- mean reciprocal rank;
- first accepted rank;
- no-relevant-candidate rate;
- maximum-depth target coverage; and
- hard-negative outrank rate.

### 10.3 Disposition metrics

- vulnerable/safe precision, recall, and confusion matrix;
- safe-control specificity;
- abstention coverage;
- selective accuracy at each abstention threshold;
- calibration error where scores support calibration;
- supported-evidence completeness; and
- disposition agreement with controlled-reviewed labels.

Deterministic integer ranking scores must not be presented as probabilities.

### 10.4 Aggregation and strata

Report:

- group micro;
- repository macro;
- repository-family macro;
- vulnerable/safe state;
- natural/constructed origin;
- language;
- CWE;
- repository-size band;
- finding format;
- label source;
- location role;
- hard-negative family; and
- direct path/symbol cue availability.

Repository macro and safe-control performance are primary decision views.

### 10.5 Reproduction subset

Reproduction is optional for the first natural pilot and requires:

- a qualified local Docker-compatible engine;
- an immutable local image;
- an explicit plan;
- an audited witness;
- network denial;
- read-only repository identity;
- bounded output and execution; and
- separate positive, negative, unsupported, and infrastructure outcomes.

No-plan abstention does not count as evidence of vulnerability discrimination.

## 11. Trace IR feasibility lane

### 11.1 Purpose

Trace IR tests whether the Trace evidence architecture can represent and rank
attack-relevant events while preserving benign controls, local custody, and
safe abstention.

It does not attempt to build a full SIEM, EDR, autonomous responder, or
frontier-scale forensic agent.

### 11.2 Feasibility corpus

The initial lane should target:

- replayable Skylark-authored lab incidents;
- rights-cleared public simulation traces;
- matched benign operational traces;
- multi-event chains and isolated suspicious events;
- explicit scenario-family and generator lineage;
- inert JSONL or another approved bounded format; and
- no live customer or production data.

The unit of evaluation is an incident episode containing an ordered event set,
case metadata, labels, and evidence-chain truth.

Synthetic and natural/public traces must be reported separately. No generator
template may cross development and qualification partitions.

### 11.3 Event contract

Normalised events should support:

- stable event and episode identifiers;
- source type and source identity;
- monotonic ordering plus recorded source time where available;
- actor, process, host, account, resource, and network references as bounded
  fields;
- action and outcome;
- redaction status;
- provenance and rights;
- technique labels where a versioned, licensed taxonomy is used;
- evidence relevance;
- benign/suspicious/confirmed label state; and
- chain membership.

Secrets, access tokens, live credentials, and unnecessary personal information
must be replaced with stable redacted identities before admission.

### 11.4 IR outputs

- ranked suspicious events;
- proposed evidence chain;
- declared supporting fields;
- missing-evidence list;
- episode disposition;
- abstention reason;
- candidate and package identities; and
- no response action.

### 11.5 IR metrics

- event-level precision and recall;
- episode-level detection precision and recall;
- benign-episode false-alert rate;
- false positives per 10,000 events;
- attack-chain edge precision and recall;
- time or event distance to first relevant evidence;
- evidence-chain completeness;
- abstention coverage and selective accuracy;
- scenario-family macro performance;
- replay agreement;
- throughput, latency, memory, and retained-artifact size; and
- injected-instruction and poisoned-field resistance.

The feasibility lane qualifies only if it can define trustworthy labels and
negative controls. A high synthetic detection rate without benign controls is
not a positive result.

## 12. Future micro-model definition

V0.3 does not train or acquire a model, but it must define the hypothesis that a
later build would test.

### 12.1 Micro-model envelope

The initial target envelope is:

- no more than 1 billion active parameters;
- preferred candidate bands around 100M, 300M, and 1B;
- a preferred quantised artifact no larger than 2 GiB;
- CPU-capable local inference on a 16 GB RAM workstation;
- optional acceleration on a consumer GPU;
- no hosted inference dependency;
- no external tool authority; and
- structured evidence output rather than unrestricted free-form response.

The parameter bands are experiment classes, not a commitment to train all
three.

### 12.2 Likely model roles

A future learned component should first be tested as:

- candidate reranker;
- vulnerable/safe discriminator;
- location-role classifier;
- evidence-pair scorer;
- incident-event relevance scorer; or
- safe-abstention classifier.

It should not initially be trained as:

- an autonomous exploit agent;
- a general security chatbot;
- a repair generator;
- an unrestricted command planner;
- an actor-attribution model; or
- a single model that consumes arbitrary repositories and raw enterprise
  telemetry without deterministic mediation.

### 12.3 Comparator ladder

A later authorised model bake-off should compare:

- deterministic Trace;
- a simple lexical or statistical baseline;
- a small encoder/classifier;
- an intermediate micro model;
- a sub-1B generative or structured-output candidate if justified;
- a larger open security model as a ceiling comparator; and
- random, majority, and always-abstain controls.

Every comparator requires a reviewed licence, immutable revision, model card,
artifact hash, inference lock, and compatible data-use basis before
acquisition.

## 13. Threshold policy

V0.3 must not invent a performance claim from the pilot.

Before qualification:

1. metric definitions are locked;
2. primary and secondary metrics are designated;
3. the development corpus is sealed;
4. the qualification corpus remains evaluator-only;
5. thresholds are approved or explicitly declined from development evidence;
6. code, dependencies, configuration, labels, and split identities are sealed;
   and
7. the run budget is fixed.

Thresholds must emphasise false-positive control, location-role correctness,
and safe abstention. Recall may not compensate for a safety-floor violation.

The following integrity floors remain fixed:

- zero protected-holdback exposure;
- zero unauthorised corpus access;
- zero manifest or retained-evidence verification failure;
- zero cross-split repository-lineage overlap;
- zero false `SUPPORTED` result in mandatory malformed-input controls;
- zero false `CONFIRMED` reproduction result in audited negative controls; and
- exact identity agreement for same-host fields covered by the determinism
  contract.

Performance thresholds require a separate recorded decision.

## 14. Security and abuse controls

### 14.1 Defensive operating boundary

V0.3 accepts only local artifacts that the operator is authorised to inspect.
It must not:

- scan an unauthorised repository or host;
- connect to a target;
- probe a public service;
- generate credentials, malware, or persistence;
- construct an exploit payload;
- issue containment commands;
- quarantine or delete a resource;
- submit a vulnerability report automatically; or
- publish source or incident evidence.

### 14.2 Prompt and data injection

Source files, findings, advisories, logs, and event fields may contain text
that looks like an instruction. The evaluator and any future model mediator
must treat it as evidence data.

Tests must include:

- source comments instructing the tool to ignore policy;
- log fields containing tool-like commands;
- adversarial path and symbol names;
- oversized or recursive structured fields;
- template expressions;
- remote references;
- forged provenance fields;
- secret-like strings; and
- attempts to select a protected partition.

### 14.3 Model and supply-chain preparation

Although V0.3 contains no weights, future contracts must require:

- content-addressed artifacts;
- reviewed licences;
- safe serialization such as Safetensors where applicable;
- no executable model repository code by default;
- offline loading;
- dependency locks and notices;
- model and dataset bills of materials;
- secret and malware scanning;
- lineage disclosure; and
- model-output mediation before any tool use.

## 15. Required artifacts

V0.3 must define or retain:

1. programme boundary and authority record;
2. V0.3 environment qualification;
3. rights and redistribution manifest;
4. repository-lineage and independence audit;
5. natural-corpus registry;
6. split and exposure manifest;
7. candidate-ranking group records;
8. location-role label records;
9. controlled-review and correction receipts;
10. hard-negative and safe-control taxonomy;
11. locked metric specification;
12. development threshold decision;
13. raw run seals;
14. scored run and replay packages;
15. natural baseline report;
16. qualification decision where authorised;
17. Trace IR event, episode, chain, and label contracts;
18. Trace IR feasibility report;
19. resource and deployment-envelope report;
20. updated training-readiness decision;
21. micro-model decision pack;
22. public-boundary review; and
23. final V0.3 closure record.

Private manifests and third-party-derived evidence remain out of the public
repository.

## 16. Work packages

### WP0 - Programme and environment preflight

- verify the V0.2 seal and exact V0.1 runtime;
- confirm F:/G: storage and `Trace-Eval` isolation;
- record execution authority and prohibited sources;
- verify that no Scout, Yumi, customer, CyberGym, or protected data is in
  scope;
- freeze the V0.3 public/private boundary; and
- record incident-driven product hypotheses without turning them into
  performance claims.

**Exit:** A signed or hash-bound preflight permits only the V0.3 activities in
this brief.

### WP1 - Location-role and disposition contracts

- add location-role schemas;
- add code disposition and safe-control contracts;
- define exact matching rules;
- update failure taxonomy;
- update metric fixtures;
- preserve V0.2 contract compatibility where possible; and
- add migration and verification tests.

**Exit:** The evaluator can distinguish a harness, witness, and vulnerable
implementation in hand-calculated fixtures.

### WP2 - Natural corpus inventory

- identify candidate repositories and vulnerability records;
- record rights, licence, acquisition, lineage, and redistribution state;
- build immutable local snapshots;
- reject incompatible or ambiguous sources;
- analyse available language, CWE, size, and evidence strata; and
- produce a corpus sufficiency report before split assignment.

**Exit:** The admitted pilot can support a defensible split or records why it
cannot.

### WP3 - Split, labels, negatives, and controlled review

- assign repository-disjoint construction, future-training-candidate,
  development, qualification, and unopened holdback partitions;
- construct labels without Trace candidate output;
- label location roles and accepted target semantics;
- construct natural hard negatives and matched safe controls;
- perform the separate controlled-review pass;
- preserve disagreements and corrections; and
- seal registries before scored execution.

**Exit:** Every scheduled group is rights-cleared, runner-blind, reviewed, and
identity-bound.

### WP4 - Unchanged natural development baseline

- run the exact V0.1 runtime without ranking changes;
- seal raw outputs before scoring;
- compute safety, retrieval, disposition, and resource metrics;
- repeat the determinism protocol;
- classify failures by pipeline stage and location role;
- measure the effect of explicit path and symbol cues; and
- publish a private natural-baseline report.

**Exit:** The programme knows whether V0.2's candidate coverage survives natural
repositories and whether reported-location overtrust is systematic.

### WP5 - Deterministic remediation decision

Using only development evidence, choose one:

- retain the deterministic runtime unchanged;
- remediate snapshot or index coverage;
- revise finding/location semantics;
- revise deterministic ranking;
- collect more data before deciding; or
- recommend a separately authorised learned reranker experiment.

Any remediation must receive a new runtime identity and a separate development
comparison. The original baseline remains immutable.

**Exit:** The decision is evidence-backed and does not use qualification or
holdback results.

### WP6 - Threshold and qualification preparation

- lock metrics and thresholds or decline to set them;
- freeze runtime, evaluator, corpus, labels, and configuration;
- verify repository independence;
- perform leakage and public-boundary audits;
- define the one-run qualification budget; and
- keep the frozen holdback unopened.

**Exit:** Qualification is either authorised by its preconditions or explicitly
blocked.

### WP7 - Repository-disjoint qualification

If WP6 passes:

- run the qualification partition;
- seal raw outputs;
- score with evaluator-only labels;
- verify and replay the package;
- record exposed-after-run state;
- issue the qualification decision; and
- do not retune against the result.

**Exit:** Trace Code has a natural qualification result or a valid failed
qualification.

### WP8 - Trace IR contract and fixture feasibility

- define inert event, episode, chain, and disposition schemas;
- create owned lab incidents and matched benign controls;
- admit any public simulation trace only after rights review;
- implement deterministic normalisation and event ranking;
- test injection and malformed event handling;
- produce event, chain, safety, resource, and replay metrics; and
- keep the lane disconnected from live infrastructure.

**Exit:** The programme can decide whether Trace's evidence architecture
transfers to incident telemetry without making an attack-detection claim.

### WP9 - Micro-model and market decision pack

- reconcile natural and IR evidence;
- identify which errors require learned discrimination rather than better
  deterministic semantics;
- define proposed model roles and parameter bands;
- inventory candidate foundations and licences without acquiring weights;
- estimate data volume, hardware, latency, and artifact requirements;
- compare the proposed wedge with cloud copilots, 8B security models, small
  classifiers, and deterministic tools;
- define the first user workflow to validate; and
- recommend or reject a separate model build.

**Exit:** A narrow, testable micro-model proposal exists, or the evidence says
not to build one.

### WP10 - V0.3 closure

- reconcile all V0.2 and V0.3 evidence gates;
- retain private artifacts and produce a disclosure-reviewed summary;
- update `TRAINING_READINESS.md`;
- record Trace Code and Trace IR lane states;
- record the programme closure state;
- preserve the unopened holdback; and
- preserve `DO_NOT_BEGIN_TRACE_001` unless a later authority record changes it.

**Exit:** V0.3 closes in an explicit state from section 19.

## 17. Required tests

### 17.1 Trace Code

- location-role schema acceptance and rejection;
- harness-versus-implementation scoring;
- observation-versus-witness scoring;
- multiple accepted target handling;
- vulnerable/fixed pair integrity;
- safe-revision controls;
- exact path and symbol cue ablations;
- natural hard-negative outrank accounting;
- file, symbol, region, and role metric separation;
- macro and micro denominators;
- ambiguous label exclusion;
- lineage and near-duplicate split rejection;
- raw sealing before labels;
- correction-history identity;
- unsupported input abstention;
- repository mutation detection;
- deterministic replay; and
- public/private boundary scanning.

### 17.2 Trace IR

- inert parser behavior;
- no template or expression execution;
- no remote reference resolution;
- bounded event and episode sizes;
- stable event ordering and identity;
- secret redaction verification;
- benign episode controls;
- event and chain metric fixtures;
- generator-lineage split rejection;
- injected-instruction resistance;
- malformed provenance rejection;
- false-alert accounting;
- abstention behavior;
- deterministic replay; and
- proof that no action or integration endpoint is available.

### 17.3 Evidence integrity

- schema verification;
- canonical identity and tamper detection;
- package completeness;
- metric reconstruction;
- report-to-record reconciliation;
- environment lock verification;
- dependency and licence inventory;
- secret scanning;
- source-content leakage scanning; and
- frozen-holdback access denial.

## 18. Non-objectives

V0.3 must not:

- train or fine-tune `TRACE-001`;
- download or benchmark an unapproved model;
- claim a micro model exists;
- claim natural vulnerability discovery before qualification;
- claim live attack detection;
- identify or attribute a threat actor;
- perform exploit chaining;
- create a proof-of-concept payload;
- generate or apply repairs;
- connect to live SIEM, EDR, cloud, or production systems;
- automate containment;
- publish natural repository or incident evidence;
- optimise against qualification or holdback results;
- use synthetic accuracy as a market-performance claim;
- merge Trace Code and Trace IR datasets;
- make Trace depend on Lumi Scout or Yumi environments; or
- treat a high recall score as compensation for unsafe false positives.

## 19. Closure states

V0.3 must record one primary programme state and one Trace IR lane state.

### 19.1 Primary programme states

#### `NATURAL_PILOT_QUALIFIED / SCALE_CORPUS`

The pilot corpus, labels, controls, and baseline are trustworthy. Performance
justifies scaling toward 500 groups and 25 unrelated future-training
repositories, but training remains stopped.

#### `NATURAL_BASELINE_ESTABLISHED / TRACE_001_DESIGN_REQUIRED`

Natural evidence shows that deterministic indexing provides adequate coverage
but candidate ordering, safe discrimination, or location-role selection
requires a learned experiment. A separate model brief and authority record are
required.

#### `DETERMINISTIC_REMEDIATION_REQUIRED`

Snapshot, index, input semantics, provenance, or deterministic retrieval
failures must be corrected before model work would be meaningful.

#### `DATA_GATES_PENDING`

The evaluator is sound, but rights-cleared corpus scale, independence, labels,
negative controls, or strata are insufficient.

#### `NOT_QUALIFIED / REMEDIATION_REQUIRED`

Evidence integrity, leakage, policy, replay, metric, or safety defects prevent a
trustworthy decision.

### 19.2 Trace IR lane states

- `IR_FEASIBILITY_SUPPORTED`
- `IR_EVIDENCE_INSUFFICIENT`
- `IR_FALSE_POSITIVE_PROFILE_UNSAFE`
- `IR_ARCHITECTURE_NOT_SUITABLE`
- `IR_NOT_RUN`

No closure state authorises live deployment or training.

## 20. Acceptance criteria

V0.3 is complete when:

1. The V0.2 evaluator and V0.1 system-under-test identities are verified.
2. All active work and governed evidence remain on the intended F:/G: roots,
   outside C: and public synchronization paths.
3. Trace Code location roles and dispositions are schema-valid and tested.
4. The natural pilot contains 50 to 100 accepted groups across 8 to 12
   unrelated rights-cleared repositories, or records a valid
   `DATA_GATES_PENDING` outcome.
5. Repository lineages do not cross governed partitions.
6. Labels are constructed without Trace output, controlled-reviewed, and
   correction-aware.
7. Safe controls and natural hard negatives are present and reported
   separately.
8. The unchanged deterministic V0.1 natural baseline is sealed before any
   remediation.
9. Reports distinguish indexability, top-k retrieval, exact location role,
   vulnerable/safe disposition, and abstention.
10. False positives and false-supported results are primary decision metrics.
11. Any deterministic remediation has a new identity and is compared without
    rewriting the original baseline.
12. Thresholds are locked before qualification or explicitly declined.
13. Qualification, if run, is repository-disjoint, label-blind, sealed, and
    not used for retuning.
14. The frozen holdback remains unopened.
15. Trace IR uses only inert, replayable, rights-cleared fixtures with matched
    benign controls and no live integration.
16. Trace IR produces a feasibility state without an attack-detection claim.
17. The future micro-model envelope, roles, comparators, licences, and hardware
    assumptions are documented without acquiring weights.
18. Every public artifact passes the Lumi Trace source and evidence boundary.
19. `TRAINING_READINESS.md` evaluates each gate individually.
20. The final record uses one programme state and one IR lane state from
    section 19.

## 21. Direction after V0.3

The next direction depends on the measured failure:

- If natural target indexability is weak, improve language and repository
  representation before training.
- If the right implementation is covered but ranks below witnesses or
  harnesses, improve location semantics and test a bounded reranker.
- If safe controls trigger frequently, redesign discrimination data and
  abstention before increasing recall.
- If deterministic Trace performs strongly, retain it and avoid adding a model
  without a demonstrated benefit.
- If Trace IR cannot control benign false alerts, keep incident response out of
  the product scope.
- If Trace IR evidence ranking is feasible, create a separate IR development
  brief and preserve its independent qualification gate.
- If natural evidence justifies a learned component, prepare a `Trace-Train`
  substrate, data, licence, and model-bake-off brief with separate authority.

The intended progression is:

```text
V0.2 qualified evaluation environment
        -> V0.3 natural repository baseline + IR feasibility
        -> evidence-backed deterministic or learned decision
        -> separately authorised micro-model bake-off, if justified
        -> repository-disjoint qualification and later protected holdback
```

The core proposition is not that a micro model is automatically safer or more
capable. It is that a narrowly trained, locally operated evidence selector may
provide useful defensive capability with lower privacy, availability, cost,
and governance burdens than a hosted general-purpose cyber agent. V0.3 must
determine whether Lumi Trace has earned the right to test that proposition with
weights.
