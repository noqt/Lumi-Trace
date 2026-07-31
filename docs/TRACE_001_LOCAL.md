# TRACE-001 Local Experiment

## Status and boundary

TRACE-001 is a completed negative candidate-reranking experiment, not the Lumi
Trace evidence authority. The deterministic runtime still owns repository
snapshotting, candidate construction, sandbox evidence, classification, and
export.

The V0.4 experiment is from scratch. It does not use or download a foundation
model, tokenizer, adapter, external weight file, hosted inference service, or
remote code. The public source repository contains training and inference
code, but no checkpoint or training feature data.

The V0.4 checkpoint remains on governed private storage. It did not advance
through grouped model selection and is not authorised for product integration,
pilot use, or publication. The repository's Apache-2.0 source licence does not
license that checkpoint.

## Fail-closed training

The governed training entry point is:

```powershell
python scripts/run_trace_001.py `
  --private-root G:/Data/skylark-lumi-trace-eval/v0.4 `
  train
```

The command refuses to run unless:

- the final corpus and partition seal exist;
- at least 500 allowlisted training groups from at least 25 families exist;
- every Section 17 gate is true in the final readiness record;
- candidate, metric, objective, supply-chain, code, dependency, resource, and
  checkpoint policies match their locks;
- qualification and protected holdback are unopened; and
- the feature-record allowlist exactly equals the training manifest.

It performs two clean local CPU runs and retains a checkpoint only if their
canonical identities match. It records CPU, wall, Python memory, artifact size,
pair-update, resume, and quantisation evidence. It does not execute repository
code or use the network. The V0.4 authority has now been consumed; these
instructions do not authorise another training run.

## Private model-selection inference

After the frozen deterministic model-selection comparators exist:

```powershell
python scripts/run_trace_001.py `
  --private-root G:/Data/skylark-lumi-trace-eval/v0.4 `
  score-partition `
  --partition MODEL_SELECTION `
  --run final-model
```

The scorer accepts only label-blind deterministic candidate features. It
removes the private target bit before inference, seals the ranking, and applies
private scoring labels afterward. It evaluates full, natural-cue-marked,
no-path, no-symbol, reduced-description, and identifier-ablation views.

Qualification is not invoked by this command. The separate qualification lock
selects once from grouped model-selection evidence.

## Checkpoint contract

`trace-001-linear-ranker-v1` is canonical JSON containing:

- eight ordered numeric weights;
- the exact feature names;
- the locked training configuration;
- training-manifest and training-data identities;
- completed epochs and pair updates;
- an identity over the complete checkpoint; and
- explicit `foundation_model: null`, `tokenizer: null`, `remote_code: false`,
  `hosted_service: false`, and `cpu_inference: true` fields.

`verify_checkpoint` must pass before inference. Resume also requires exact
training-manifest, data, and configuration agreement. Malformed, non-finite,
wrong-sized, reordered, or identity-mismatched checkpoints fail closed.

The optional `trace-001-linear-ranker-int8-v1` projection uses deterministic
symmetric int8 weights. It is a comparison artifact, not an independently
trained model, and may advance only if its regression gate passes.

## Resource envelope

The locked V0.4 implementation uses:

- local CPU training and inference;
- 12 epochs;
- at most 2,000 candidates per group;
- at most 256 pair updates per group per epoch;
- eight active parameters;
- canonical JSON-only checkpoints; and
- no more than one full and one int8 retained private artifact.

The completed experiment used 541 groups across 317 families, 12 epochs,
1,522,092 pair updates, and eight active parameters. Two clean runs matched in
340.41 wall seconds, with 210,632,567 bytes peak Python-traced memory and a
1,115-byte full checkpoint. The int8 projection failed its regression gate at
0.93 top-one agreement.

On model selection, the full checkpoint underperformed sparse and therefore
did not advance. These instructions do not grant access to the governed corpus
or private checkpoint, authorise another run, or authorise weight publication.
