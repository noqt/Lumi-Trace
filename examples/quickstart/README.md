# Lumi Trace synthetic quickstart

This synthetic fixture is distributed under Apache-2.0.

It exists only to demonstrate the Lumi Trace workflow and output format. It is not a benchmark, a real advisory, or evidence of coverage on natural repositories.

Run it from the repository root:

```sh
lumi-trace trace \
  --finding examples/quickstart/finding.json \
  --finding-format manual \
  --repository examples/quickstart/repository \
  --output out/quickstart

lumi-trace verify out/quickstart
```

The finding deliberately names `src/archive.py::extraction_target`, so that location should appear among the leading implementation candidates.

No reproduction plan is supplied. The human summary reports
`Localisation: complete`, `Confirmation: not attempted
(NO_REPRODUCTION_PLAN)`, and `Evidence classification:
INSUFFICIENT_EVIDENCE`. This means confirmation was not attempted; it does not
mean the localisation stage failed.
