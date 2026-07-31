# Lumi Trace Quickstart

Lumi Trace accepts an existing finding and a local repository or supported
archive that you are authorised to analyse. The release intentionally contains
no public demo, sample advisory, or third-party repository. This avoids
implying that a sample result establishes detection coverage.

## Prepare inputs

Create a `finding.json` that conforms to `manual-finding-v1`; the required
fields and a structural description are in [Schemas](SCHEMAS.md). Keep the
repository or archive on your local machine. Remote repository URLs are not a
supported input.

## Bash

```sh
python3 -m venv lumi-trace-env
. lumi-trace-env/bin/activate
python -m pip install --no-index --no-deps --disable-pip-version-check \
  ./skylark_lumi_trace-0.4.1-py3-none-any.whl

lumi-trace trace \
  --finding ./finding.json \
  --finding-format manual \
  --repository ./local-repository \
  --output ./trace-evidence

lumi-trace verify ./trace-evidence
```

## PowerShell

The virtual-environment executables are called directly, so script activation
and execution-policy changes are not required.

```powershell
py -3.12 -m venv lumi-trace-env
.\lumi-trace-env\Scripts\python.exe -m pip install `
  --no-index --no-deps --disable-pip-version-check `
  .\skylark_lumi_trace-0.4.1-py3-none-any.whl
.\lumi-trace-env\Scripts\lumi-trace.exe trace `
  --finding .\finding.json `
  --finding-format manual `
  --repository .\local-repository `
  --output .\trace-evidence
.\lumi-trace-env\Scripts\lumi-trace.exe verify .\trace-evidence
```

## Expected result

`trace` writes a locally verifiable evidence bundle. Without an explicit,
qualified reproduction plan, the expected classification is
`INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`. That is an abstention from
confirmation, not proof that the finding is absent or remediated.

Read [the product contract](STEP_1_PRODUCT_CONTRACT.md),
[privacy statement](PRIVACY_AND_DATA_HANDLING.md), and
[disclaimer](../DISCLAIMER.md) before using output in a security decision.
