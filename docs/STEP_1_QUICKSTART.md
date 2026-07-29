# Lumi Trace Step 1 Five-Minute Quickstart

This path uses the built wheel, one rights-reviewed public finding, and a
pinned public source archive. Docker, a model, an API key, and hosted inference
are not required.

The release candidate is not authorised for public distribution. Use only the
review bundle supplied by the maintainer.

Use CPython 3.11 or 3.12 with a recursion limit of at least 1,000. Other Python
implementations and minor versions are outside the current deterministic
profile.

## Files supplied to the tester

- `skylark_lumi_trace-0.4.1.dev0-py3-none-any.whl`;
- this quickstart;
- the `public-ghsa-8359-h9fx-j6v9` example directory.

Run `fetch_example.py` once while online. It acquires the archive directly from
upstream, downloads only the pinned public revision, and rejects a hash
mismatch. Core tracing is offline after that acquisition.

## Bash

```sh
python3.12 -m venv lumi-trace-env
. lumi-trace-env/bin/activate
python -m pip install ./skylark_lumi_trace-0.4.1.dev0-py3-none-any.whl

python ./public-ghsa-8359-h9fx-j6v9/fetch_example.py --output .

lumi-trace trace \
  --finding ./public-ghsa-8359-h9fx-j6v9/finding.json \
  --finding-format manual \
  --repository ./datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip \
  --output ./trace-evidence

lumi-trace verify ./trace-evidence
```

## PowerShell

```powershell
py -3.12 -m venv lumi-trace-env
.\lumi-trace-env\Scripts\Activate.ps1
python -m pip install .\skylark_lumi_trace-0.4.1.dev0-py3-none-any.whl

python .\public-ghsa-8359-h9fx-j6v9\fetch_example.py --output .

lumi-trace trace `
  --finding .\public-ghsa-8359-h9fx-j6v9\finding.json `
  --finding-format manual `
  --repository .\datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip `
  --output .\trace-evidence

lumi-trace verify .\trace-evidence
```

## Expected result

The terminal summary identifies the frozen deterministic ranker, shows the
first implementation-role locations with their true overall ranks, states that
reproduction was not requested, reports
`INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`, and gives the output and
verification command.

The ranking should place the documented implementation area in
`src/datamodel_code_generator/parser/jsonschema.py` near the first results.
The exact scores and identities are pinned in the release-candidate usability
record. This one example demonstrates the workflow only; it does not establish
generalisation, qualification, or production readiness.

`lumi-trace verify` should return JSON with `"valid": true`.

## Common corrections

- **Output already exists:** choose a new `--output` path. Trace never
  overwrites evidence.
- **Finding path cannot be read:** check the working directory and file
  permissions.
- **SARIF produces multiple findings:** add `--run-index` and
  `--result-index` to select exactly one result.
- **Archive rejected:** use the pinned archive unchanged. Lumi Trace rejects
  unsafe paths, links, special members, collisions, oversized content, and
  non-printable-ASCII repository paths in the current deterministic profile.
- **Docker unavailable:** omit `--plan` and `--image`. Docker is not part of
  this quickstart.

## Data handling

Keep `trace-evidence` private. It contains public-example finding text and
repository-derived paths, symbols, tokens, locations, and hashes. Customer
use can produce the same categories of sensitive local output. Read
`PRIVACY_AND_DATA_HANDLING.md` before using private material.
