# Public example: GHSA-8359-h9fx-j6v9

This example gives Lumi Trace a real public finding and the exact affected
source revision of `koxudaxi/datamodel-code-generator`. It demonstrates local,
deterministic implementation-location ranking. It does not reproduce the
vulnerability, execute upstream code, prove generalisation, or qualify Lumi
Trace.

The finding is a Skylark-authored paraphrase of the public advisory. It
deliberately omits known target paths and symbols so the ranker does not receive
the answer. See [RIGHTS_AND_PROVENANCE.md](RIGHTS_AND_PROVENANCE.md) before
using or redistributing any material.

`finding.json` is the primary quickstart input. `finding.sarif` is an authored
single-result representation of the same finding for clean-install SARIF
testing; it also omits target locations.

## Fetch the reviewed source archive

The only networked step is this explicit acquisition command:

```sh
python fetch_example.py --output .
```

The standard-library-only fetcher downloads
`datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip`
from GitHub, verifies its pinned SHA-256, rejects links, special files and
unsafe member paths, and verifies the upstream `LICENSE`, third-party notice and
remediation-relevant source file. It never extracts or executes the archive. A
mismatching existing file fails closed.

## Run Lumi Trace

From this directory, after installing the candidate Lumi Trace wheel:

```sh
lumi-trace trace \
  --finding finding.json \
  --finding-format manual \
  --repository datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip \
  --output evidence

lumi-trace verify evidence
```

PowerShell uses the same arguments on one line:

```powershell
lumi-trace trace --finding finding.json --finding-format manual --repository datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip --output evidence
lumi-trace verify evidence
```

No Docker image, API key, model, upstream dependency installation, or
vulnerability reproduction is required. After the archive has been acquired,
the Trace and verification commands do not need network access.

## Expected output

The command should emit a concise terminal summary, an `evidence-bundle.json`,
an `evidence.sarif`, and a hash manifest under `evidence/`. No reproduction was
requested, so confirmation must explicitly abstain rather than report an
operational error or a verified exploit.

Reviewers should expect the ranked locations to include the implementation area
changed by the upstream fix:

- `src/datamodel_code_generator/parser/jsonschema.py`;
- the existing `_get_ref_body`, `_get_ref_body_from_url`, or
  `_get_ref_body_from_remote` reference-resolution symbols.

Those expected locations come from reviewing the public fixed commit and are
not present in `finding.json`. A different or missing ranking must be recorded
as the observed result; do not rewrite the finding to supply the answer.

Do not commit the downloaded archive or generated evidence. Both can contain
third-party source paths and repository-derived metadata.
