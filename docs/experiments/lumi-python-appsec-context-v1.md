# Synthetic Python AppSec context example

Experiment marker: `LUMI-EXP-PYAPPSEC-01`

This worked example shows how Lumi Trace `v0.10.0` maps an already-supplied
synthetic Python application-security finding to likely source context and
produces a hash-bound evidence package. It uses only the inert quickstart
fixture distributed in the existing `v0.10.0` source archive. Do not substitute
a real finding, private repository, proprietary source, live vulnerability,
secret, raw log, screenshot, attachment, or personal data.

Lumi Trace is not a vulnerability scanner. This example does not establish
that a vulnerability is real, exploitable, fixed, or absent; it does not replace
SAST or qualified review. The expected result is localisation with
`INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`, not confirmation.

## Measurement status and fixed window

This page does not start an experiment merely by existing on a local branch.
`T0` is the public GitHub timestamp when an independently accepted exact
worked-example commit reaches public `main`. The measurement window is exactly
`[T0, T0 + 14 days)`; it is not extended, restarted, reposted, or moved after
results are seen.

Only a qualifying public, source-bound, unaffiliated synthetic workflow receipt
created in that window can count. Zero qualifying receipts at the cutoff is
`ZERO_SIGNAL_CHANNEL_REJECT`. Downloads, page views, repository traffic, clones,
stars, watches, forks, generic mentions, internal or CI runs, and publication of
the example do not count. A receipt is not proof of installation, productive
use, repeat use, adoption, demand, security effectiveness, or willingness to
pay.

## 1. Obtain and verify the exact release

From the existing [`v0.10.0` GitHub Release](https://github.com/noqt/Lumi-Trace/releases/tag/v0.10.0),
place these three files in one new directory:

- `skylark_lumi_trace-0.10.0-py3-none-any.whl` — 174,344 bytes;
- `skylark_lumi_trace-0.10.0.tar.gz` — 147,845 bytes; and
- `SHA256SUMS`.

The release is bound to source commit
`60ceacaa5b92718cc50bbed4e5ce34da7e85e093`. Verify the two package files
against the release checksum record before installation.

Bash:

```sh
sha256sum -c SHA256SUMS
```

PowerShell:

```powershell
Get-Content .\SHA256SUMS | ForEach-Object {
  $expected, $filename = $_ -split '\s{2}', 2
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $filename).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "Checksum mismatch: $filename" }
}
```

The exact checksums are:

```text
fb788f981dbf681d08f2edf2515db8e968669ef23f5109cac31bfad866cce11d  skylark_lumi_trace-0.10.0-py3-none-any.whl
a28123e75fd4a47bd551a0c300d043b0156badba61843c3769a649b8017fe690  skylark_lumi_trace-0.10.0.tar.gz
```

A checksum match proves agreement with the release record only. It is not a
security, fitness, installation, or provenance guarantee beyond those bytes.

## 2. Install and identify the bundled synthetic inputs

Extract the source archive into the same new working directory. Create a fresh
CPython 3.11 or 3.12 environment and install the verified wheel without
dependencies:

Bash:

```sh
tar -xzf skylark_lumi_trace-0.10.0.tar.gz
cd skylark_lumi_trace-0.10.0
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps ../skylark_lumi_trace-0.10.0-py3-none-any.whl
lumi-trace version
```

PowerShell:

```powershell
tar -xzf .\skylark_lumi_trace-0.10.0.tar.gz
Set-Location .\skylark_lumi_trace-0.10.0
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-deps `
  ..\skylark_lumi_trace-0.10.0-py3-none-any.whl
.\.venv\Scripts\lumi-trace.exe version
```

The version receipt must report `"version": "0.10.0"` and
`"inventory_id": "skylark.lumi.trace"`.

The released quickstart inputs are now under `examples/quickstart/`. Verify
their exact bytes:

```text
finding.json
  sha256:85a3d1c0bfddc3c3073394842702077fe34e5abef20de179c6959d8827cb403f
repository/src/archive.py
  sha256:a6cc1774c6d27003e014ca67edf2d9b7baf1a530bcbdab4ef2714cd388664f8f
```

The source fixture contains one 312-byte file. Lumi's deterministic
`lumi-tree-sha256-v1` identity for that fixture is:

```text
repository:c1c0f34490cc76c5a7af819555c9a4178dc3f0bd880ba18b428d1a653fd46e24
```

## 3. Trace and verify

Continue from the extracted `skylark_lumi_trace-0.10.0` directory. Choose a new
output directory that does not already exist; never delete or overwrite an
earlier evidence package merely to rerun the example.

Bash:

```sh
lumi-trace trace \
  --finding examples/quickstart/finding.json \
  --finding-format manual \
  --repository examples/quickstart/repository \
  --output out/lumi-exp-pyappsec-01

lumi-trace verify out/lumi-exp-pyappsec-01
sha256sum out/lumi-exp-pyappsec-01/evidence-bundle.json
```

PowerShell:

```powershell
.\.venv\Scripts\lumi-trace.exe trace `
  --finding .\examples\quickstart\finding.json `
  --finding-format manual `
  --repository .\examples\quickstart\repository `
  --output .\out\lumi-exp-pyappsec-01

.\.venv\Scripts\lumi-trace.exe verify .\out\lumi-exp-pyappsec-01
Get-FileHash -Algorithm SHA256 `
  -LiteralPath .\out\lumi-exp-pyappsec-01\evidence-bundle.json
```

Expected source-bound result:

```text
Top implementation path: src/archive.py::extraction_target
Confirmation: not attempted (NO_REPRODUCTION_PLAN)
Evidence classification: INSUFFICIENT_EVIDENCE
verify: valid
finding input sha256: 85a3d1c0bfddc3c3073394842702077fe34e5abef20de179c6959d8827cb403f
repository manifest: c1c0f34490cc76c5a7af819555c9a4178dc3f0bd880ba18b428d1a653fd46e24
```

On CPython 3.12.10 for Windows, two clean runs with these exact inputs produced
byte-identical package artifacts. The exact observed `evidence-bundle.json` was
6,077 bytes at SHA-256
`f016bc8f06b46d4c877fd9cb8f59edcb03fd9d89869a79eb947fd917cb5ece1e`,
with bundle identity
`evidence-bundle:da81db2425cc09c9fcb68fa11b43ba7af246daabe02e216102dba7f32c93e3c1`.
The bundle records the exact finding input hash and repository manifest above.
Because the evidence bundle also records runtime identity, participants must
report the hash their own supported run actually produced rather than copying
this platform-specific observed hash.

## 4. Privacy-safe public receipt

Do not send a receipt through Lumi Issues, Discussions, a pull-request comment,
private vulnerability reporting, email, direct message, or another NOQT intake
route. This example creates no account, endpoint, response obligation, or
permission to submit material to NOQT. If you independently choose to record a
result, use a publicly readable GitHub commit or immutable blob you control and
include only these fields:

```yaml
experiment_id: LUMI-EXP-PYAPPSEC-01
worked_example_commit: <exact public commit containing this worked example>
lumi_version: 0.10.0
wheel_sha256: fb788f981dbf681d08f2edf2515db8e968669ef23f5109cac31bfad866cce11d
synthetic_fixture_blob_sha256: a6cc1774c6d27003e014ca67edf2d9b7baf1a530bcbdab4ef2714cd388664f8f
finding_input_sha256: 85a3d1c0bfddc3c3073394842702077fe34e5abef20de179c6959d8827cb403f
evidence_bundle_sha256: <sha256 from your completed run>
ranked_path: src/archive.py::extraction_target
verify_result: valid
data_statement: synthetic/public input only; no secret, private source, or live vulnerability
```

Do not add a name, email, organisation, geography, device or machine identifier,
IP address, environment path, raw log, screenshot, attachment, private source,
real finding, exploit detail, or other personal/private content. Public evidence
is self-attested as to who ran the commands. A copied or unverifiable receipt,
a bot result, a result from NOQT or this experiment's builders/reviewers, or a
result prompted, contacted, or paid for by NOQT does not qualify.

At most one receipt per public actor and unique source identity may count.
Mirrors, reposts, identical receipt/output hashes, and ambiguous affiliation are
deduplicated or excluded. Observation is limited to bounded public GitHub
searches at day 7 and the cutoff; private analytics are not inspected.

## Safety stop and correction

Stop and do not publish or copy any reference that contains or appears to expose
a secret, private or customer source, personal data, a live or unpatched
vulnerability, harmful material, an incorrect checksum, or an unsupported
claim. Preserve only its public URL and digest for a separately authorised
review; do not reproduce unsafe content.

If this example's commands, hashes, or claims are wrong, measurement stops. The
history-preserving correction route is an ordinary reviewed commit on this same
repository that removes the active README invitation and replaces this page's
participation text with a dated `EXPERIMENT CLOSED` notice and result. Do not
force-push, rewrite history, delete this page, delete participant content, change
the release or tag, enable Issues or Discussions, or silently restart the
window.
