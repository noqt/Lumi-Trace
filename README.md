# Lumi: Trace functionality

**Turn a known security finding into ranked source locations and a verifiable evidence package—without uploading your repository.**

> **Watch the real scanner-to-review handoff.** [See the passing Bandit
> run](https://github.com/noqt/Lumi-Trace/actions/workflows/bandit-sarif-demo.yml?query=branch%3Amain),
> then [fork Lumi Trace](https://github.com/noqt/Lumi-Trace/fork) and open
> **Actions -> Try Lumi on synthetic Bandit SARIF -> Run workflow**. Bandit
> 1.9.4 scans the inert fixture before Lumi ranks it. There is no local install,
> API key, private source, or evidence upload.

If Lumi ranks the wrong path, explains the result badly, or doesn't run,
[send us the public run or exact blocker](https://github.com/noqt/Lumi-Trace/issues/new?template=bandit_demo_result.yml).
A useful failure report is more valuable than a star. The
[three-step guide](https://github.com/noqt/Lumi-Trace/blob/main/docs/TRY_BANDIT_DEMO.md)
shows the full flow.

This repository provides Trace functionality for Lumi as a local command-line
tool for application-security engineers, software maintainers, and security
reviewers. Give it an existing finding and a local Python repository or
supported archive. It will:

1. normalise the finding;
2. create an immutable local snapshot of the repository;
3. rank the files and symbols most relevant to the finding; and
4. export human-reviewable JSON and SARIF evidence.

Lumi's Trace workflow is deterministic: the same supported inputs produce the
same ranked artifacts. Its primary workflow has no hosted-inference path,
requires no API key, and sends no product telemetry.

> **V0.10.1** accepts narrowly safe repository-internal file symlinks as inert
> Git-style target-byte stubs while continuing to reject external, chained,
> directory, `.git`, mount, reparse, junction, and archive links. It retains
> V0.10.0's component-scoped triage, the first-party GitHub Actions wrapper
> around local batch SARIF triage, and direct checksum verification from a flat
> GitHub Release download. Published artifacts are listed on
> [GitHub Releases](https://github.com/noqt/Lumi-Trace/releases).

## When Trace functionality is useful

Use Lumi Trace when you already have a finding from a scanner, advisory, code review, penetration test, or incident investigation and need to answer:

- Which files and functions should a reviewer inspect first?
- What evidence was used to produce that ranking?
- Can the result be exported back to SARIF?
- Can an explicit reproduction plan be run locally under a restricted container policy?

Lumi's Trace functionality is **not** a vulnerability scanner. It does not
discover new vulnerabilities, generate patches or exploits, decide that a
repository is safe, or execute instructions embedded in findings or source
code.

## Key properties

- **Local by default.** Findings, source, indexes, and evidence stay on your machine.
- **Deterministic.** Ranking and artifact identities are reproducible for supported inputs.
- **Auditable.** Outputs include the normalized finding, repository identity, candidates, SARIF, and a hash-bound manifest.
- **Fail-closed.** Unsupported or ambiguous inputs are rejected or reported as abstentions rather than guessed through.
- **Optional restricted reproduction.** A user-authored plan can run in a preloaded, network-denied Linux container. Docker is not required for localisation.

### What changed in V0.7.1

V0.7.1 includes V0.6.1's unique-path projection: it keeps the V0.5 deterministic score and role-aware ranking intact, then projects raw ranked anchors into one representative per repository path. The default output is ten unique review paths rather than repeated symbols from the same file. Each emitted path retains the score reasons and source location of its highest-ranked anchor.

This is a presentation and review-flow change, not a new vulnerability-detection model or a claim of discovery accuracy. V0.5 evidence remains verifiable under its original ranker identity.

On a frozen, label-blind public confirmation set of 12 reviewed Python vulnerability-fix cases, an accepted target path appeared in the V0.6 shortlist’s first ten unique paths in 11 cases (91.7%); median first accepted target-path rank was 1. These are bounded known-finding localisation results, not vulnerability-discovery accuracy or general security coverage.

## Requirements

- CPython 3.11 or 3.12.
- A local repository directory, ZIP archive, or supported TAR-family archive.
- Printable-ASCII repository-relative paths in the current product profile.
- Docker-compatible Linux containers only when optional reproduction is requested.

The current supported localisation profile is Python-focused. Other files may be indexed as context, but broader language-localisation coverage is not claimed.

## Install

### From a GitHub Release

Download the wheel for the version you want from [GitHub Releases](https://github.com/noqt/Lumi-Trace/releases), then install it in a clean virtual environment.

Bash:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps ./skylark_lumi_trace-0.10.1-py3-none-any.whl
lumi-trace version
```

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-deps `
  .\skylark_lumi_trace-0.10.1-py3-none-any.whl
.\.venv\Scripts\lumi-trace.exe version
```

Use the filename from the release you downloaded. Do not copy the `0.10.1` command against a different release.

### Verify a downloaded release

Keep the wheel, source archive, and `SHA256SUMS` from the same GitHub Release
in one directory. On Bash-compatible systems, verify both package files before
installing:

```sh
sha256sum -c SHA256SUMS
```

In PowerShell, run this from the same flat directory:

```powershell
Get-Content .\SHA256SUMS | ForEach-Object {
  $expected, $filename = $_ -split '\s{2}', 2
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $filename).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "Checksum mismatch: $filename" }
}
```

No output means both package hashes matched. A checksum match establishes that
the downloaded package matches the release record; it is not a security or
fitness guarantee.

### From source

```sh
git clone https://github.com/noqt/Lumi-Trace.git
cd Lumi-Trace
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
lumi-trace version
```

## Five-minute synthetic walkthrough

The source repository and source archive include a small synthetic fixture under `examples/quickstart/`, distributed under Apache-2.0. It demonstrates installation, ranking, output, and verification. It is not a benchmark or a claim about real-world detection coverage.

### First success from a source build

This demo is available in source builds containing this change. Published
v0.10.0 wheels do not include lumi-trace demo; until a release containing it
is published, use the [From source](#from-source) installation instructions.

From any empty, non-repository directory after installing the source build, run the
self-contained synthetic quickstart demo:

```sh
lumi-trace demo --output lumi-demo-output
lumi-trace verify lumi-demo-output
```

The command uses only the inert `examples/quickstart` fixture bundled by the
demo workflow. It does not scan, execute repository code, use Docker or the
network, or read a private finding. The result is explicitly synthetic and
should report `INSUFFICIENT_EVIDENCE` with `NO_REPRODUCTION_PLAN`; it is a
workflow check, not a security verdict or independent-use evidence. Choose a
new output directory for each run; existing output is never overwritten.

From the repository root:

```sh
lumi-trace trace \
  --finding examples/quickstart/finding.json \
  --finding-format manual \
  --repository examples/quickstart/repository \
  --output out/quickstart

lumi-trace verify out/quickstart
```

PowerShell:

```powershell
.\.venv\Scripts\lumi-trace.exe trace `
  --finding .\examples\quickstart\finding.json `
  --finding-format manual `
  --repository .\examples\quickstart\repository `
  --output .\out\quickstart

.\.venv\Scripts\lumi-trace.exe verify .\out\quickstart
```

The summary should place `src/archive.py::extraction_target` among the leading implementation locations.

The walkthrough does not supply a reproduction plan, so the human summary is expected to include:

```text
Localisation: complete
Ranked locations: 1
Confirmation: not attempted (NO_REPRODUCTION_PLAN)
Evidence classification: INSUFFICIENT_EVIDENCE
```

The fixture has a two-candidate universe. V0.10.1 projects those candidates to
one unique ranked review path, so the human summary reports one ranked location.

That does **not** mean localisation failed. It means candidate ranking completed, but Lumi Trace was not asked to execute a witness and therefore did not confirm the finding. See [Understanding results](docs/PRODUCT_SCOPE.md#localisation-and-confirmation-are-separate).

Choose a new `--output` directory for each run. Lumi Trace does not overwrite an existing evidence package.

## Run against your own finding

A minimal manual finding is:

```json
{
  "schema_version": "manual-finding-v1",
  "title": "Archive member path may escape the extraction root",
  "description": "Member names should be validated before they are joined to the extraction root.",
  "severity": "high",
  "keywords": ["archive", "member", "path", "traversal"]
}
```

Save it as `finding.json`, then run:

```sh
lumi-trace trace \
  --finding finding.json \
  --finding-format manual \
  --repository /path/to/local/repository \
  --output out/my-trace
```

Lumi Trace also accepts a selected SARIF 2.1.0 result and an already-normalized finding. For an entire bounded SARIF report, use batch triage:

```sh
lumi-trace triage \
  --sarif findings.sarif \
  --repository /path/to/local/repository \
  --output out/triage
```

Batch triage creates a per-result shortlist and one unique-path review queue. Queue order is review priority, not probability, exploitability, or a repository safety verdict. A malformed individual result is retained as an error record while valid results complete; that verified partial-success outcome exits with code `5`.

### Review a verified batch package from current source

The `review` command is available from source at commit
`1ca7a3922cd29a6976bb1ce65acac7de467451bc`. The currently published V0.10.0
wheel does not include it. Install that exact source revision into a fresh
CPython 3.11 or 3.12 environment:

```sh
python -m pip install --no-deps "git+https://github.com/noqt/Lumi-Trace.git@1ca7a3922cd29a6976bb1ce65acac7de467451bc"
```

Use a local SARIF 2.1.0 report whose selected results identify physical Python
implementation locations under an authorised repository or pre-selected
component root. Filter container layers, dependency or OS inventory,
infrastructure/configuration, and pathless findings in the producer workflow.
For SARIF that uses `%SRCROOT%`, verify that it maps to the intended local
repository before continuing. Choose a new output directory; Lumi does not
replace an existing package.

```sh
lumi-trace triage \
  --sarif findings.sarif \
  --repository /path/to/local/repository \
  --output out/triage
lumi-trace verify out/triage
lumi-trace review out/triage --limit 20
```

`review` accepts verified batch triage packages only. It verifies the complete
package before emitting a page of repository-relative review metadata. Continue
with the exclusive queue-rank cursor returned by the previous page:

```sh
lumi-trace review out/triage --after-rank 20 --limit 20
```

The limit must be from 1 to 200. Queue order is review priority, not probability,
exploitability, or proof that a vulnerability exists. The review page omits raw
finding messages, snippets, result-error details, and absolute host paths, but
the underlying evidence package can still contain sensitive findings, paths,
symbols, hashes, and runtime metadata. Keep the package access-controlled and
out of source control, public issues, and public artifacts. These commands run
locally with no Lumi product telemetry or API key; they do not make the
surrounding operating system, Python, Git, shell, or backups private.

See [Inputs and outputs](docs/INPUTS_AND_OUTPUTS.md).

## GitHub Actions

Already have SARIF from your scanner? Use the [GitHub Actions integration](docs/GITHUB_ACTIONS.md) with a local SARIF 2.1.0 report whose selected results identify physical Python implementation locations under an authorised repository or pre-selected component root. Container layers, OS or dependency inventory, infrastructure/configuration, and pathless findings should remain in the scanner's native filtering and producer workflow. For eligible findings, Lumi prioritises known results into a deterministic reviewer queue and verifies the resulting evidence package. If one result is invalid, valid results can still be retained in a verified partial package while the default policy keeps CI red.

Lumi does not scan code, repair malformed SARIF, decide whether findings are true, or declare a repository safe. Artifact upload is off by default. GitHub still retains normal workflow logs and the job summary under repository or organisation settings.

Evaluating first? Use the [synthetic Bandit walkthrough](docs/TRY_BANDIT_DEMO.md). It demonstrates the handoff only; it is not independent use or adoption.

## What gets written

A normal localisation run produces:

| File | Purpose |
| --- | --- |
| `normalized-finding.json` | Canonical representation of the selected finding. |
| `repository-index.json` | Local snapshot identity and deterministic file/symbol index. |
| `candidates.json` | Ranked candidate files and symbols with score reasons. |
| `evidence-bundle.json` | Combined ranking, provenance, limitations, and classification. |
| `evidence.sarif` | SARIF 2.1.0 projection for compatible tools. |
| `manifest.json` | File sizes, SHA-256 hashes, and package identity. |

When optional reproduction is requested, the package also contains the validated plan and reproduction receipt.

Verify an output directory at any time:

```sh
lumi-trace verify out/my-trace
```

Verification checks structure, identities, hashes, and cross-artifact consistency. It does not independently prove that the security finding is true.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [Synthetic Python AppSec context example](docs/experiments/lumi-python-appsec-context-v1.md) — a checksum- and hash-bound supplied-finding walkthrough using only the bundled inert fixture; it is not vulnerability discovery, exploitability evidence, productive use, or adoption evidence.
- [Product scope and limitations](docs/PRODUCT_SCOPE.md)
- [Inputs and outputs](docs/INPUTS_AND_OUTPUTS.md)
- [GitHub Actions integration](docs/GITHUB_ACTIONS.md)
- [Optional local reproduction](docs/REPRODUCTION.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Runtime threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

Machine-readable JSON Schemas are published under [`schemas/`](schemas/).

## Security and privacy

Repository content is treated as untrusted data during localisation and is not imported or executed. Optional reproduction occurs only when the operator supplies a separate plan and immutable local container-image reference.

Evidence packages can still contain sensitive finding text, repository paths, symbols, hashes, and optional bounded process output. Keep them access-controlled and do not attach private evidence to public issues.

Report suspected vulnerabilities through GitHub's private vulnerability-reporting flow described in [SECURITY.md](SECURITY.md).

## Licence and support

Source code and documentation distributed from this repository are licensed under Apache-2.0. User-supplied repositories, findings, generated evidence, model weights, and third-party material are not licensed by that source-code licence.

Community support is best effort through GitHub Issues. There is no service-level agreement.
