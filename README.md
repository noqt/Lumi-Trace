# Lumi Trace

**Turn a known security finding into ranked source locations and a verifiable evidence package—without uploading your repository.**

Lumi Trace is a local command-line tool for application-security engineers, software maintainers, and security reviewers. Give it an existing finding and a local Python repository or supported archive. It will:

1. normalise the finding;
2. create an immutable local snapshot of the repository;
3. rank the files and symbols most relevant to the finding; and
4. export human-reviewable JSON and SARIF evidence.

Lumi Trace is deterministic: the same supported inputs produce the same ranked artifacts. Its primary workflow has no hosted-inference path, requires no API key, and sends no product telemetry.

> **Stable release:** [`v0.4.1`](https://github.com/noqt/Lumi-Trace/releases/tag/v0.4.1) is the current published release. The `main` branch is preparing the unreleased `v0.4.2` documentation and package-boundary maintenance update; use the documentation attached to a release when you need an exact match.

## When Lumi Trace is useful

Use Lumi Trace when you already have a finding from a scanner, advisory, code review, penetration test, or incident investigation and need to answer:

- Which files and functions should a reviewer inspect first?
- What evidence was used to produce that ranking?
- Can the result be exported back to SARIF?
- Can an explicit reproduction plan be run locally under a restricted container policy?

Lumi Trace is **not** a vulnerability scanner. It does not discover new vulnerabilities, generate patches or exploits, decide that a repository is safe, or execute instructions embedded in findings or source code.

## Key properties

- **Local by default.** Findings, source, indexes, and evidence stay on your machine.
- **Deterministic.** Ranking and artifact identities are reproducible for supported inputs.
- **Auditable.** Outputs include the normalized finding, repository identity, candidates, SARIF, and a hash-bound manifest.
- **Fail-closed.** Unsupported or ambiguous inputs are rejected or reported as abstentions rather than guessed through.
- **Optional restricted reproduction.** A user-authored plan can run in a preloaded, network-denied Linux container. Docker is not required for localisation.

## Requirements

- CPython 3.11 or 3.12.
- A local repository directory, ZIP archive, or supported TAR-family archive.
- Printable-ASCII repository-relative paths in the current product profile.
- Docker-compatible Linux containers only when optional reproduction is requested.

The current supported localisation profile is Python-focused. Other files may be indexed as context, but broader language-localisation coverage is not claimed.

## Install

### From a GitHub Release

Download the wheel from the [GitHub Release](https://github.com/noqt/Lumi-Trace/releases/tag/v0.4.1), then install it in a clean virtual environment.

Bash:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps ./skylark_lumi_trace-0.4.1-py3-none-any.whl
lumi-trace version
```

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-deps `
  .\skylark_lumi_trace-0.4.1-py3-none-any.whl
.\.venv\Scripts\lumi-trace.exe version
```

Use the filename from the release you downloaded. Do not copy the `0.4.1` command against a different release.

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

The source repository and source archive include a small Skylark-authored fixture under `examples/quickstart/`. It demonstrates installation, ranking, output, and verification. It is not a benchmark or a claim about real-world detection coverage.

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
Ranked locations: 2
Confirmation: not attempted (NO_REPRODUCTION_PLAN)
Evidence classification: INSUFFICIENT_EVIDENCE
```

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

Lumi Trace also accepts a selected SARIF 2.1.0 result and an already-normalized finding. See [Inputs and outputs](docs/INPUTS_AND_OUTPUTS.md).

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
- [Product scope and limitations](docs/PRODUCT_SCOPE.md)
- [Inputs and outputs](docs/INPUTS_AND_OUTPUTS.md)
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

Skylark-owned source code and documentation are licensed under Apache-2.0. User-supplied repositories, findings, generated evidence, model weights, and third-party material are not licensed by that source-code licence.

Community support is best effort through GitHub Issues. There is no service-level agreement.
