# Getting started with Lumi Trace

This guide takes you from a clean environment to a verified evidence package. The fastest path uses the synthetic example included in the repository.

## 1. Choose a release or source checkout

For repeatable use, prefer a published version from [GitHub Releases](https://github.com/noqt/Lumi-Trace/releases).

A release installation uses the wheel attached to that release. A source installation uses the code currently checked out. The synthetic walkthrough is included in the source repository and source archive, not in the wheel.

## 2. Create an isolated Python environment

Lumi Trace supports CPython 3.11 and 3.12.

Bash:

```sh
python3 -m venv .venv
. .venv/bin/activate
```

PowerShell:

```powershell
py -3.12 -m venv .venv
```

## 3. Install Lumi Trace

From a downloaded wheel:

```sh
python -m pip install --no-deps ./skylark_lumi_trace-0.8.1-py3-none-any.whl
```

From a source checkout:

```sh
python -m pip install .
```

PowerShell can call the environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install .
```

Confirm the installation:

```sh
lumi-trace version
```

Before installation, you can verify a downloaded wheel and source archive by
keeping them with the release `SHA256SUMS` file in one directory and running:

```sh
sha256sum -c SHA256SUMS
```

See the README for the PowerShell equivalent. A matching checksum confirms the
download matches that release's published hash; it does not guarantee security
or fitness for a particular use.

## 4. Run the synthetic walkthrough

The example is intentionally small and inert. It exists to prove that installation, input parsing, ranking, export, and verification work together. It is not a performance benchmark.

Bash:

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

The ranked output should include `src/archive.py::extraction_target`.

Lumi Trace refuses to overwrite an existing output directory. Delete the synthetic output or choose a new path before rerunning:

```sh
rm -rf out/quickstart
```

PowerShell:

```powershell
Remove-Item -Recurse -Force .\out\quickstart
```

Only remove a directory after confirming it contains no evidence you need to retain.

## 5. Understand the first result

A no-Docker quickstart run normally reports:

```text
Localisation: complete
Ranked locations: 2
Confirmation: not attempted (NO_REPRODUCTION_PLAN)
Evidence classification: INSUFFICIENT_EVIDENCE
```

This is not a crash and does not invalidate the ranked candidates. Lumi Trace separates two questions:

1. **Localisation:** Which files and symbols are most relevant to the supplied finding?
2. **Confirmation:** Did an explicit witness succeed inside the restricted reproduction environment?

The quickstart answers the first question. It intentionally does not attempt the second.

## 6. Create a manual finding

Only `title` is required, but useful descriptions and keywords improve finding-guided ranking.

```json
{
  "schema_version": "manual-finding-v1",
  "id": "APPSEC-2026-014",
  "title": "Archive member path may escape the extraction root",
  "description": "Member names should be validated before being joined to the extraction root.",
  "severity": "high",
  "rule": {
    "id": "CWE-22",
    "name": "Path traversal",
    "cwes": ["CWE-22"],
    "tags": ["archive", "path-traversal"]
  },
  "locations": [
    {
      "path": "src/archive.py",
      "symbol": "extraction_target",
      "start_line": 8
    }
  ],
  "keywords": ["archive", "member", "path", "traversal", "extraction"]
}
```

Unknown fields are rejected. Repository paths must be canonical, repository-relative paths. See [Inputs and outputs](INPUTS_AND_OUTPUTS.md) and the machine-readable schema at `../schemas/manual-finding-v1.json`.

## 7. Trace a local repository

```sh
lumi-trace trace \
  --finding ./finding.json \
  --finding-format manual \
  --repository ./local-repository \
  --output ./trace-evidence
```

The repository may be a local directory, safe ZIP archive, or supported TAR-family archive. Remote Git URLs are not accepted.

## 8. Use SARIF input

For a SARIF file containing exactly one result:

```sh
lumi-trace trace \
  --finding ./results.sarif \
  --finding-format sarif \
  --repository ./local-repository \
  --output ./trace-evidence
```

For a SARIF file containing several results, select one explicitly:

```sh
lumi-trace trace \
  --finding ./results.sarif \
  --finding-format sarif \
  --run-index 0 \
  --result-index 3 \
  --repository ./local-repository \
  --output ./trace-evidence
```

Lumi Trace does not execute commands, links, or instructions found in SARIF.

## 9. Inspect and verify output

Start with:

- `candidates.json` for ranked files and symbols;
- `evidence-bundle.json` for provenance, limitations, and classification;
- `evidence.sarif` for SARIF-compatible review; and
- `manifest.json` for package hashes and identity.

Verify the package:

```sh
lumi-trace verify ./trace-evidence
```

Verification detects changed, missing, or inconsistent artifacts. It does not independently validate the vulnerability.

## Common corrections

### Output directory already exists

Choose a new `--output` path. Lumi Trace does not merge into or overwrite an evidence package.

### No candidates were emitted

The tool may have abstained because it found no positive finding-guided signal. Improve the finding description, rule metadata, keywords, or known locations without inventing facts.

### A path was rejected

The current product profile requires portable, printable-ASCII repository-relative paths and rejects traversal, links, special files, collisions, and unsafe archive members.

### Docker is unavailable

Docker is optional for localisation. Remove `--plan` and `--image` unless you intend to run an explicit reproduction plan.

### A repository is unsupported

Use a regular local directory, safe ZIP, or supported TAR-family archive. Remote repositories, mutable archives, links, and special files are outside the current contract.

## Next steps

- Read [Product scope and limitations](PRODUCT_SCOPE.md) before relying on a result.
- Read [Inputs and outputs](INPUTS_AND_OUTPUTS.md) when integrating SARIF or JSON.
- Read [Optional local reproduction](REPRODUCTION.md) before executing repository code.
- Keep generated evidence private as described in [Privacy](PRIVACY.md).
