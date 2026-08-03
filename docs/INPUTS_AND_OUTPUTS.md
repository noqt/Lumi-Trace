# Inputs and outputs

## Manual finding input

The simplest input is `manual-finding-v1`.

Only `title` is required. The most useful optional fields are `description`, `rule`, `locations`, and `keywords`.

```json
{
  "schema_version": "manual-finding-v1",
  "id": "APPSEC-2026-014",
  "title": "Archive member path may escape the extraction root",
  "description": "Member names should be validated before they are joined to the extraction root.",
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

The contract is strict. Unknown fields are rejected rather than ignored. The authoritative schema is `../schemas/manual-finding-v1.json`.

### Location rules

A location can use `path` or `uri`, but not both. Paths must be safe repository-relative paths. Line and column values start at 1.

Locations are evidence supplied by the finding; they are not treated as ground truth.

## SARIF input

Lumi Trace accepts SARIF 2.1.0.

A `trace` run operates on exactly one result. When a SARIF document contains several runs or results, select one with:

```sh
--run-index 0 --result-index 3
```

Remote artifact locations and unresolved URI bases are rejected. No SARIF field is interpreted as a command or reproduction plan.

### Batch SARIF triage

Use `triage` when one local SARIF 2.1.0 report contains several results for the same local repository:

```sh
lumi-trace triage \
  --sarif findings.sarif \
  --repository ./local-repository \
  --output ./triage-evidence
```

`--top-k` defaults to ten unique paths per completed finding. `--max-findings` defaults to 100 and may not exceed 1,000. The command fails before repository localisation if its selected result count or requested aggregate contribution bound is too large; it never silently truncates results.

Malformed individual results are recorded as `NORMALIZATION_FAILED` or `LOCALIZATION_FAILED` error artifacts. Valid results still complete and the package verifies, but the command exits with code `5` for that partial-success state. Exit `0` means every selected result completed. Queue order is a deterministic review priority, not probability or exploitability.

### GitHub Actions wrapper

The first-party GitHub Action passes only a local SARIF path, a local workspace
repository path, and existing `triage` bounds to this same batch contract. Its
job summary and outputs are derived only after package verification. It can
optionally retain the verified package as a GitHub artifact; this is disabled by
default because the package may contain sensitive metadata. See [GitHub Actions
integration](GITHUB_ACTIONS.md) for its inputs, CI policies, and exit behaviour.

## Normalized finding input

`normalized-finding-v1` is the canonical internal representation produced by the manual and SARIF importers. It can be supplied directly with:

```sh
--finding-format normalized
```

Use this form when another controlled workflow already produces Lumi Trace's normalized contract.

## Repository input

Supported repository sources are:

- a local directory;
- a safe ZIP archive; or
- a bounded supported TAR-family archive.

The current profile rejects links, special files, unsafe paths, path collisions, encrypted ZIP members, mutable or unsupported archives, and repository-relative paths outside printable ASCII.

Remote Git URLs are not supported. Clone or otherwise acquire the repository separately, then give Lumi Trace the local path.

## Reproduction plan input

Reproduction is optional and uses a separate `reproduction-plan-v1` file. A plan is never inferred from a finding or repository.

See [Optional local reproduction](REPRODUCTION.md).

## Output directory

A complete trace writes a new directory. Existing directories are not overwritten.

| Artifact | Contains |
| --- | --- |
| `normalized-finding.json` | Canonical finding, source metadata, locations, keywords, and fingerprints. |
| `repository-index.json` | Snapshot identity, files, hashes, bounded tokens, symbols, and exclusions. |
| `candidates.json` | Ranked candidates, roles, deterministic scores, score reasons, and abstention state. |
| `evidence-bundle.json` | Combined provenance, ranking summary, reproduction state, classification, and limitations. |
| `evidence.sarif` | SARIF 2.1.0 projection of the selected finding and ranked locations. |
| `manifest.json` | Exact artifact membership, sizes, SHA-256 hashes, and package identity. |
| `reproduction-plan.json` | Canonical supplied plan, when reproduction was requested. |
| `reproduction-receipt.json` | Sandbox attestations, bounded step results, and witness matches, when reproduction was requested. |

A batch triage package instead contains one shared `repository-index.json`, `normalized-findings.json`, `review-queue.json`, `triage-summary.json`, `triage.sarif`, per-result candidate and evidence artifacts under `findings/`, any result-local errors under `errors/`, and a manifest binding every file.

SARIF output omits source snippets. It can still contain finding text, paths, symbols, and source regions.

## Verification

```sh
lumi-trace verify ./trace-evidence
```

Verification checks the package's contracts, identities, hashes, membership, and cross-artifact consistency.

To validate one supported JSON contract:

```sh
lumi-trace validate ./trace-evidence/candidates.json
```

The built-in validator is not a general-purpose JSON Schema engine. The published schemas under `../schemas/` are the external machine-readable contracts.

## Schema compatibility

Schema names and `schema_version` values are versioned contracts. Breaking reinterpretation of an existing contract is not permitted; a breaking change requires a new schema version.

Historical implementation identities are retained for verification where required, but they are not part of the normal user workflow. Refer to release notes or technical provenance records only when reproducing an older evidence package.
