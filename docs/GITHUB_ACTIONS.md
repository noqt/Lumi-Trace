# GitHub Actions integration

Lumi Trace V0.10.1 runs the existing local batch-SARIF triage workflow inside a
GitHub Actions job. It does not scan a repository, call a hosted model, post PR
comments, or decide that a finding is exploitable. Your workflow must create a
local SARIF 2.1.0 file first.

The action reads that SARIF file and the checked-out repository, then writes a
bounded reviewer summary and a verified evidence package. The queue is a review
priority only, not probability, exploitability, or a repository safety result.

## Minimal step

After checkout and the step that writes `results.sarif`, add:

```yaml
- name: Prioritise scanner findings
  uses: noqt/Lumi-Trace@v0.10.1
  with:
    sarif: results.sarif
```

Use the exact release tag that you have chosen. For a higher-assurance workflow,
replace the tag with the immutable commit SHA shown by that release. The action
sets up CPython 3.12 itself and needs no Lumi account, API key, container, or
Lumi-specific service.

Your job normally needs only:

```yaml
permissions:
  contents: read
```

The consumer workflow remains responsible for checkout and for producing the
SARIF file. Lumi Trace never installs or runs a scanner.

## Policy and evidence example

This example keeps a verified evidence package as a private workflow artifact
and makes a `high` or `critical` scanner finding fail the job after the summary
and artifact steps run:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1

  # Run your existing scanner here. It must write results.sarif locally.

  - name: Prioritise scanner findings
    uses: noqt/Lumi-Trace@v0.10.1
    with:
      sarif: results.sarif
      fail-on-severity: high
      upload-artifact: true
      artifact-name: lumi-trace-evidence
```

Do not upload evidence from a repository or finding you are not authorised to
store in GitHub. Evidence can contain finding text, paths, symbols, source
regions, hashes, and score reasons. Artifact upload is therefore disabled by
default.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `sarif` | required | Local SARIF 2.1.0 file inside `GITHUB_WORKSPACE`. |
| `repository` | `.` | Checked-out repository directory or supported archive inside the workspace. |
| `output` | `.lumi-trace` | New workspace-relative output directory. Existing output is rejected. |
| `top-k` | `10` | Unique paths retained for each completed finding. |
| `max-findings` | `100` | Selected-result cap, from 1 to 1,000. |
| `fail-on-partial` | `true` | Fail after handling a verified partial package. |
| `fail-on-severity` | `none` | Fail on scanner-supplied `critical`, `high`, `medium`, or `low` and above. |
| `upload-artifact` | `false` | Upload the verified package as a GitHub workflow artifact. |
| `artifact-name` | `lumi-trace-evidence` | Artifact name when upload is enabled. |

All input paths must resolve inside `GITHUB_WORKSPACE`. Lumi Trace rejects path
escapes, direct symlinks, unsafe output locations, and existing output
directories before triage begins.

## Outputs and job summary

The action exposes `status`, `exit-code`, `selected-results`,
`completed-localizations`, `result-local-errors`, `unique-review-paths`, and
the workspace-relative `evidence-path`. When artifact upload is enabled, it
also exposes GitHub's `artifact-id` and `artifact-digest` outputs.

The GitHub job summary contains counts and, at most, ten review paths with
their scanner-supplied severity, finding count, and best shortlist rank. It
does not include source snippets, raw SARIF messages, or absolute runner paths.

## Exit behaviour

| Status | Final exit code | Meaning |
| --- | ---: | --- |
| `complete` | 0 | Every selected result completed and no configured policy triggered. |
| `partial-success` | 0 | Some results were invalid, but the verified package was retained because `fail-on-partial: false` was chosen. |
| `partial-failed` | 5 | A verified partial package exists and the default partial policy failed the job. |
| `policy-failed` | 1 | A configured scanner-severity threshold was met. This is not a Lumi Trace vulnerability verdict. |
| `fatal-error`, `integrity-failure`, `input-error`, or `adapter-error` | 2 | No verified package is being claimed as successful. |

The action verifies a complete or partial package before describing it as
verified or uploading it. A severity policy reads the normalized level supplied
by the upstream scanner; it never uses a Lumi Trace score as a risk threshold.

## What remains local and what GitHub receives

Lumi Trace's ranking runtime makes no product network request and does not
execute repository code or SARIF content. In this integration, GitHub provides
the hosted runner and receives the job logs and summary. It receives an evidence
artifact only when `upload-artifact: true` is explicitly selected. See
[Privacy and data handling](PRIVACY.md) before enabling artifact upload.

## Limits

The action is a thin wrapper around `lumi-trace triage`. It supports the current
Python-focused localisation profile and the existing batch limits. It does not
clone repositories, install scanners, perform reproduction, create annotations,
or comment on pull requests. See [Inputs and outputs](INPUTS_AND_OUTPUTS.md)
and [Product scope](PRODUCT_SCOPE.md) for the underlying product contract.
