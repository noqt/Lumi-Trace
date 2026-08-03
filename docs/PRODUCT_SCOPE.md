# Product scope and limitations

## Purpose

Lumi Trace helps an authorised reviewer investigate an **existing** security finding against a local source repository or archive.

Its primary job is to produce a transparent, deterministic shortlist of files and symbols for human review. It also writes a hash-bound evidence package that can be verified later or exported to SARIF.

For one bounded multi-result SARIF report, `lumi-trace triage` produces the same per-finding shortlists and a consolidated unique-path reviewer queue. The queue is a practical work order only: it is not a probability, exploitability measure, vulnerability verdict, or statement that the repository is safe.

The optional first-party GitHub Action invokes this same triage contract in a
consumer's workflow after that workflow has created local SARIF. It adds a
bounded job summary and optional evidence-artifact retention; it does not add a
scanner, hosted analysis service, or autonomous security decision.

## Intended users

Lumi Trace is designed for:

- application-security engineers triaging scanner or assessment findings;
- maintainers investigating a known advisory or defect report;
- security reviewers who need a reproducible record of what was inspected; and
- teams that cannot upload proprietary source to a hosted analysis service.

It assumes the operator is authorised to access the finding and repository.

## Localisation and confirmation are separate

Lumi Trace deliberately treats localisation and confirmation as different outcomes.

### Localisation

Localisation ranks repository locations against the supplied finding. A successful localisation run can be useful even when no code is executed.

The ranking score is an ordering signal. It is not:

- a probability;
- a vulnerability verdict;
- proof that the top result is the repair location; or
- proof that a file imports, compiles, or is exploitable.

Lumi Trace can abstain when it finds no positive finding-guided signal or when the bounded candidate inventory is incomplete.

### Confirmation

Confirmation is optional. It requires a separate, user-authored reproduction plan and a preloaded immutable Linux-container image.

Without a reproduction plan, the evidence package records:

```text
INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN
```

This means confirmation was not attempted. It does not mean the finding is false, fixed, or absent.

A `CONFIRMED` result applies only to the declared witnesses in that plan, against the identified repository snapshot, after the documented sandbox checks pass. It does not establish that the repository is otherwise secure.

## Supported inputs

The current product accepts:

- one `manual-finding-v1` JSON object;
- one `normalized-finding-v1` JSON object;
- one explicitly selected SARIF 2.1.0 result;
- one local multi-result SARIF 2.1.0 report through `triage`, capped at 100 results by default and 1,000 results absolutely;
- one local repository directory, safe ZIP archive, or supported TAR-family archive; and
- optionally, one `reproduction-plan-v1` and one immutable local image reference.

Remote repository URLs and remote SARIF artifact locations are not accepted.

Batch triage materialises and indexes the local repository once. It does not run optional reproduction for each result. A malformed individual SARIF result may be recorded as a bounded local error while valid results remain available; the resulting verified partial-success package exits with code `5`.

Unsafe archive paths, links, special files, path collisions, encrypted ZIP members, unsupported archive extensions, and inputs above documented limits fail closed.

## Supported runtime profile

- CPython 3.11 or 3.12.
- Python-focused implementation-location ranking.
- Printable-ASCII repository-relative paths.
- Bounded indexing, candidate generation, JSON output, and optional execution.
- No hosted inference, API key, product telemetry, or automatic image pull.

Other source and text files may be indexed as context. That does not amount to supported localisation coverage for those languages.

## What Lumi Trace does not do

Lumi Trace does not:

- discover new vulnerabilities;
- continuously scan repositories;
- generate patches, exploits, or remediation instructions;
- automatically execute a scanner recommendation, SARIF message, source comment, README command, or repository script;
- decide that code is safe or compliant;
- replace qualified human security review;
- upload source, findings, or output from the core runtime; the opt-in GitHub
  Actions artifact setting is a separate consumer-controlled platform upload;
- call a hosted model or hosted analysis service; or
- provide legal, regulatory, or professional advice.

## Deterministic evidence classes

Lumi Trace emits one of three evidence outcomes.

### `CONFIRMED`

Every declared witness matched after the reproduction environment, network denial, repository immutability, and execution controls attested successfully.

### `UNSUPPORTED`

The requested reproduction could not be performed within the supported contract.

### `INSUFFICIENT_EVIDENCE`

Confirmation was not requested, a witness did not match, or an execution, timeout, output, immutability, or infrastructure condition prevented confirmation.

Confidence grades and basis points describe the evidence state. They are deterministic labels, not statistical probabilities.

## Output verification

`lumi-trace verify OUTPUT_DIRECTORY` checks:

- expected artifact membership;
- JSON contract invariants;
- canonical identities;
- SHA-256 hashes and file sizes;
- links among the finding, repository, candidates, receipt, bundle, and SARIF; and
- classification consistency.

Verification detects tampering or inconsistency in the package. It does not independently reproduce or validate the underlying vulnerability.

## Known limitations

- Ranking can miss relevant code or prioritise unrelated code.
- Unreported vulnerable code under test, fixture, generated, or vendor paths may be ranked lower by the current role-precision rule; supplied exact locations are exempt and strong source signals can outweigh the demotion in ranking.
- A known location included in a finding can strongly influence results.
- Lexical symbols are review landmarks, not compiler guarantees.
- Unsupported or ambiguous Python syntax may remain a file candidate without symbol-level detail.
- Very large repositories may hit fixed bounds and cause abstention.
- Printable-ASCII path support excludes some valid repositories.
- Container isolation shares the host kernel and is not equivalent to a virtual machine.
- A user-selected local image remains a supply-chain input.
- A reproduction witness can be too weak, incomplete, or incorrectly specified.

Use the output as structured review assistance, not as an autonomous security decision.
