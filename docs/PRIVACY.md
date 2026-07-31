# Privacy and data handling

## What stays local

Lumi Trace's core commands operate on local files. The primary `trace` workflow does not:

- upload a finding or repository;
- call hosted inference;
- require an API key;
- send product telemetry;
- fetch a model; or
- pull a container image.

Optional reproduction uses only an immutable image already present in the operator's local Linux-container engine.

This statement covers Lumi Trace itself. It does not claim that Python, the operating system, the container engine, shell history, backup software, endpoint tooling, or other software on the host has no network or telemetry behavior.

## Data Lumi Trace reads

Depending on the command, Lumi Trace reads:

- finding text and metadata from manual JSON, normalized JSON, or SARIF;
- repository-relative paths and bounded regular-file content;
- an explicitly supplied reproduction plan; and
- local container-engine and image metadata when reproduction is requested.

Repository code is treated as data during localisation and is not imported or executed. Execution occurs only through an explicit reproduction plan.

## Data Lumi Trace writes

An evidence package can contain sensitive material, including:

- finding text, identifiers, severity, and source-tool metadata;
- repository paths, symbol names, locations, bounded token vocabulary, and score reasons;
- repository and artifact hashes;
- runtime and sandbox metadata; and
- bounded stdout or stderr previews when the operator explicitly enables them.

SARIF output omits source snippets, but it can still expose finding text, paths, symbols, source regions, and hashes.

## Handling guidance

Treat an evidence package at least as sensitively as the source repository and security finding that produced it.

- Write output to an access-controlled local directory.
- Apply appropriate retention, backup, incident-response, and deletion rules.
- Keep output out of public repositories and public issue trackers.
- Redact or recreate a problem with synthetic data before reporting a bug.
- Do not assume that `lumi-trace verify` performs redaction; it checks integrity only.
- Leave process-output previews disabled unless they are necessary.

## Public support and security reports

Use public GitHub Issues only for synthetic or fully redacted product defects.

Report suspected vulnerabilities through GitHub's private vulnerability-reporting flow described in [`SECURITY.md`](../SECURITY.md). Include the minimum necessary information and do not attach customer source, credentials, private evidence, or unrelated personal data.
