# Privacy and Data Handling

## Local processing

Lumi Trace's core commands operate on local files. `trace` does not upload a
finding or repository, call hosted inference, require an API key, send product
telemetry, or fetch a model or container image. The Python runtime package has
no third-party runtime dependency.

Optional Docker reproduction uses only an immutable image that the user has
already placed in a local engine; Lumi Trace never pulls an image.

This boundary does not claim that Python, the operating system, Docker, or
other software outside Lumi Trace has no network-capable functionality.

## Data read

Depending on the command, Lumi Trace reads:

- finding text, identifiers, severity, fingerprints, paths, symbols, and
  regions from manual JSON, normalized JSON, or SARIF;
- repository paths and regular-file content within the documented size
  bounds;
- an explicitly supplied reproduction plan; and
- local Docker engine/image metadata only when reproduction is requested.

Repository code is treated as untrusted data during the deterministic path and
is not imported or executed. A reproduction plan is never inferred from
repository content or finding text.

## Data written

An evidence package can contain sensitive or identifying material:

- finding text and source-tool metadata;
- repository-relative paths, symbol names, locations, token vocabulary, and
  deterministic score reasons/components;
- repository and artifact hashes;
- runtime and sandbox metadata; and
- bounded stdout/stderr previews or hashes when the user opts into
  reproduction.

SARIF omits source snippets but still contains ranked paths, symbols, regions,
and finding text. Hashes can also be sensitive when they identify private
artifacts.

## Retention and disclosure

Write outputs to an access-controlled local directory. Apply the same
retention, backup, incident-response, and deletion rules used for the source
repository and security finding. Do not commit customer or private
repository-derived evidence to this source repository, attach it to a public
issue, or publish it without an explicit disclosure and rights review.

`lumi-trace verify` validates structure, identities, and artifact bindings. It
does not redact output or decide whether it is safe to disclose.

## Optional reproduction

No-Docker use is the default quickstart. When reproduction is explicitly
requested, Lumi Trace requires a preloaded digest-form Linux image, qualifies
the network-denied/non-root/read-only sandbox, and fails closed before plan
execution if those controls do not attest.

Only commands declared by the user-authored reproduction plan are eligible to
run. Instructions embedded in a finding, SARIF message, source comment,
README, or repository file are never promoted into a plan.

## Questions and incidents

General support is through GitHub Issues. Report security vulnerabilities only
through GitHub's private vulnerability-reporting flow. The founder owns this
privacy statement; see `STEP_1_RELEASE_GATE.md` for the final publication
controls.
