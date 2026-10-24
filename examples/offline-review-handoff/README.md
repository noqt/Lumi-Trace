# Offline review handoff example

This directory contains a small, wholly owned synthetic package for demonstrating
a local offline `lumi-trace` verification and review handoff. It is documentation
and test material, not a release artifact, and does not claim that a published
wheel exposes `review`.

## Source prerequisite

Install source commit `4f392e4a60d60a49a50264eff5f192bf1e681ba0`, which includes the
`review` command and pins the patched setuptools `84.1.0` build backend, in a
fresh CPython 3.11 or 3.12 environment before running the handoff:

```sh
python -m pip install --no-deps "git+https://github.com/noqt/Lumi-Trace.git@4f392e4a60d60a49a50264eff5f192bf1e681ba0"
```

## Run the handoff

`PACKAGE` is exactly `examples/offline-review-handoff/package`. From the
repository root, verify the package before reading its bounded review queue:

```sh
PACKAGE=examples/offline-review-handoff/package
lumi-trace verify "$PACKAGE"
lumi-trace review "$PACKAGE" --limit 20
```

In command notation, these are `lumi-trace verify PACKAGE`, followed by
`lumi-trace review PACKAGE --limit 20`.

The expected result is:

```text
completeness: complete
selected findings: 1
completed localisations: 1
result-local errors: 0
review entries: 3
has_more: false
```

## What this package shows

The package contains metadata and an index, but no complete raw source snapshot.
Its native SARIF already contains the exact physical path, region, and logical
symbol; an ordinary editor could therefore open the primary location directly.

CPython 3.11 and 3.12 are supported. The controlled observation for this example
used CPython 3.12.5 and source commit
`c8c8bcba7f5bb880c421e6c4cacd596c8b5622a9`.

The currently published V0.10.0 wheel lacks `review`. The serialized
`source_revision=release:0.10.1` value is self-reported version metadata only;
it is not proof of a release, tag, or publication. Nothing here claims release
availability.

## Scope and limits

Integrity verification is not authenticated provenance and is not proof of a
vulnerability, security, repository safety, or detection correctness. This
controlled synthetic local relocation is not evidence of cross-machine behavior,
blind independent review, outside use, adoption, or demand.

Evidence can contain sensitive findings, paths, symbols, hashes, and runtime
metadata. Keep generated evidence access-controlled and out of source control
except for this narrowly scoped public example.

## Provenance, reuse, and licensing

These exact sample bytes are task-generated, wholly synthetic material made
available under the authorized exact-sample reuse terms and this repository's
Apache-2.0 policy.
The public exception covers only these exact bytes; it does not imply that all
generated evidence is Apache-licensed. Preserve `LICENSE`, `NOTICE`,
`DISCLAIMER.md`, and all applicable legal-holder text when copying or
redistributing the sample.
