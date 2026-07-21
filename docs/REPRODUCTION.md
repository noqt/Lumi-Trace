# Bounded Local Reproduction

## Explicit Authority Only

Lumi Trace reproduction is optional and runs only when the user supplies both
a separate `reproduction-plan-v1` file and an immutable digest-form local image
reference. SARIF, manual findings, repository files, comments, and README
instructions are never auto-executed or converted into a plan.

The plan author is responsible for authorisation and for every argv value. Lumi
Trace provides no host execution fallback.

## Runtime Requirements

- A reachable Docker-compatible daemon configured for Linux containers through
  a local Unix socket or local-machine Windows named pipe. Remote endpoints are
  rejected before engine inspection.
- An explicitly selected digest-form image reference already present in the
  local image store. Accepted forms are `sha256:<64 lowercase hex characters>`
  and `NAME@sha256:<64 lowercase hex characters>`.
- `/bin/sh` in that image for the mandatory qualification probe.
- Sufficient local resources for the declared limits.

Lumi Trace resolves the selected digest reference to an immutable `sha256:`
image ID. It uses `--pull never`; a mutable tag is rejected, and an absent
image produces structured unsupported evidence and is never downloaded.

Check engine availability and whether an immutable image is already local:

```sh
PYTHONPATH=src python -m lumi_trace status \
  --image alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
```

## Plan Format

```json
{
  "schema_version": "reproduction-plan-v1",
  "include_output_preview": false,
  "limits": {
    "timeout_seconds": 15,
    "output_bytes": 65536,
    "pids": 64,
    "memory_mb": 128,
    "cpus": 0.5
  },
  "steps": [
    {
      "argv": ["/bin/sh", "tests/reproduce.sh"],
      "cwd": ".",
      "expect": {
        "exit_code": 23,
        "stdout_contains": "LUMI_TRACE_WITNESS:path-traversal"
      }
    }
  ]
}
```

The plan contract is strict:

- `steps` is required and non-empty.
- `limits` must supply `timeout_seconds`, `output_bytes`, `pids`, `memory_mb`,
  and `cpus` within the schema bounds.
- `include_output_preview` is optional and defaults to `false`.
- Every step has a non-empty array of non-empty argv strings. Lumi Trace passes
  the array directly and never joins it into a host-shell command.
- `argv[0]` must name an executable supplied by the image. Snapshot file modes
  and mtimes are normalized, so repository scripts must be passed to an
  explicit image interpreter such as `/bin/sh` or `python`.
- `cwd` is a canonical relative POSIX path below `/repo`; `.` is allowed.
- `expect` must include at least one of `exit_code`, `stdout_contains`, or
  `stderr_contains`.
- Exit codes are exact integers from 0 through 255.
- Contains predicates are exact UTF-8 substrings. They are not regular
  expressions, shell patterns, keywords, or semantic inference.
- When more than one predicate is supplied, every predicate must match.

Choosing `argv[0]` as `/bin/sh` is an explicit choice by the plan author. It
does not turn other plan fields into shell syntax.

## Qualification

`status` performs read-only engine and local-image inspection. `reproduce` and
`trace` qualify the exact resolved image before running a plan. The `/bin/sh` probe
must attest that:

- the process is not root;
- there is no non-loopback default IPv4 or IPv6 route;
- `/repo` is not writable;
- the Docker/Podman engine socket is not present;
- no host credential mount is present, sensitive credential environment names
  are empty, and `HOME` is the isolated `/tmp`; and
- the core-file limit is zero.

Qualification failure prevents every plan step. Lumi Trace does not relax the
policy or retry on the host.

## Container Policy

Each run uses:

- `--pull never` and the immutable local image ID;
- `--network none`;
- a read-only root filesystem;
- read-only repository snapshot at `/repo`;
- non-root UID:GID `65532:65532`;
- all Linux capabilities dropped;
- `no-new-privileges`;
- bounded PIDs, CPUs, memory, memory swap, file descriptors, core size, elapsed
  time, and captured output;
- a bounded temporary `/tmp`;
- cleared proxy variables and common credential environment variables;
- the declared argv executable forced as the container entrypoint;
- image health checks and daemon log persistence disabled;
- image-declared volumes rejected; and
- forced container and anonymous-volume cleanup.

No engine socket, host credential directory, API key, or external network is
provided to the container; the snapshot is the sole bind mount. Lumi Trace does
not claim that a user-selected image contains no baked-in secret, so operators
must select a trusted local image.

## Run a Plan

```sh
PYTHONPATH=src python -m lumi_trace reproduce \
  --repository tests/fixtures/demo-repository \
  --plan tests/data/reproduction-plan.json \
  --image alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
  --output out/reproduction-receipt.json
```

Or include the same plan and image in the complete pipeline:

```sh
PYTHONPATH=src python -m lumi_trace trace \
  --finding tests/data/manual-finding.json \
  --finding-format manual \
  --repository tests/fixtures/demo-repository \
  --plan tests/data/reproduction-plan.json \
  --image alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
  --output out/reproduced-trace
```

## Receipts and Classification

Receipts bind the validated plan, immutable image and policy identities,
repository identity, qualification observations, bounded step results, witness
matches, and immutability evidence. By default, process output is represented
by counts and SHA-256 hashes only. When `include_output_preview` is explicitly
enabled, the receipt may also contain a bounded preview.

Runtime telemetry records the engine version, architecture, and local endpoint
class without the endpoint address. Wall-clock duration is marked as not
recorded so repeated receipts remain deterministic.

A successful process exit alone never confirms a finding. `CONFIRMED` requires
every declared predicate plus all sandbox and immutability attestations.
Timeout, output-limit, setup, qualification, execution, or witness failures
produce structured `UNSUPPORTED` or `INSUFFICIENT_EVIDENCE` rather than an
unqualified confirmation.

## Privacy and Safety

Reproduction receipts are customer evidence. They can contain command metadata,
paths, hashes, qualification details, and opt-in output previews. Keep customer
and ad hoc receipts local, do not commit them, and do not publish third-party
or customer-derived receipts. The sole repository exception is a versioned
release seal generated only from the licensed Skylark-authored synthetic
fixture, with every artifact bound by its release-seal manifest and checked for
public-boundary compliance.

The container boundary reduces risk but is not a virtual machine. Use only
authorised plans and trusted local images on a patched, appropriately isolated
host. See the [threat model](THREAT_MODEL.md).
