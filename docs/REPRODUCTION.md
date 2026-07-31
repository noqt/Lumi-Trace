# Optional local reproduction

Lumi Trace can run an explicit witness against the identified repository snapshot in a restricted local Linux container. This is optional. Localisation does not require Docker.

## Safety model

Reproduction runs only when the operator supplies both:

1. a separate `reproduction-plan-v1`; and
2. an immutable digest-form image that already exists in the local container engine.

Lumi Trace does not:

- derive a plan from SARIF, finding text, source comments, README files, or repository content;
- pull a container image;
- fall back to running commands on the host; or
- provide network access to the reproduction container.

The operator remains responsible for authorisation, the selected image, every command argument, and the adequacy of each witness.

## Requirements

- A local Docker-compatible daemon configured for Linux containers.
- A trusted image already present locally.
- An immutable image reference in one of these forms:
  - `sha256:<64-lowercase-hex-characters>`
  - `name@sha256:<64-lowercase-hex-characters>`
- `/bin/sh` inside the image for the qualification probe.

Check the local engine and image before running a plan:

```sh
lumi-trace status --image name@sha256:<digest>
```

## Minimal plan

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
      "argv": ["python", "-m", "pytest", "-q", "tests/test_archive.py"],
      "cwd": ".",
      "expect": {
        "exit_code": 1,
        "stdout_contains": "path traversal witness"
      }
    }
  ]
}
```

Every step uses an argument array. Lumi Trace does not join it into a host-shell command.

Predicates are exact:

- `exit_code` is an integer from 0 to 255;
- `stdout_contains` is a literal UTF-8 substring; and
- `stderr_contains` is a literal UTF-8 substring.

When several predicates are supplied, every predicate must match.

## Run reproduction with a trace

```sh
lumi-trace trace \
  --finding ./finding.json \
  --finding-format manual \
  --repository ./local-repository \
  --plan ./reproduction-plan.json \
  --image name@sha256:<digest> \
  --output ./trace-evidence
```

Or run the plan separately:

```sh
lumi-trace reproduce \
  --repository ./local-repository \
  --plan ./reproduction-plan.json \
  --image name@sha256:<digest> \
  --output ./reproduction-receipt.json
```

## Container controls

Before any plan step runs, Lumi Trace qualifies the selected image and container policy. The runtime uses:

- no network;
- a read-only root filesystem;
- a read-only repository snapshot mounted at `/repo`;
- a non-root user;
- dropped Linux capabilities;
- `no-new-privileges`;
- bounded CPU, memory, process count, file descriptors, time, temporary storage, and output;
- cleared proxy and common credential environment variables;
- no engine socket or host credential mount; and
- forced cleanup.

Qualification failure prevents execution. Lumi Trace does not weaken the policy or retry on the host.

## Interpreting results

A process exiting successfully is not enough to confirm a finding.

`CONFIRMED` requires:

- every declared witness to match;
- the exact image and policy identities to be recorded;
- network-denial and non-root checks to pass;
- the repository snapshot to remain unchanged; and
- no infrastructure condition to force abstention.

Timeouts, output limits, qualification failures, witness mismatches, or infrastructure errors produce `UNSUPPORTED` or `INSUFFICIENT_EVIDENCE`.

## Residual risk

A container shares the host kernel. A local image can contain vulnerable software or baked-in secrets. A user-authored plan intentionally executes repository code and can expose data through bounded output.

Use a patched, appropriately isolated host and a trusted local image. Keep receipts private. For higher-risk material, use stronger isolation than a general-purpose workstation.
