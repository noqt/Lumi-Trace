# Security Policy

## Supported Version

Lumi Trace V0.1.0 is a private-review build. Security fixes currently target
the `codex/lumi-trace-v0-1` review branch. No public or stable release is
supported yet.

## Reporting a Vulnerability

Do not report a suspected vulnerability, sandbox escape, sensitive output, or
customer-data exposure in a public issue.

While the repository is private, report it through the private channel by
which repository access was granted or open a private draft advisory under the
repository's **Security -> Advisories** tab if your role permits it.

Public release is blocked until GitHub private vulnerability reporting is
enabled and its **Security -> Report a vulnerability** flow is tested by the
maintainers. Once the repository is public, use that private flow. Do not fall
back to a public issue. Include only the minimum information necessary to reproduce the problem
and remove credentials, customer source, protected evidence, and unrelated
personal data.

Maintainers will acknowledge receipt, assess affected versions and boundaries,
and coordinate remediation and disclosure. No fixed response-time SLA applies
to this pre-release build.

## High-Priority Security Areas

Reports are especially useful when they concern:

- archive traversal, link handling, path collisions, or snapshot identity;
- repository mutation during snapshotting or reproduction;
- Docker network-denial, image qualification, privilege, mount, or resource
  controls;
- command or working-directory validation in reproduction plans;
- unexpected image pulling or host execution fallback;
- evidence-bundle identity or artifact-manifest verification;
- source snippets, secrets, credentials, or host paths leaking into reports;
  or
- a `CONFIRMED` result produced without every declared witness and sandbox
  attestation.

## Operational Security

Lumi Trace processes untrusted repositories and may execute an explicitly
approved plan inside a local container. Operators must:

- use only repositories and reproduction instructions they are authorised to
  test;
- use a patched Linux-container engine on a dedicated or otherwise appropriate
  host;
- select and verify a trusted image already present locally;
- keep the Docker engine socket and host credentials outside the container;
- leave output previews disabled unless they are necessary;
- keep customer and ad hoc evidence directories local, private, and out of
  version control; the only repository exception is a manifest-bound,
  versioned release seal generated from the licensed Skylark-authored synthetic
  fixture; and
- inspect the [threat model](docs/THREAT_MODEL.md) before reproduction.

Network denial and container controls reduce risk; they do not eliminate Linux
kernel, container-engine, local-image supply-chain, denial-of-service, or
authorised-code-execution risk. Lumi Trace has no host execution fallback.

## Disclosure Boundary

Never attach historical Lumi evidence, customer evidence, protected holdback
material, CyberGym tasks, third-party repository contents, credentials, or
private manifests to a report. Hashes, minimal synthetic reproductions, and
Skylark-authored fixtures are preferred.
