# Security Policy

## Supported Version

The latest GitHub Release is the supported version. Security fixes target the
`main` branch; earlier releases may be superseded by a security fix.

## Reporting a Vulnerability

Do not report a suspected vulnerability, sandbox escape, sensitive output, or
private-data exposure in a public issue.

Use GitHub's **Security -> Report a vulnerability** private reporting flow. If
that flow is temporarily unavailable, open a private draft advisory if your
role permits it or contact a maintainer through an established private
channel. Do not fall back to a public issue. Include only the minimum
information necessary to reproduce the problem and remove credentials,
private source, sensitive evidence, and unrelated personal data.

Maintainers will acknowledge receipt, assess affected versions and boundaries,
and coordinate remediation and disclosure. No fixed response-time SLA applies.

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
- keep private evidence directories local and out of version control; and
- inspect the [threat model](docs/THREAT_MODEL.md) before reproduction.

Network denial and container controls reduce risk; they do not eliminate Linux
kernel, container-engine, local-image supply-chain, denial-of-service, or
authorised-code-execution risk. Lumi Trace has no host execution fallback.

## Disclosure Boundary

Never attach private source, real findings, generated evidence, third-party
repository contents, credentials, or private manifests to a report. Minimal
synthetic reproductions and Skylark-authored fixtures are preferred.
