# Lumi repository instructions

These instructions apply to the whole repository. A deeper `AGENTS.md` may add
narrower rules for its subtree, but it may not relax the safety, privacy,
evidence, rights, compatibility, preservation, or publication boundaries below.

## Authority and source truth

1. Exact action-specific founder, legal, risk, and publication authority in the
   governing company control plane takes precedence.
2. An accepted bounded work order controls scope, branch, permanent worktree,
   tests, resource limits, and stop conditions.
3. This file controls repository-local execution. Current tracked source,
   tests, machine-readable schemas, `README.md`, `SECURITY.md`, and the supported
   documentation under `docs/` are evidence to reconcile, not permission to
   broaden an action.

The public source repository is `https://github.com/noqt/Lumi-Trace`. Bind every
change and result to an exact commit. Do not treat a branch name, local `main`,
tag, build, worktree, or passing test as proof of current public state or release
authority. Machine-readable files under `schemas/` control machine validation;
the `docs/research/` archive and historical evidence remain provenance, not the
supported product contract.

This guidance entered integration through the accepted side lineage
`ac01efad7c06289003cce30613a0857fe8495a17` ->
`4aa33fadb9391c7ef9c4eaf8e76c8810e998b712` (bounded documentation and
metadata attribution correction) ->
`857ff748f4e322f82283e76ecd7e5cc7c0c7c48e` (root guidance). The integration
branch was based on freshly verified public `main`; public `main` and the
peeled annotated `v0.10.0` tag then resolved to
`60ceacaa5b92718cc50bbed4e5ce34da7e85e093`. Revalidate external state before
any external use. These identities record provenance only. They do not
authorise a push, tag, release, deployment, or public claim.

On an instruction, source, schema, documentation, legal, or evidence conflict,
preserve the state and stop only the affected claim or mutation until the
conflict is reconciled.

## Product and security boundary

Lumi is the active product. Trace is functionality within Lumi, not a separate
active product. Existing `Lumi Trace` prose and legacy repository, package,
module, command, schema, release, artifact, and evidence identifiers remain
valid technical interfaces and provenance.

Trace starts with an existing security finding and an authorised local Python
repository or supported archive. It creates a clean-room snapshot, ranks likely
files and symbols for human review, and emits hash-bound JSON and SARIF evidence.
It is not a vulnerability scanner, autonomous security decision, safety or
compliance verdict, patch or exploit generator, intrusion-detection service, or
substitute for qualified review. It can miss relevant material and rank
irrelevant material.

Preserve these boundaries:

- localisation and confirmation are separate; a successful ranking without a
  reproduction plan correctly records `INSUFFICIENT_EVIDENCE` and
  `NO_REPRODUCTION_PLAN`;
- `CONFIRMED` applies only to every declared witness in the exact plan, snapshot,
  image, and attested sandbox. It never establishes that the repository is safe,
  broadly vulnerable, exploitable, fixed, or otherwise reviewed;
- component scope must come from pre-existing finding or package context, be
  broad enough for the ordinary implementation, and be selected before
  localisation. Never narrow from a known fix, diff, file, or target symbol;
- a component-scoped result covers only the supplied component tree;
- the supported profile is CPython 3.11 or 3.12, Python-focused localisation,
  printable-ASCII repository-relative paths, and bounded local inputs. Broader
  language, path, hosted, or runtime coverage is not implied; and
- findings, SARIF, archives, repositories, and plans are untrusted data.
  Localisation must not import or execute repository content or instructions
  embedded in findings or source.

Optional reproduction requires a separate user-authored argv-only plan and an
immutable container image already present in a local Linux-container engine.
Keep the repository read-only, network disabled, capabilities dropped, resource
limits bounded, and attestations complete. Never pull an image during
reproduction or fall back to host execution. Container isolation reduces risk;
it is not a virtual-machine or zero-escape guarantee. Follow
`docs/THREAT_MODEL.md` and `docs/REPRODUCTION.md` exactly.

## Privacy, evidence, and claims

The core runtime operates locally: it has no hosted-inference path, API-key
requirement, product telemetry, or automatic image pull. This says nothing about
the surrounding operating system, Python, container engine, shell, backups, or
CI platform. The GitHub Action runs the local workflow on a GitHub runner;
normal logs and summaries reach GitHub, and evidence upload is a separate
consumer-controlled opt-in.

Evidence packages may contain sensitive finding text, paths, symbols, token
vocabulary, hashes, runtime metadata, and optional output previews. Keep them
access-controlled and out of source control, public issues, and public
artifacts. Use synthetic fixtures and the minimum necessary redacted material.
Do not inspect or collect credentials, private external data, customer source,
real findings, personal data, private manifests, protected evidence, model
weights, or training data without exact separate authority. `lumi-trace verify`
checks integrity and cross-artifact consistency; it does not redact content or
independently validate a vulnerability.

Use these company evidence labels for claims about work:

- `OBSERVED`: directly inspected fact bound to source, time, and identity.
- `IMPLEMENTED_INTERNAL`: present at an exact commit or artifact and exercised
  by named internal checks; not independent use or market evidence.
- `INTENDED`: planned or designed but not demonstrated as implemented.
- `UNSUPPORTED`: absent, conflicting, stale, or insufficient evidence; do not
  present the claim as fact.

Keep those labels distinct from the product's deterministic output classes
`CONFIRMED`, `UNSUPPORTED`, and `INSUFFICIENT_EVIDENCE`. Bind every technical
result to the exact commit, artifact hash, commands, Python/OS environment,
timestamp, skips, and limitations. Do not generalise a synthetic fixture,
internal clean-install run, CI result, checksum, evidence package, or release
into independent installation, adoption, demand, production readiness,
universal security coverage, or market evidence.

## Compatibility, preservation, and rights

Preserve established interfaces unless an authorised compatibility plan proves
the transition. Protected identifiers include the `Lumi-Trace` repository,
`skylark-lumi-trace` distribution, `skylark_lumi_trace` artifact prefix,
`lumi_trace` Python package, `lumi-trace` command, GitHub Action inputs and
outputs, schema filenames and `schema_version` values, evidence artifact names,
canonical identity prefixes, algorithm identities, exit codes, and release
tags. A breaking schema change requires a new schema version; never silently
reinterpret an existing contract.

Treat Git history, tags, worktrees, untracked files, `out/`, `dist/`, build
outputs, evidence packs, manifests, checksums, SBOMs, attestations, and release
artifacts as protected. Inventory the original checkout and all worktrees before
mutation and prove preservation afterwards. Never use destructive reset, clean,
history rewrite, force-push, tag replacement, bulk overwrite, or deletion
without exact authority. Write new artifacts to a fresh task- and commit-bound
location, hash them, and stage only an explicit intended file list.

The source and documentation distributed from this repository are Apache-2.0
subject to the files that govern them. Retain `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md`, `DISCLAIMER.md`, and applicable third-party terms.
Existing legal-holder, copyright, and attribution text is preserved legal and
provenance material, not authority to infer or announce a current company
identity. Do not change legal holders, attribution, licence posture, contributor
terms, or materially licensed dependencies without the corresponding reserved
review and authority.

## Required workflow and verification

For a supported release install, verify the wheel and source archive against the
same release's `SHA256SUMS`, install the wheel in a fresh CPython 3.11 or 3.12
environment with `--no-deps`, and run `lumi-trace version`. A checksum match
proves only agreement with the release record. For a source checkout, use a
fresh environment and `python -m pip install .`.

Exercise the owned synthetic workflow from `README.md` or
`docs/GETTING_STARTED.md`: run `lumi-trace trace` against
`examples/quickstart/finding.json` and `examples/quickstart/repository`, write to
a new output directory, then run `lumi-trace verify`. The ranking should include
`src/archive.py::extraction_target`; without a reproduction plan, the expected
classification is `INSUFFICIENT_EVIDENCE / NO_REPRODUCTION_PLAN`. Never
overwrite or delete an existing evidence directory merely to rerun a check.

Run checks proportionate to the change and report exactly what ran:

- documentation-only: instruction precedence, compatibility-token scan,
  documentation link/path existence, privacy and claim-boundary review,
  secret/personal-path scan, intended-file scope, and `git diff --check`;
- Python or behavioural change: CPython 3.11 and 3.12 non-Docker tests,
  `python -m ruff check .`, `python -m ruff format --check .`, and the relevant
  licence, secret, dependency, public-boundary, schema, deterministic-output,
  and workflow checks;
- packaging or release preparation: all applicable checks above plus the
  reproducible-build, clean-install matrix, package build, audit, Twine,
  checksum, SBOM, manifest, and release-evidence procedure in
  `.github/maintainers/REPRODUCIBLE_BUILD.md`; and
- Docker-marked reproduction checks: only under an explicit bounded assignment
  on a suitable host with the immutable fixture image already present. Record
  them as skipped when those prerequisites are absent; never acquire an image
  merely to turn a skip into a pass.

Do not weaken a test, threshold, negative control, sandbox attestation, or
compatibility contract to obtain PASS. If a required interpreter, tool, or
environment is unavailable without external acquisition, report it as
unavailable rather than silently substituting another check.

## Runtime and publication boundary

In the controlled local execution environment, operate only on F: and G:.
Before any runtime, test, or tool that may use temporary or cache storage, create
a task-specific `[TASK_TEMP]` with
`New-Item -Path [TASK_TEMP] -ItemType Directory -Force -ErrorAction Stop` (do
not substitute `-LiteralPath` on `New-Item`); resolve it, prove it exists as a
directory on exactly F: or G:, bind `TEMP`, `TMP`, `TMPDIR`,
`PYTHONDONTWRITEBYTECODE`, and tool caches, then start a fresh runtime that
asserts its selected temporary directory resolves exactly to `[TASK_TEMP]`.
Abort before substantive execution on creation, resolution, drive, or equality
failure. Environment-variable assignment alone is not evidence.

Do not commit absolute machine paths, personal identifiers, credential
locations, raw process arguments or environments, or private evidence. Local
branches, permanent worktrees, commits, tests, builds, and release preparation
are not pushes, tags, GitHub Releases, deployments, publication, or public
claims.

The current repository procedure distributes releases through GitHub Releases,
not PyPI. `.github/maintainers/RELEASE_SECURITY.md`, a signed tag, passing CI,
prepared artifacts, or an existing public release does not itself grant future
publication authority. Perform any product-remote push, tag creation or change,
release, deployment, package-index upload, evidence upload, or public claim only
with exact action-specific authority for this repository and independent review.
Silence and local acceptance are not publication authority.
