# Lumi Trace runtime threat model

Lumi Trace uses a clean-room snapshot, deterministic Python-focused
localisation, and optional restricted reproduction. Localisation reads
repository code as data and does not execute it.

## Scope and Security Goal

This threat model covers import, clean-room materialisation, indexing, ranking,
optional Docker reproduction, classification, and local export. The goal is to
collect useful evidence without allowing untrusted repository or plan content
to escape the declared local boundary, acquire network access, mutate the
source snapshot, or create an unjustified `CONFIRMED` result.

Lumi Trace assumes the operator is authorised to inspect the finding and repository
and to run the explicit reproduction plan.

## Assets

- authorised repository source and immutable archives;
- vulnerability findings, paths, symbols, and fingerprints;
- reproduction instructions and process output;
- host files, credentials, network, and Docker engine;
- evidence integrity, provenance, and classification.

## Trust Boundaries

1. **Input boundary:** finding documents, archive metadata, repository files,
   and reproduction plans are untrusted.
2. **Clean-room boundary:** source content is copied or safely extracted to a
   temporary snapshot before indexing or execution.
3. **Container boundary:** an approved local image and plan execute under the
   local Linux container engine.
4. **Output boundary:** reports leave the temporary workspace and remain
   sensitive local evidence.

The host OS, Python runtime, Docker-compatible daemon, local image store, and
operator-selected output directory are trusted dependencies. Repository
content, archives, findings, and plan steps are not.

## Threats and Controls

| Threat | Current control |
| --- | --- |
| Archive traversal or host overwrite | Canonical relative paths; rejection of absolute and parent paths, links, special members, encrypted ZIP members, oversized members, and case/Unicode collisions; extraction only into a temporary root. The current deterministic profile additionally requires printable-ASCII repository paths. |
| Source mutation or time-of-check/time-of-use drift | Stable manifests before and after directory copying; re-hash of the materialised snapshot; integrity failure on mismatch. |
| Symlink or special-file escape | Symlink directories, symlink files, devices, sockets, FIFOs, and archive links are unsupported. |
| Archive or repository resource exhaustion | File-count, expanded-byte, per-member, per-text-file, Python-source-line, bracket-depth, f-string-depth, parser-projection character/work/AST-node/AST-depth, per-file/global token and symbol, index JSON-byte/item, timeout, output, PID, memory, CPU, swap, core, and file-descriptor limits. Parser projections are capped at 16,384 characters, 512 non-whitespace work units, 2,048 AST nodes and 128 AST levels. The fixed scanner uses byte-oriented mask storage and constant-space explicit-continuation counting. |
| Host parser or Unicode database changes ranking output | The lexical front end freezes string/f-string handling and ASCII declaration identifiers before bounded Python 3.11 grammar validation; AST nodes never supply evidence fields; non-Python patterns use ASCII regex semantics; successful current-profile runs require printable-ASCII repository paths and CPython 3.11/3.12 with a recursion limit of at least 1,000; cross-runtime index and candidate bytes are release-gate comparisons. |
| Lexical symbol mistaken for proof of valid code | Unsupported or declaration-ambiguous Python files emit no partial symbols. Accepted symbols remain lexical landmarks only; the extractor does not assert that unrelated statements are semantically valid or that the file imports or compiles. |
| Command injection through plan text | Every step is a non-empty argv string array passed without host-shell parsing; working directories are canonical repository-relative paths. An explicit `/bin/sh` argv remains an intentional command chosen by the plan author. |
| Automatic execution from a scanner finding | SARIF and manual findings contain evidence only. Lumi Trace never derives or executes commands from SARIF; reproduction requires a separate local plan and image argument. |
| Image substitution or network pull | The input must be `sha256:<digest>` or `NAME@sha256:<digest>`, must already be local, is resolved to an immutable `sha256:` image ID, and runs with `--pull never`. |
| Network exfiltration | Container network mode is `none`; qualification checks that the image has no default IPv4 or IPv6 route beyond loopback; proxy environment variables are cleared. |
| Container privilege or engine takeover | Non-root UID:GID 65532, all capabilities dropped, exact no-new-privileges attestation, read-only root, the repository as the sole bind mount, sensitive-environment clearing, bounded resources, and zero core-file limit. |
| Repository mutation during reproduction | The clean-room snapshot is mounted read-only at `/repo`; only a bounded temporary `/tmp` is writable; repository identity is checked for unchanged evidence. |
| Unsafe image environment | Images with declared volumes are rejected; entrypoint and healthcheck behavior is overridden. Before any plan step, `/bin/sh` checks non-root identity, routes, read-only `/repo`, engine sockets, isolated `HOME`, and core limits. Container inspection separately attests the sole bind mount and cleared sensitive environment. |
| Remote daemon or daemon-side persistence | Only local Unix-socket/local-machine named-pipe endpoints qualify. Healthchecks and log persistence are disabled, volume declarations are rejected, and forced cleanup includes anonymous volumes. |
| False confirmation | `CONFIRMED` requires a qualified sandbox, network and immutability attestations, completed steps, and every explicit exit-code/substring witness. Any missing attestation fails closed. |
| Secret or source disclosure in SARIF | SARIF export omits source snippets and uses repository-relative locations. |
| Sensitive local-output disclosure | Outputs are never uploaded, previews are opt-in and bounded, documentation warns that paths, symbols, tokens, hashes, metadata, and previews remain sensitive user data. |
| Evidence tampering | Canonical SHA-256 identities and an artifact manifest bind the repository, index, candidates, receipts, bundle, and package. |
| Batch result collision or misleading aggregation | Stable result keys include the source run/result position; raw SARIF strings never form output paths. A queue path occurs once, retains every candidate contribution, and orders only by supplied severity, finding count, shortlist rank, and canonical path. Query-specific scores are never summed or presented as probability. |

## Reproduction Witness Semantics

Each expected exit code is compared exactly. `stdout_contains` and
`stderr_contains` are literal UTF-8 substring predicates, not regular
expressions, shell patterns, keywords, or inferred vulnerability evidence. If a
step supplies multiple predicates, every predicate must match. This keeps
classification explicit and auditable but does not prove the witness is a
complete security oracle.

## Fail-Closed Behavior

Invalid paths, unsupported inputs, local-image absence, failed qualification,
timeouts, output limits, infrastructure errors, witness mismatches, repository
mutation, or missing attestations cannot produce `CONFIRMED`. Expected product
errors return typed non-zero CLI statuses or structured `UNSUPPORTED` /
`INSUFFICIENT_EVIDENCE` receipts. Lumi Trace never falls back to executing a
plan on the host.

## Residual Risks

- A container shares the host kernel. Kernel or engine vulnerabilities can
  cross the boundary despite the configured controls.
- A locally present image is a supply-chain input. Lumi Trace records and pins
  its image identity but does not establish the image publisher's trust.
- A reproduction plan intentionally executes untrusted repository code. It can
  consume bounded resources, read the mounted snapshot, and expose data through
  process output.
- Network mode `none` does not prove the absence of every kernel or engine side
  channel.
- Repository indexing can reveal identifiers and string-derived tokens even
  when source snippets are absent.
- Docker qualification tests observable controls at runtime; it is not a formal
  proof of isolation.
- Deterministic ranking can miss the relevant location or rank an unrelated
  location highly.

Use a dedicated, patched host for higher-risk material and keep generated
evidence local and access-controlled.

## Out of Scope

Lumi Trace does not provide multi-tenant isolation, malware analysis, virtual-machine
isolation, exploit containment guarantees, hosted execution, repair generation,
or automatic vulnerability discovery. It must not be used to process material
the operator is not authorised to inspect or execute.
