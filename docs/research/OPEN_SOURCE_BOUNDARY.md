# Open-Source Boundary

## Apache-2.0 Scope

The repository's Apache-2.0 licence applies only to source code
and documentation expressly distributed under that licence. It establishes an
open-source software project; it does not establish or license an open-source
AI model.

The source repository contains no checkpoint, model-weight file, training
dataset, private feature group, or governed natural-corpus artifact. V0.4
produced one bounded private checkpoint after its evidence gates passed. That
checkpoint was invalidated for selection and qualification by the V0.4.1
integrity review. V0.4.1 development checkpoints and their receipts remain in
governed private storage; their existence does not place them under Apache-2.0
or authorise weight publication.

## Excluded Materials

Apache-2.0 on the source repository does not grant rights to:

- current or future model weights, checkpoints, or adapters;
- current or future training data, labels, dataset manifests, or evaluation
  data;
- third-party source code, packages, repository contents, or datasets except
  under their own licences;
- customer repositories, findings, reproduction material, reports, or
  evidence;
- historical Lumi evidence, checkpoints, adapters, or research artefacts;
- protected V2.7 holdback material or any other reserved evaluation material;
- CyberGym tasks, task metadata, source bundles, or derived task evidence;
- credentials, secrets, private manifests, or customer and ad hoc local runtime
  receipts; or
- former company names, marks, or branding beyond rights expressly granted by law.

Future `TRACE-001` weights require a separate, explicit weight licence. Future
training data requires documented rights and provenance. Neither category
inherits Apache-2.0 merely because training or inference code is present in an
Apache-licensed repository.

## Evidence Publication Rules

Historical Lumi evidence, customer evidence, and protected holdback evidence
must never be copied into, committed to, or published from this repository.
This prohibition includes derived excerpts or summaries that would disclose
protected task or repository substance.

User-supplied repositories and immutable archives are local runtime inputs.
They do not become project fixtures or distributable project content. Evidence
reports containing customer or third-party material remain under the user's
control and must not be committed or published by the project. Public examples
and fixtures must be created for this repository or carry a verified permissive licence
and explicit provenance.

The generated-evidence exception permits either:

1. a versioned release seal produced exclusively from the repository's
   licensed synthetic fixture created for this repository; or
2. a separately versioned, disclosure-reviewed aggregate evaluation seal that
   contains no repository or case identity, source, label, path, symbol,
   revision, diff, raw output, customer data, or protected-partition substance.

Every artifact must be covered by its seal manifest and pass licence, secret,
dependency, and public-boundary checks. This exception never permits customer,
third-party repository content, historical evidence, holdback substance,
CyberGym material, or case-level derivatives.

Third-party repository contents must not be republished as part of a Lumi
Trace evidence package. Reports should minimise captured content and prefer
repository identities, hashes, paths, symbols, line locations, command
receipts, and user-authorised observations.

## Dependency and Notice Rules

Third-party dependencies remain governed by their own licences. The release
must keep dependency licences and notices explicit, must not remove required
attribution, and must record any vendored material in
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

Before any public release, a reviewer must confirm that:

- the repository contains only authorised, distributable content;
- no weights or training data are present;
- no historical, customer, holdback, CyberGym, or private evidence is present,
  apart from the manifest-bound licensed synthetic release seal;
- fixture provenance and permissions are recorded;
- dependency and licence checks pass; and
- secret scanning passes.

V0.1 source publication was separately authorised after the release-evidence
review. V0.2 implementation and sealing do not authorise publication; every
later release must repeat the boundary review and receive its own publication
decision.

V0.3 retains natural repository manifests, location labels, event packages,
controlled-review receipts, raw outputs, resource observations, and scored
packages only in governed private storage. The public V0.3 seal contains
contract records, counts, decisions, and disclosure-safe summaries; it contains
no natural repository substance or incident-event content. V0.3 remains
`NO_GO_PENDING_USER_REVIEW` for publication.

V0.4 keeps source-candidate records, advisory material, exact revisions,
repository objects, licence evidence, security findings, labels, audit cards,
features, partition manifests, private results, and any checkpoint on governed
F:/G: storage. Only aggregate counts, metrics, gate states, resource
observations, decisions, and stop conditions may enter `evidence/v0.4`.

The V0.4 source distribution includes training and assurance code, not training
data or weights. A private training run does not authorise checkpoint
publication. The public evidence must record `weight_files_published: false`,
and repository publication remains `NO_GO_PENDING_USER_REVIEW` until the user
reviews the sealed build.

V0.4.1 invalidates contaminated V0.4 model-selection and qualification
derivatives, preserves the unopened historical holdback, and regenerates
development evidence through separated builder and scorer roles. Private
development models may be exercised by an explicit local model path, but no
model is bundled in a wheel, source distribution, container, or public evidence
package. Fresh model-selection and qualification inputs, raw rankings, labels,
scored results, information-flow logs, and checkpoint files remain exclusively
on governed F:/G: storage.

The disclosure-reviewed V0.4.1 evidence may contain aggregate remediation,
development, adversarial-review, product-integration, resource, readiness, and
continuation records. It must not contain repository, organisation, family,
group, advisory, target, path, symbol, label, or partition-member identity. A
V0.4.1 seal is evidence for the recorded qualification decision only; it does
not authorise repository publication, checkpoint publication, a release, or
TRACE-001 training.
