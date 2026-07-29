# Step 1 Authority and Publication Gate

Status: `OPEN / PUBLICATION BLOCKED`
Applies to: Lumi Trace Step 1 deterministic productisation
Starting commit: `5ad55ab27ae84028b0c2b2a74b622e7da54e3cc9`
Development branch: `codex/lumi-trace-step-1-productisation`

## Gate rule

Development, testing and preparation of a draft release candidate may continue
on the dedicated productisation branch. No merge to the public default branch,
tag, GitHub Release, PyPI upload, artefact signature, licence change or other
publication action is authorised by this document.

Publication remains blocked until every founder decision below is completed in
writing. A technical pass, evidence seal or clean-machine test cannot close an
ownership or publication decision.

## Release issue list

| Area | Current state | Evidence or decision required |
| --- | --- | --- |
| Code and IP ownership | `OPEN` | Identify the legal owner of every Skylark-authored contribution in the candidate and record whether any work was produced on employer time, equipment or under an agreement that could affect ownership. Record any exclusion, consent or assignment needed before publication. |
| Apache-2.0 source boundary | `PROVISIONAL` | Confirm that the declared owner may distribute the selected source and documentation under Apache-2.0. Weights, training data, private evidence, customer material and third-party repository contents remain outside that grant. |
| Third-party source, example and output rights | `OPEN` | Approve the Step 1 public example and its item-level provenance record. Confirm licences, attribution, permitted redistribution or fetch-only handling, and the rights boundary for generated example output. |
| Authoritative repository and approver | `OPEN` | Confirm `noqt/Lumi-Trace` as the publication repository, select the release branch or commit, and name the person authorised to approve the release. The development branch above is not automatically the release branch. |
| Public support and security contact | `OPEN` | Confirm the maintained public support route, the owner of the privacy statement, and the security-reporting contact. GitHub private vulnerability reporting is documented but does not identify a general support owner. |
| Distribution and signing | `OPEN` | Choose GitHub Releases only or explicitly authorise PyPI as well. Separately decide whether wheel, sdist, checksums, tag or provenance attestations require signing, and identify the signing identity and method if required. |

## Six founder decisions

All six decisions are presently `OPEN`.

1. **Ownership and employer-time contribution — OPEN.** Confirm who owns and
   may publish the code, including any employer-time, employer-equipment or
   contractual exposure.
2. **Public example and rights record — OPEN.** Approve the exact example,
   revision, finding sources, licences, attribution and redistribution/fetch
   treatment.
3. **Release branch and approver — OPEN.** Name the authoritative release
   branch or commit and the release approver.
4. **Distribution channel — OPEN.** Choose GitHub Releases only or authorise a
   PyPI publication path as well.
5. **Support, security and privacy ownership — OPEN.** Confirm the public
   support route, security contact and privacy-statement owner.
6. **Release signing — OPEN.** State either the required signing mechanism and
   identity or an explicit decision that this candidate will be unsigned.

## Closure record

The release approver must complete this table without deleting the issue
history above.

| Decision | State | Decided by | Decision date | Evidence or rationale |
| --- | --- | --- | --- | --- |
| Ownership and employer-time contribution | `OPEN` | — | — | — |
| Public example and rights record | `OPEN` | — | — | — |
| Release branch and approver | `OPEN` | — | — | — |
| Distribution channel | `OPEN` | — | — | — |
| Support, security and privacy ownership | `OPEN` | — | — | — |
| Release signing | `OPEN` | — | — | — |

The publication gate may change to `CLOSED / RELEASE REVIEW AUTHORISED` only
when all six rows are closed, any conditions are reflected in the release
candidate, and the approver records an explicit release-review decision. Gate
closure still does not itself perform or authorise an automated publication
command.
