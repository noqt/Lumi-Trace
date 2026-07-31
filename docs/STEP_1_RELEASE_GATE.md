# Step 1 Authority and Publication Gate

Status: `RELEASE PREPARATION AUTHORISED / FINAL PUBLICATION APPROVAL PENDING`
Applies to: Lumi Trace Step 1 deterministic productisation
Starting commit: `5ad55ab27ae84028b0c2b2a74b622e7da54e3cc9`
Development branch: `codex/lumi-trace-step-1-productisation`

## Gate rule

The founder has authorised completion of release preparation, including source
changes, local release builds, GitHub workflow preparation, and evidence
regeneration. This document does **not** authorise a merge, push, tag, GitHub
Release, or other public publication action.

Before publication, the founder must review the final prepared commit,
reassess any relevant individual employment-contract terms once available,
create a GitHub-verified signed tag, and explicitly approve the final GitHub
Release workflow publication. A technical pass, evidence seal, or signed tag
does not by itself replace that approval.

## Founder decision record

| Decision | State | Decided by | Decision date | Evidence or rationale |
| --- | --- | --- | --- | --- |
| Ownership and employer-time contribution | `RESIDUAL RISK ACCEPTED FOR PREPARATION` | Founder | 2026-07-31 | Founder reports that the project is outside their employment duties, uses personal development systems and no employer information or confidential material, and found no policy asserting blanket ownership. Some work may have occurred during paid time. The founder accepts that residual risk for release preparation and will reassess if their individual contract has broader language. This is a business risk decision, not a legal clearance or conclusion about ownership. |
| Apache-2.0 source boundary | `CLOSED FOR PREPARATION` | Founder | 2026-07-31 | The selected deterministic product candidate contains Skylark-authored source and documentation under Apache-2.0. Weights, training data, private evidence, customer material, and third-party repository content remain excluded. |
| Public example and rights record | `CLOSED` | Founder | 2026-07-31 | No demo, sample advisory, generated example output, or third-party repository is distributed. The prior public-example path and associated notices are removed from the release candidate. |
| Release branch and approver | `CLOSED FOR PREPARATION` | Founder | 2026-07-31 | `noqt/Lumi-Trace` is the intended repository. The exact post-preparation commit will be recorded at final review. The founder is the sole release approver. |
| Distribution channel | `CLOSED` | Founder | 2026-07-31 | Free, open-source GitHub Releases only. No PyPI publication. |
| Support, security and privacy ownership | `CLOSED` | Founder | 2026-07-31 | GitHub Issues are the general support route; GitHub private vulnerability reporting is the security route; the founder owns the privacy statement. |
| Release signing and provenance | `CLOSED FOR PREPARATION` | Founder | 2026-07-31 | Require a GitHub-verified signed tag by the founder's GitHub-linked signing identity, plus GitHub Actions/Sigstore artifact attestations and published SHA-256 checksums. The signing and publication actions remain deferred to final approval. |

## Publication checklist

1. Record the final prepared commit and release evidence seal below.
2. Reassess the individual employment contract if it contains broader IP,
   outside-employment, confidentiality, or conflict terms.
3. Confirm all release checks pass for the final commit.
4. Create and verify the signed `v0.4.1` tag as described in
   [Release Security](RELEASE_SECURITY.md).
5. Give explicit final approval to run the GitHub release workflow with
   `publish=true`.

## Final review record

| Field | Value |
| --- | --- |
| Final prepared commit | `PENDING` |
| Final release evidence seal | `PENDING` |
| Contract reassessment | `PENDING` |
| Signed tag verified on GitHub | `PENDING` |
| Final publication approval | `PENDING` |
