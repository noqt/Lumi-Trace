# Rights and provenance record

Record date: 2026-07-29 (Australia/Sydney)
Example ID: `public-ghsa-8359-h9fx-j6v9`
Engineering disposition: `PASS_FOR_PINNED_FETCH_ONLY_EXAMPLE`
Publication disposition: `FOUNDER_RIGHTS_APPROVAL_REQUIRED`

This is an engineering provenance assessment, not legal advice. It bounds the
material used by this example and does not establish complete commercial
clearance for Lumi Trace.

## Upstream source

| Field | Reviewed value |
| --- | --- |
| Repository | [`koxudaxi/datamodel-code-generator`](https://github.com/koxudaxi/datamodel-code-generator) |
| Repository visibility | Public |
| Licence | MIT |
| Exact vulnerable revision | [`2dbe5b5794472a4cad8e9286c942dffda7359816`](https://github.com/koxudaxi/datamodel-code-generator/commit/2dbe5b5794472a4cad8e9286c942dffda7359816) |
| Vulnerable tree | `3a31875fcf0dcc829eda9fa41c1d37a89143a3ef` |
| Exact fixed revision | [`2ff4a72b4550a2b2069754c5b075b1655067e5fb`](https://github.com/koxudaxi/datamodel-code-generator/commit/2ff4a72b4550a2b2069754c5b075b1655067e5fb) |
| Fixed tree | `b76db2e1addce6b8fd40656750e8f85fa5415c4a` |
| Fixed release | [`0.62.0`](https://github.com/koxudaxi/datamodel-code-generator/releases/tag/0.62.0) |
| Licence at vulnerable revision | [`LICENSE`](https://github.com/koxudaxi/datamodel-code-generator/blob/2dbe5b5794472a4cad8e9286c942dffda7359816/LICENSE) |
| Licence at fixed revision | [`LICENSE`](https://github.com/koxudaxi/datamodel-code-generator/blob/2ff4a72b4550a2b2069754c5b075b1655067e5fb/LICENSE) |
| Licence Git blob SHA-1 | `be185632f9881301cbc0ceb73296a6cf9c8ff149` |
| Licence file SHA-256 | `2b9e0bc1cebf8ddbb272ccbca051634047924ae122aaf5488c21885ce327b934` |

The fixed commit has the vulnerable revision as its single parent. The MIT
licence file is byte-identical at both revisions. MIT permits use, copying,
modification and distribution subject to retaining its copyright and permission
notice in copies or substantial portions. The fetched archive retains the
upstream `LICENSE`; Lumi Trace does not vendor or redistribute the archive.

An exhaustive review of the pinned Git tree found one additional notice file:
[`docs/assets/playground/THIRD_PARTY_LICENSES.txt`](https://github.com/koxudaxi/datamodel-code-generator/blob/2dbe5b5794472a4cad8e9286c942dffda7359816/docs/assets/playground/THIRD_PARTY_LICENSES.txt)
(Git blob SHA-1 `5110ce63e9ba2bad5ec7e5812ad64687eaa6d77b`, SHA-256
`554dc29604b51ebe1b286ed60a9e21bbfc824c7851b7a2c8a3849ded2f769903`).
It records browser-playground dependencies under MPL-2.0, MIT and Apache-2.0
and states that those package artifacts are loaded at runtime rather than
vendored in the repository. The example retains and verifies this notice but
does not open the playground, load its dependencies, or execute any upstream
asset.

## Finding and advisory

| Field | Reviewed value |
| --- | --- |
| Repository advisory | [`GHSA-8359-h9fx-j6v9`](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8359-h9fx-j6v9) |
| GitHub global advisory | [`GHSA-8359-h9fx-j6v9`](https://github.com/advisories/GHSA-8359-h9fx-j6v9) |
| CVE | `CVE-2026-55389` |
| Repository advisory published | 2026-06-12 |
| Global Advisory Database publication/review | 2026-07-28 |
| Submitted by / reporter credit | Hamza Haroon (`thegr1ffyn`) |
| Affected package range stated by advisory | `datamodel-code-generator <= 0.61.0` |
| First patched package version stated by advisory | `0.62.0` |
| Advisory Database record | [`GHSA-8359-h9fx-j6v9.json`](https://github.com/github/advisory-database/blob/c12f52af6bf189411b6fd4bf7d8aeaf6a3ac6629/advisories/github-reviewed/2026/07/GHSA-8359-h9fx-j6v9/GHSA-8359-h9fx-j6v9.json) |
| Advisory Database revision | [`c12f52af6bf189411b6fd4bf7d8aeaf6a3ac6629`](https://github.com/github/advisory-database/commit/c12f52af6bf189411b6fd4bf7d8aeaf6a3ac6629) |
| Advisory record Git blob SHA-1 | `1a13eb30486a579bd4822c819683486f7fc0b0da` |
| Advisory record SHA-256 | `33c217e32b14c99e7846997031ea8374dd7840868e67fb85ba60e76d24fe3c75` |
| Advisory Database licence | [CC-BY-4.0](https://github.com/github/advisory-database/blob/c12f52af6bf189411b6fd4bf7d8aeaf6a3ac6629/LICENSE.md) |
| Advisory Database licence SHA-256 | `9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94` |

`finding.json` and `finding.sarif` are short Skylark-authored factual
paraphrases. They record the public identifiers, affected behavior and CWE
classifications but do not copy the advisory's proof of concept, long
description, source excerpts, or third-party gist. Attribution and the
CC-BY-4.0 licence are nevertheless retained here, and the text has been
shortened and changed for the finding-only workflow.

## Acquisition identity

| Field | Reviewed value |
| --- | --- |
| Archive URL | [`https://codeload.github.com/koxudaxi/datamodel-code-generator/zip/2dbe5b5794472a4cad8e9286c942dffda7359816`](https://codeload.github.com/koxudaxi/datamodel-code-generator/zip/2dbe5b5794472a4cad8e9286c942dffda7359816) |
| Required filename | `datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816.zip` |
| Archive SHA-256 | `12a2eef58a6241b250f87f9a2c0c581a5a6d29be88bf4e5090df0df060fb806c` |
| Compressed size | 3,844,899 bytes |
| Archive root | `datamodel-code-generator-2dbe5b5794472a4cad8e9286c942dffda7359816` |
| Members reviewed | 4,048 total; 3,514 regular files |
| Uncompressed regular-file bytes | 12,788,943 |
| Links, special files or unsafe paths observed | None |

The remediation-relevant vulnerable source file,
`src/datamodel_code_generator/parser/jsonschema.py`, has Git blob SHA-1
`065b48969f0fcab7984a57bc22ebc6b62a2141dd` and SHA-256
`27c901e05071c494e1fcac98f2394b9415fc120a523105edad846ba908d779d4`.
The public fix changes reference-resolution behavior in that file.

GitHub source archives are generated service artifacts rather than signed
release assets. The fetcher therefore pins the exact bytes reviewed above and
fails closed if GitHub later regenerates different bytes for the same commit.
Do not update the archive hash merely to make a changed download pass. Re-run
the rights, structure and provenance review first.

The equivalent GitHub TAR archive was also reviewed but is not used: current
Lumi Trace correctly rejects its PAX extension headers. The pinned ZIP above was
successfully materialised through the product's `RepositoryWorkspace` controls
without weakening the archive policy.

## Material boundary and safe use

Committed in Lumi Trace:

- the Skylark-authored `finding.json` and `finding.sarif`;
- the Skylark-authored standard-library fetcher;
- this provenance record and the example instructions.

Not committed or redistributed:

- the upstream source archive or any extracted upstream source;
- advisory proof-of-concept material;
- upstream tests, dependencies or generated code;
- Lumi Trace output derived from the third-party repository.

The quickstart treats the archive as inert source input. It does not install
the upstream package, install its dependencies, execute repository code, run a
proof of concept, or attempt vulnerability reproduction. Network access is used
only by the explicit fetch command.

## Evaluation separation

On 2026-07-29 the exact advisory and repository were checked against the
authoritative governed V0.4 candidate-source register and had no match. This
public product example must now be reserved as
`PUBLIC_PRODUCT_EXAMPLE_ONLY`: do not admit it to training, engineering
evaluation, model selection, qualification, protected holdback, or performance
claims. Running the documented example for product integration and clean-install
usability is permitted, but its result must not become a capability metric. If
that separation cannot be enforced, withdraw this example.

## Remaining approvals and caveats

- The founder must approve this example and rights record before release.
- Fetch-only use avoids bundling third-party source, but anyone who separately
  redistributes the archive or substantial source portions must retain the MIT
  notice.
- Reuse of Advisory Database wording must preserve CC-BY-4.0 attribution and
  indicate changes.
- Repository and product names identify their respective projects; no
  endorsement or trademark permission is implied.
- Re-check that the advisory remains published and unwithdrawn at release seal
  time.
