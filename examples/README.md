# Examples

## Real public product example

[`public-ghsa-8359-h9fx-j6v9`](public-ghsa-8359-h9fx-j6v9/README.md) is the
rights-reviewed five-minute product example. It pairs a Skylark-authored
finding with an exact vulnerable revision of the public, MIT-licensed
`koxudaxi/datamodel-code-generator` repository. A fail-closed fetcher downloads
and verifies the source ZIP on explicit request; no third-party source or
repository-derived evidence is committed.

This example is reserved as `PUBLIC_PRODUCT_EXAMPLE_ONLY`. It must not be used
for training, engineering evaluation, model selection, qualification,
protected holdback, or performance claims. Its only permitted execution is the
documented product-example and clean-install usability path. Review its
[`RIGHTS_AND_PROVENANCE.md`](public-ghsa-8359-h9fx-j6v9/RIGHTS_AND_PROVENANCE.md)
before acquisition or publication.

## Owned synthetic regression fixtures

The authoritative regression fixtures are the Skylark-authored, Apache-2.0
repository and findings under `tests/fixtures/demo-repository` and
`tests/data`. They are intentionally harmless and contain no customer,
CyberGym, historical Lumi, holdback, or third-party repository evidence.
