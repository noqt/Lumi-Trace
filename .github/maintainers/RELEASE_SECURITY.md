# GitHub Release Security Procedure

Lumi Trace is distributed through GitHub Releases only. It is not uploaded to
PyPI. This procedure is deliberately small: a GitHub-verified signed tag and
GitHub Actions artifact attestations provide a practical provenance trail
without maintaining a separate public PGP key.

## Before a release

1. Confirm the exact commit has passed the release checks and has explicit
   release approval recorded in the pull request or release record.
2. Create an annotated, signed tag for that exact commit using the maintainer's
   GitHub-linked signing identity. GitHub supports verified GPG,
   SSH, and S/MIME signatures; SSH signing is suitable when a separate PGP
   workflow is not wanted.
3. Push only the verified tag. Confirm that GitHub displays the tag as
   **Verified** before continuing.

## Publish from GitHub Actions

Run the **Prepare signed GitHub release** workflow manually against that tag.
The workflow verifies the tag/version relationship, runs the release checks,
builds the wheel and normalized source distribution, creates SHA-256 checksums
and release evidence, and obtains GitHub Actions artifact attestations through
the Sigstore-backed GitHub Attestations service.

The workflow defaults to preparation only. Set its `publish` input to `true`
only after the tag is verified and final release approval has been given.
That action creates a GitHub Release and uploads the wheel, source archive,
checksums, and evidence files. It never uploads to PyPI.

## What users can verify

Users can confirm that the release tag is verified in GitHub, download the
wheel, source archive, and `SHA256SUMS` into one directory, and run
`sha256sum -c SHA256SUMS`. PowerShell users can compare the same filenames with
`Get-FileHash -Algorithm SHA256`. Users can also use GitHub's
artifact-attestation verification for the release files. These controls
establish release provenance; they do not make a security or fitness guarantee
about the software.
