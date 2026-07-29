# Step 1 Reproducible Release Procedure

This procedure prepares and inspects a deterministic Lumi Trace release
candidate. It does not publish, tag, sign or merge anything. The authority gate
in `docs/STEP_1_RELEASE_GATE.md` remains controlling.

## Preconditions

- Use two clean checkouts of the exact candidate commit. Keep their checkout
  paths and build outputs separate.
- Use CPython 3.12 with the pinned build and release tools from
  `pyproject.toml`; CPython 3.11 and 3.12, each with a recursion limit of at
  least 1,000, are both required for clean-install validation.
- Keep all generated material under the ignored `out/` directory.
- Acquire the approved public example separately before disabling network
  access. Core execution after acquisition must not require a package index,
  model, API key, Docker or network.
- Use only repositories whose relative paths are printable ASCII;
  non-printable-ASCII repository paths are outside the current deterministic
  profile and must fail closed.
- Do not use a development checkpoint, private corpus, evaluator checkout or
  protected evidence.

Record the candidate state before building:

```text
git rev-parse HEAD
git status --porcelain=v2 --branch
python --version
python -m pip --version
python -m build --version
python -m twine --version
```

The worktree must be clean. Set `SOURCE_DATE_EPOCH` to the candidate commit
time, `PYTHONHASHSEED` to zero and disable package-index access for the build.

PowerShell:

```powershell
$sourceA = Resolve-Path SOURCE_A
$sourceB = Resolve-Path SOURCE_B
$revision = git -C $sourceA rev-parse HEAD
if ($revision -ne (git -C $sourceB rev-parse HEAD)) { throw "source revisions differ" }
if (git -C $sourceA status --porcelain) { throw "SOURCE_A is not clean" }
if (git -C $sourceB status --porcelain) { throw "SOURCE_B is not clean" }
$env:SOURCE_DATE_EPOCH = git -C $sourceA show -s --format=%ct $revision
$env:PYTHONHASHSEED = "0"
$env:PIP_NO_INDEX = "1"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"

python -m build --no-isolation --wheel --outdir out/step1-build-a $sourceA
python -m build --no-isolation --sdist --outdir out/step1-raw-a $sourceA
python (Join-Path $sourceA "scripts\normalize_step1_sdist.py") `
  --input out/step1-raw-a/skylark_lumi_trace-0.4.1.dev0.tar.gz `
  --output out/step1-build-a/skylark_lumi_trace-0.4.1.dev0.tar.gz

python -m build --no-isolation --wheel --outdir out/step1-build-b $sourceB
python -m build --no-isolation --sdist --outdir out/step1-raw-b $sourceB
python (Join-Path $sourceB "scripts\normalize_step1_sdist.py") `
  --input out/step1-raw-b/skylark_lumi_trace-0.4.1.dev0.tar.gz `
  --output out/step1-build-b/skylark_lumi_trace-0.4.1.dev0.tar.gz
python -m twine check out/step1-build-a/*
python -m twine check out/step1-build-b/*
```

Bash:

```bash
SOURCE_A="$(realpath SOURCE_A)"
SOURCE_B="$(realpath SOURCE_B)"
revision="$(git -C "$SOURCE_A" rev-parse HEAD)"
test "$revision" = "$(git -C "$SOURCE_B" rev-parse HEAD)" || {
  echo "source revisions differ" >&2
  exit 1
}
test -z "$(git -C "$SOURCE_A" status --porcelain)" || {
  echo "SOURCE_A is not clean" >&2
  exit 1
}
test -z "$(git -C "$SOURCE_B" status --porcelain)" || {
  echo "SOURCE_B is not clean" >&2
  exit 1
}
export SOURCE_DATE_EPOCH="$(git -C "$SOURCE_A" show -s --format=%ct "$revision")"
export PYTHONHASHSEED=0
export PIP_NO_INDEX=1
export PIP_DISABLE_PIP_VERSION_CHECK=1

python -m build --no-isolation --wheel --outdir out/step1-build-a "$SOURCE_A"
python -m build --no-isolation --sdist --outdir out/step1-raw-a "$SOURCE_A"
python "$SOURCE_A/scripts/normalize_step1_sdist.py" \
  --input out/step1-raw-a/skylark_lumi_trace-0.4.1.dev0.tar.gz \
  --output out/step1-build-a/skylark_lumi_trace-0.4.1.dev0.tar.gz

python -m build --no-isolation --wheel --outdir out/step1-build-b "$SOURCE_B"
python -m build --no-isolation --sdist --outdir out/step1-raw-b "$SOURCE_B"
python "$SOURCE_B/scripts/normalize_step1_sdist.py" \
  --input out/step1-raw-b/skylark_lumi_trace-0.4.1.dev0.tar.gz \
  --output out/step1-build-b/skylark_lumi_trace-0.4.1.dev0.tar.gz
python -m twine check out/step1-build-a/*
python -m twine check out/step1-build-b/*
```

Setuptools source distributions retain checkout/build timestamps even when
`SOURCE_DATE_EPOCH` is set. The bounded normalizer above reads without
extracting, rejects unsafe paths, links and special members, and writes a
canonical USTAR+gzip archive with fixed ownership, modes, ordering and
timestamps. Raw sdists are diagnostic inputs only and are not release
artifacts.

Compare the first and second final wheel byte-for-byte and do the same for the
canonical source distribution. Different hashes are a release failure; do not
select one build or rewrite an artefact after the comparison.

PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 out/step1-build-a/*
Get-FileHash -Algorithm SHA256 out/step1-build-b/*
```

Bash:

```bash
sha256sum out/step1-build-a/*
sha256sum out/step1-build-b/*
```

## Generate bounded release evidence

After both build directories have exactly one identical wheel and one
identical sdist, inspect the first pair. Pass concrete filenames rather than a
directory or unresolved wildcard.

```text
python scripts/build_step1_release_evidence.py \
  --wheel WHEEL_PATH \
  --sdist SDIST_PATH \
  --source-revision REVISION \
  --source-date-epoch SOURCE_DATE_EPOCH
```

The default output is the ignored directory
`out/step1-release-evidence`. The command:

- validates archive structure and matching package metadata;
- rejects evaluator, evidence, cache, weight and private-material paths;
- rejects serialized root-level model weights, common secret signatures and
  absolute Windows or user-home paths in payloads;
- rejects undeclared runtime dependencies for the Step 1 zero-dependency
  product contract;
- writes `SHA256SUMS`, a member-level artefact inventory, a sanitized
  environment record, an SPDX 2.3 JSON SBOM, a pass/fail summary and a
  hash-bound evidence manifest.

The check is mechanical. It cannot determine legal ownership, recognise every
possible customer identifier or replace review of example rights. Those
decisions remain in the authority gate.

## Clean-install matrix

For each of CPython 3.11 and 3.12 with a recursion limit of at least 1,000,
create a new environment outside the development checkout and install only the
candidate wheel with dependency resolution disabled:

```text
PYTHON -m venv CLEAN_ENV
CLEAN_ENV_PYTHON -m pip install --no-index --no-deps WHEEL_PATH
CLEAN_ENV_LUMI_TRACE version
CLEAN_ENV_LUMI_TRACE trace \
  --finding APPROVED_EXAMPLE_FINDING \
  --finding-format manual \
  --repository APPROVED_EXAMPLE_REPOSITORY \
  --output CLEAN_OUTPUT
CLEAN_ENV_LUMI_TRACE verify CLEAN_OUTPUT
```

Repeat the primary command with the approved SARIF input. Run from a directory
that contains only the candidate release, approved example and quickstart—not
the source checkout, its virtual environment, test fixtures or evaluator.
Record start/end time, commands, stdout/stderr, output hashes, errors and
whether founder intervention was required.

For each equivalent finding, compare `repository-index.json` and
`candidates.json` across CPython 3.11 and 3.12. Their bytes, scores, candidate
counts, index identity, ranking identity, and candidate-set identity must
match. Evidence bundles and SARIF may retain declared platform provenance, so
compare those only after accounting for their explicit provenance fields.
Any candidate-universe or score drift is a failed matrix, even when both
individual runs verify.

The matrix corpus must include Python 3.11 f-strings, rejected PEP 695/701
syntax, CR/LF/CRLF variants, non-ASCII source inside strings/comments,
non-Python source containing Unicode-category edge characters, and an
explicit non-printable-ASCII repository-path rejection. It must also exercise
the 16,384-character, 512-work-unit, 2,048-AST-node and 128-AST-level
projection controls and the 1,000 minimum recursion-limit gate. The current
`.11` scanner, `.7` candidate algorithm, v4 index and `python-lexical-v1`
extractor must be present in every successful current-profile artifact.

No-Docker execution is the required core path. Docker-marked tests may be run
separately only when the immutable image is already present locally; Lumi
Trace must not pull it. Record skipped Docker checks as skipped with the reason.

## Required release checks

Run and retain complete outputs for:

```text
python -m pytest -q -m "not docker"
python -m ruff check .
python -m ruff format --check .
python scripts/check_licenses.py
python scripts/check_secrets.py
python scripts/check_dependencies.py
python scripts/check_public_boundary.py
python -m pip_audit --skip-editable --progress-spinner off
python -m build
python -m twine check dist/*
```

The release-candidate summary must identify skipped checks, failed attempts and
the exact Python/platform matrix. A status-only list is not a substitute for
the retained command output.
