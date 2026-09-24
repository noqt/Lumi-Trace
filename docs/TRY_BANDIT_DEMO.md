# Try Lumi on Bandit SARIF

Lumi turns an existing scanner finding into a short, verifiable source-review
queue. This public demo runs Bandit 1.9.4 against a tiny inert Python fixture,
then sends the real SARIF result through Lumi. You can see the whole handoff
without sharing your code or installing anything locally.

## See the result before you fork

**Observed run (historical; completed successfully 2026-08-27):** [GitHub Actions
run 33064835136](https://github.com/noqt/Lumi-Trace/actions/runs/33064835136)
used source commit
[`3ed61d61a26a4ad297ea9c0dad5abbede84aa14c`](https://github.com/noqt/Lumi-Trace/commit/3ed61d61a26a4ad297ea9c0dad5abbede84aa14c)
and the pinned fixture
[`examples/bandit-demo/repository/app.py`](https://github.com/noqt/Lumi-Trace/blob/3ed61d61a26a4ad297ea9c0dad5abbede84aa14c/examples/bandit-demo/repository/app.py)
(blob `d87fe0034fa7ced92a53951c78b7279564fb2791`). This records that historical
source; the repository's current `main` is
[`7713c8606f9bec04c6eab6f20e7cd8b34c9d1ea1`](https://github.com/noqt/Lumi-Trace/commit/7713c8606f9bec04c6eab6f20e7cd8b34c9d1ea1).

The supplied example is deliberately small so the handoff is easy to inspect.
These are the results recorded in the linked successful run:

| Stage | Supplied input | Observed result in run 33064835136 |
| --- | --- | --- |
| Bandit | The pinned inert `app.py` fixture containing one synthetic `subprocess.run(..., shell=True)` case | One synthetic B602 SARIF finding pointing to `app.py` |
| Lumi | That SARIF finding and the same tiny fixture repository | The completed run recorded `status=complete`, `selected-results=1`, `completed-localizations=1`, and `unique-review-paths=1`. Its summary named `app.py` as the sole review path. |

Bandit already identifies the source location in this one-finding example.
Lumi does not discover another vulnerability; it only localizes the supplied
finding. The job also verifies the bounded evidence package. Artifact upload is
disabled, so this workflow does not upload the evidence package as a GitHub
artifact. GitHub retains its normal workflow logs and job summary.

For a newer run, [open the demo runs on `main`](https://github.com/noqt/Lumi-Trace/actions/workflows/bandit-sarif-demo.yml?query=branch%3Amain),
select the most recent successful run, and read the **Build a verified reviewer
queue** job summary on the run summary page.

## Run the same handoff in your fork

1. [Fork Lumi Trace](https://github.com/noqt/Lumi-Trace/fork).
2. In your fork, enable **Actions** if GitHub asks you to.
3. Open **Actions -> Try Lumi on synthetic Bandit SARIF -> Run workflow**.

The job should find one synthetic Bandit issue, finish one Lumi localisation,
and put `app.py` first in the review queue. The workflow uploads no artifact.
GitHub retains its normal workflow logs and job summary.

This is a synthetic scanner-to-Lumi walkthrough, not proof that a vulnerability
is real, exploitable, fixed, or absent. Lumi does not execute the fixture,
discover vulnerabilities, or send source to a noqt service. Do not
replace the fixture with private source or sensitive findings in a public fork.

If it fails, ranks the wrong path, explains the result badly, or never starts,
[post the public run or exact blocker](https://github.com/noqt/Lumi-Trace/issues/new?template=bandit_demo_result.yml).
The short form asks only what happened and where you got stuck. Do not post
secrets, private paths, source, screenshots, raw logs, or live vulnerability
details.
