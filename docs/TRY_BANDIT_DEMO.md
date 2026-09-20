# Try Lumi on Bandit SARIF

Lumi turns an existing scanner finding into a short, verifiable source-review
queue. This public demo runs Bandit 1.9.4 against a tiny inert Python fixture,
then sends the real SARIF result through Lumi. You can see the whole handoff
without sharing your code or installing anything locally.

## See the result before you fork

[Open the demo runs on `main`](https://github.com/noqt/Lumi-Trace/actions/workflows/bandit-sarif-demo.yml?query=branch%3Amain),
select the most recent successful run, and read the **Build a verified reviewer
queue** job summary on the run summary page.

The supplied example is deliberately small so the handoff is easy to inspect:

| Stage | Supplied input | Observed result |
| --- | --- | --- |
| Bandit | An inert `app.py` fixture containing one synthetic `subprocess.run(..., shell=True)` case | One B602 SARIF result pointing to `app.py` |
| Lumi | That SARIF result and the same tiny fixture repository | Status `complete`, one completed localisation, and one review path: `app.py` |

Bandit already identifies the source location in this one-finding example.
Lumi does not discover another vulnerability; it checks the supplied result,
builds the review queue, and verifies the bounded evidence package during the
job. Artifact upload is disabled, so this workflow does not upload the evidence
package as a GitHub artifact. GitHub retains its normal workflow logs and job
summary.

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
