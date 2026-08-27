# Try Lumi on Bandit SARIF

Lumi turns an existing scanner finding into a short, verifiable source-review
queue. This public demo runs Bandit 1.9.4 against a tiny inert Python fixture,
then sends the real SARIF result through Lumi. You can see the whole handoff
without sharing your code or installing anything locally.

1. [Fork Lumi Trace](https://github.com/noqt/Lumi-Trace/fork).
2. In your fork, enable **Actions** if GitHub asks you to.
3. Open **Actions -> Try Lumi on synthetic Bandit SARIF -> Run workflow**.

The job should find one synthetic Bandit issue, finish one Lumi localisation,
and put `app.py` first in the review queue. The workflow uploads no artifact.
GitHub retains its normal workflow logs and job summary.

This is a synthetic product walkthrough, not a scanner run or proof that a
vulnerability is real, exploitable, fixed, or absent. Lumi does not execute the
fixture, discover vulnerabilities, or send source to a NOQT service. Do not
replace the fixture with private source or sensitive findings in a public fork.

If it fails, ranks the wrong path, explains the result badly, or never starts,
[post the public run or exact blocker](https://github.com/noqt/Lumi-Trace/issues/new?template=bandit_demo_result.yml).
The short form asks only what happened and where you got stuck. Do not post
secrets, private paths, source, screenshots, raw logs, or live vulnerability
details.
