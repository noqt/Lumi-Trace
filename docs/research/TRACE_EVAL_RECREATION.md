# Trace-Eval Environment Recreation

Trace-Eval and the V0.1 system under test must be installed into separate
Python 3.11 virtual environments. Neither environment may use an editable
install. Stage the approved wheels and the exact dependency wheelhouse before
switching to offline operation.

```powershell
python scripts\recreate_trace_eval.py `
  --python C:\path\to\approved-python-3.11.exe `
  --root X:\isolated\skylark-lumi-trace-eval\runtime `
  --wheelhouse Y:\governed\skylark-lumi-trace-eval\wheelhouse `
  --eval-wheel Y:\staging\skylark_lumi_trace_eval-0.2.0-py3-none-any.whl `
  --sut-wheel Y:\staging\skylark_lumi_trace-0.1.0-py3-none-any.whl `
  --eval-sha256 sha256:EVALUATOR_WHEEL_DIGEST `
  --sut-sha256 sha256:c3872c3ab25b1df4c4e2f31711f9072d25e4955a1cda3eecd89e421d901c0bba
```

The evaluator lock is `eval/requirements/trace-eval.lock`. The SUT wheel has
no third-party runtime dependencies. Environment qualification records Python,
packages, OS, architecture, Docker, filesystem facts, separated roots, and the
exact V0.1 artifact hash. Machine-specific receipts stay outside the public
repository.
