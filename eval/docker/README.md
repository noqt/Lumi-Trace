# Trace-Eval Linux Reference Image

The Linux compatibility lane uses a digest-pinned official Python 3.11 base
and installs Trace-Eval and Lumi Trace into separate virtual environments from
an offline build context. The context has this shape:

```text
artifacts/
  skylark_lumi_trace_eval-0.2.0-py3-none-any.whl
  skylark_lumi_trace-0.1.0-py3-none-any.whl
wheelhouse/
  exact Linux wheels from eval/requirements/trace-eval.lock
trace-eval.lock
```

Stage and verify the base image and every wheel before building. Build with
network disabled after staging:

```text
docker build --network=none \
  --build-arg PYTHON_BASE=python@sha256:APPROVED_DIGEST \
  --build-arg EVALUATOR_WHEEL=skylark_lumi_trace_eval-0.2.0-py3-none-any.whl \
  --build-arg SUT_WHEEL=skylark_lumi_trace-0.1.0-py3-none-any.whl \
  -f eval/docker/Dockerfile BUILD_CONTEXT
```

Run cases with `--network none`, read-only source mounts, a disposable writable
workspace, bounded memory/CPU/PIDs, and no Docker socket. The Windows Python
3.11 lane is reported separately and must not be pooled with Linux results.
