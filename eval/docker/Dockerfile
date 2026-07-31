# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
ARG PYTHON_BASE=python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1
FROM ${PYTHON_BASE}

ARG EVALUATOR_WHEEL
ARG SUT_WHEEL

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/trace-eval/bin:/opt/lumi-trace/bin:/usr/local/bin:/usr/bin:/bin

COPY wheelhouse/ /opt/wheelhouse/
COPY artifacts/ /opt/artifacts/
COPY trace-eval.lock /opt/trace-eval.lock

RUN python -m venv /opt/trace-eval \
    && python -m venv /opt/lumi-trace \
    && /opt/trace-eval/bin/pip install --no-index --find-links=/opt/wheelhouse \
       --require-hashes -r /opt/trace-eval.lock \
    && /opt/trace-eval/bin/pip install --no-index --no-deps \
       /opt/artifacts/${EVALUATOR_WHEEL} \
    && /opt/lumi-trace/bin/pip install --no-index --no-deps \
       /opt/artifacts/${SUT_WHEEL} \
    && /usr/sbin/groupadd --system trace-eval \
    && /usr/sbin/useradd --system --gid trace-eval --home-dir /home/trace-eval \
       --create-home trace-eval \
    && mkdir -p /workspace /runs \
    && chown -R trace-eval:trace-eval /workspace /runs /home/trace-eval

USER trace-eval
WORKDIR /runner
ENTRYPOINT ["/opt/trace-eval/bin/trace-eval"]
