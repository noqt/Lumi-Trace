#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

. /repo/src/archive.sh
mkdir -p /tmp/lumi-trace-root
candidate="$(unsafe_join /tmp/lumi-trace-root ../escaped.txt)"
printf '%s\n' 'escaped' > "$candidate"

if [ -f /tmp/escaped.txt ]; then
    printf '%s\n' 'LUMI_TRACE_WITNESS:path-traversal'
    exit 23
fi

printf '%s\n' 'witness not observed' >&2
exit 1
