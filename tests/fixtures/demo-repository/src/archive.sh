#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

unsafe_join() {
    root="$1"
    member_name="$2"
    printf '%s/%s\n' "$root" "$member_name"
}
