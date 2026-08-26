# SPDX-License-Identifier: Apache-2.0
"""Inert synthetic source fixture. The demo never imports or executes it."""

import subprocess


def run_command(user_command: str) -> None:
    subprocess.run(user_command, shell=True, check=True)  # nosec: synthetic fixture
