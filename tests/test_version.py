#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
import subprocess

from pyjsign import VERSION


def test_version():
    p = subprocess.run(["pyjsign", "--version"], capture_output=True, text=True)
    assert p.returncode == 0
    assert p.stdout.strip() == VERSION
