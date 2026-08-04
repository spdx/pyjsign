#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Entry point for running pyjsign as a module."""

import sys

from .cli import main

sys.exit(main())
