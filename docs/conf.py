#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Sphinx configuration for pyjsign documentation."""

import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

from pyjsign.version import VERSION  # noqa: E402

project = "pyjsign"
copyright = "Garmin Ltd. or its subsidiaries"
author = "Joshua Watt"
release = VERSION
version = VERSION

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
]

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_admonition_for_examples = True

autodoc_member_order = "bysource"
autodoc_typehints = "description"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
html_static_path = []
