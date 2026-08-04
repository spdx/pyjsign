#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
# Run tests with coverage reporting

set -e

# Check if virtual environment is active
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "Error: Virtual environment not activated"
    echo "Please run: source venv/bin/activate"
    exit 1
fi

# Run pytest with coverage
python3 -m pytest tests/ \
    --cov=src/pyjsign \
    --cov-report=term-missing \
    --cov-report=html \
    --cov-report=json \
    "$@"

# Show coverage summary
echo ""
echo "Coverage report generated:"
echo "  Terminal: See above"
echo "  HTML: file://$(pwd)/htmlcov/index.html"
echo "  JSON: $(pwd)/.coverage"
