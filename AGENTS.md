# Agent Instructions

## REQUIRED: Virtual Environment Usage

**ALL testing and development MUST be done in a Python virtual environment.**

This is mandatory to ensure:
1. Dependency isolation (no conflicts with system packages)
2. Reproducible test results
3. Clean environment for each agent session
4. Compliance with development practices

### Setup Virtual Environment (Required Before Any Work)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### ALWAYS Run Tests in Virtual Environment

Before committing ANY changes, run tests inside the activated venv:

```bash
# IMPORTANT: Verify venv is active (you should see (venv) in prompt)
python3 -m pytest tests/ -v
```

Do NOT run `pytest` without first activating the venv.

### Cleanup Virtual Environment (After Work Complete)

```bash
deactivate
rm -rf venv
```

## Project Information

- **Project**: pyjsign — Python implementation of JSON signing formats
  (JSF and JSS)
- **JSF Specification**: https://cyberphone.github.io/doc/security/jsf.html
- **Python Version**: 3.8+ (3.10+ recommended for testing)
- **Key Dependencies**: cryptography, pycryptodome

## Testing Requirements

**All changes must pass the full test suite before being committed.**

- Test suite: 329 tests covering all algorithms and edge cases
- Location: `tests/` directory
- Must run in virtual environment: `source venv/bin/activate && python3 -m pytest tests/ -v`
- Expected result: All tests pass (0 failures)

### Code Coverage

To check code coverage:

```bash
source venv/bin/activate
./coverage.sh
```

Or manually:

```bash
python3 -m pytest tests/ --cov=src/pyjsign --cov-report=term-missing
```

Current target: >80% coverage for src/pyjsign/

## Code Formatting

**REQUIRED: All code MUST be formatted with `black` before being committed.**

`black` is installed as part of the dev dependencies. Inside the activated venv,
before every commit:

```bash
source venv/bin/activate
black src/ tests/
```

To check formatting without modifying files (e.g. in CI or as a pre-commit
check):

```bash
black --check src/ tests/
```

Do NOT commit changes that fail `black --check`.

## Comments and Documentation

Comments and documentation (docstrings, README, AGENTS.md, etc.) must be
concise and avoid extraneous information. Only comment code that needs
clarification; do not restate what the code already makes obvious. Do not
add historical notes, rationale for rejected alternatives, or other
narrative detail that isn't needed to understand or use the code.

## Licensing

**REQUIRED: Every new file must start with SPDX license headers.**

All new source, test, and script files must begin with:

```
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: <copyright holder>
```

Use the comment syntax appropriate for the file type (e.g. `#` for Python/
shell, `//` for languages that don't support `#`). Match the existing header
style already present in `src/pyjsign/*.py` when adding new files.

The copyright holder is not always the same for every change. If it is not
already clear from context (e.g. existing headers in the same file/PR, or
explicit user instruction), **ask the user** what `SPDX-FileCopyrightText`
value to use rather than assuming one.

### Verify REUSE Compliance

Before committing ANY changes, verify SPDX/REUSE compliance inside the
activated venv:

```bash
source venv/bin/activate
reuse lint
```

Fix any reported issues (e.g. missing/incorrect SPDX headers) before
committing. `reuse` is installed as part of the dev dependencies.

### Lint with ruff

**REQUIRED: `ruff check` must pass before every commit.**

```bash
source venv/bin/activate
ruff check .
```

Fix any reported issues before committing (many are auto-fixable via
`ruff check --fix .`; re-run `black src/ tests/` afterward, since ruff's
import-sort fixes can change formatting that black then needs to
reconcile). `ruff` is installed as part of the dev dependencies.

### Type check with mypy

**REQUIRED: `mypy src/pyjsign` must pass with no errors before every commit.**

```bash
source venv/bin/activate
mypy src/pyjsign
```

Fix any reported issues before committing. `mypy` is installed as part of
the dev dependencies.
