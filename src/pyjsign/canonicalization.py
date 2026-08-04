#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
JSON canonicalization for JSF (JSON Signature Format).
Implements RFC 8785 "JSON Canonicalization Scheme (JCS)" and JSF requirements
using the ``rfc8785`` library (https://pypi.org/project/rfc8785/).
"""

import json
from typing import Any

import rfc8785


def canonicalize(obj: Any) -> bytes:
    """
    Canonicalize a JSON object per RFC 8785 and JSF spec.

    Returns UTF-8 encoded canonical JSON:
    - Object keys sorted alphabetically
    - No whitespace (except inside strings)
    - Numbers in shortest decimal form
    - Unicode escapes minimized
    - Proper UTF-8 encoding

    Args:
        obj: JSON-serializable Python object

    Returns:
        UTF-8 encoded canonical JSON bytes

    Raises:
        ValueError: If obj contains values that cannot be canonicalized
            (e.g. NaN/Infinity floats).
        TypeError: If obj contains values that are not JSON serializable.

    Example:
        >>> canonicalize({"name": "Joe", "id": 123})
        b'{"id":123,"name":"Joe"}'
    """
    try:
        return rfc8785.dumps(obj)
    except rfc8785.CanonicalizationError as e:
        raise ValueError(str(e)) from e
    except TypeError as e:
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable") from e


def parse_canonical_json(data: bytes) -> Any:
    """
    Parse canonical JSON (reverse of canonicalize).

    Args:
        data: UTF-8 encoded JSON bytes

    Returns:
        Parsed Python object
    """
    return json.loads(data.decode("utf-8"))
