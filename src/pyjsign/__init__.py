#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
pyjsign: Python implementation of JSON signing formats.

Supports JSF (JSON Signature Format, https://cyberphone.github.io/doc/security/jsf.html)
and JSS (ITU-T X.590 JSON Signature Scheme).

This package provides signing and verification of JSON objects using
cryptographic signatures in either format.

Example:
    >>> from pyjsign import JSFSignature
    >>>
    >>> # Sign with EC key
    >>> ec_key = {
    ...     "kty": "EC",
    ...     "crv": "P-256",
    ...     "x": "...",
    ...     "y": "...",
    ...     "d": "..."
    ... }
    >>>
    >>> signer = JSFSignature(ec_key, 'ES256')
    >>> obj = {"data": "test"}
    >>> signed = signer.sign(obj)
    >>>
    >>> # Verify
    >>> verifier = JSFSignature(ec_key, 'ES256')
    >>> is_valid = verifier.verify(signed)
"""

from .algorithm_registry import AlgorithmRegistry
from .canonicalization import canonicalize, parse_canonical_json
from .certificate import CertificateHandler
from .jsf import JSFSignature
from .jss import JSSSignature
from .jwk_handler import JWKHandler
from .signer import Signer
from .version import VERSION

__version__ = VERSION
__all__ = [
    "JSFSignature",
    "Signer",
    "JSSSignature",
    "canonicalize",
    "parse_canonical_json",
    "JWKHandler",
    "AlgorithmRegistry",
    "CertificateHandler",
    "VERSION",
]
