#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
JWK (JSON Web Key) handler for JSF.
Converts cryptographic key objects to JWK format.
Supports EC, RSA, OKP, and symmetric keys per RFC 7517, using the
``joserfc`` library (https://pypi.org/project/joserfc/) for the JWK
<-> cryptography key object conversion. Parsing JWK dictionaries back
into keys is done with joserfc.jwk.import_key() directly.
"""

from typing import Union

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from joserfc.jwk import ECKey, OctKey, OKPKey, RSAKey

JWKKey = Union[
    ECKey,
    RSAKey,
    OKPKey,
    OctKey,
]

# Concrete class tuple usable with isinstance(), since isinstance() cannot
# accept a typing.Union directly.
JWK_KEY_CLASSES = (ECKey, RSAKey, OKPKey, OctKey)

RawKey = Union[
    RSAPublicKey,
    RSAPrivateKey,
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
    Ed25519PublicKey,
    Ed25519PrivateKey,
    Ed448PublicKey,
    Ed448PrivateKey,
    bytes,  # For symmetric keys
]


class JWKHandler:
    """Convert cryptographic key objects to JWK format."""

    @staticmethod
    def to_jwk(key: RawKey) -> JWKKey:
        """
        Convert a cryptographic key object (or raw bytes for symmetric keys) to JWK.

        Example:
            >>> jwk = JWKHandler.to_jwk(private_key)
            >>> jwk_dict = jwk.as_dict()
        """
        if isinstance(key, bytes):
            return OctKey.import_key(key)

        if isinstance(key, (RSAPublicKey, RSAPrivateKey)):
            return RSAKey.import_key(key)

        if isinstance(key, (EllipticCurvePublicKey, EllipticCurvePrivateKey)):
            return ECKey.import_key(key)

        if isinstance(key, (Ed25519PublicKey, Ed25519PrivateKey, Ed448PublicKey, Ed448PrivateKey)):
            return OKPKey.import_key(key)

        raise TypeError(f"Unsupported key type: {type(key)}")
