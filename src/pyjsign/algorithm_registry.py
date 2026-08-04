#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Registry of supported signature algorithms, shared by JSF and JSS.
Maps algorithm names to their type, hash algorithm, and compatible key types.
"""

from enum import Enum
from typing import Optional


class AlgorithmType(Enum):
    """Algorithm types."""

    ECDSA = "ECDSA"
    RSA_PKCS1 = "RSA_PKCS1"
    RSA_PSS = "RSA_PSS"
    HMAC = "HMAC"
    EDDSA = "EDDSA"


class Algorithm:
    """Represents a signature algorithm."""

    def __init__(
        self,
        name: str,
        algorithm_type: AlgorithmType,
        hash_algorithm: Optional[str] = None,
        key_types: Optional[list] = None,
    ):
        self.name = name
        self.algorithm_type = algorithm_type
        self.hash_algorithm = hash_algorithm
        self.key_types = key_types or []


class AlgorithmRegistry:
    """
    Registry of supported signature algorithms.

    Example:
        >>> AlgorithmRegistry.list_algorithms()
        ['ES256', 'ES384', 'ES512', 'RS256', ...]
        >>> alg = AlgorithmRegistry.get_algorithm("ES256")
        >>> alg.algorithm_type
        <AlgorithmType.ECDSA: 'ECDSA'>
        >>> AlgorithmRegistry.validate_algorithm_key_type("ES256", "EC")
        True
    """

    # Supported algorithms per the JSF/JWA algorithm names
    ALGORITHMS = {
        # ECDSA with SHA-256/384/512
        "ES256": Algorithm("ES256", AlgorithmType.ECDSA, "SHA256", ["EC"]),
        "ES384": Algorithm("ES384", AlgorithmType.ECDSA, "SHA384", ["EC"]),
        "ES512": Algorithm("ES512", AlgorithmType.ECDSA, "SHA512", ["EC"]),
        # RSA PKCS#1 v1.5
        "RS256": Algorithm("RS256", AlgorithmType.RSA_PKCS1, "SHA256", ["RSA"]),
        "RS384": Algorithm("RS384", AlgorithmType.RSA_PKCS1, "SHA384", ["RSA"]),
        "RS512": Algorithm("RS512", AlgorithmType.RSA_PKCS1, "SHA512", ["RSA"]),
        # RSA PSS
        "PS256": Algorithm("PS256", AlgorithmType.RSA_PSS, "SHA256", ["RSA"]),
        "PS384": Algorithm("PS384", AlgorithmType.RSA_PSS, "SHA384", ["RSA"]),
        "PS512": Algorithm("PS512", AlgorithmType.RSA_PSS, "SHA512", ["RSA"]),
        # HMAC
        "HS256": Algorithm("HS256", AlgorithmType.HMAC, "SHA256", ["oct"]),
        "HS384": Algorithm("HS384", AlgorithmType.HMAC, "SHA384", ["oct"]),
        "HS512": Algorithm("HS512", AlgorithmType.HMAC, "SHA512", ["oct"]),
        # EdDSA
        "EdDSA": Algorithm("EdDSA", AlgorithmType.EDDSA, None, ["OKP"]),
        # JSF spec (RFC 8037) uses curve-specific names instead of "EdDSA"
        "Ed25519": Algorithm("Ed25519", AlgorithmType.EDDSA, None, ["OKP"]),
        "Ed448": Algorithm("Ed448", AlgorithmType.EDDSA, None, ["OKP"]),
    }

    @staticmethod
    def get_algorithm(name: str) -> Optional[Algorithm]:
        """Get algorithm by name."""
        return AlgorithmRegistry.ALGORITHMS.get(name)

    @staticmethod
    def validate_algorithm_key_type(algorithm: str, key_type: str) -> bool:
        """
        Validate that algorithm is compatible with key type.

        Args:
            algorithm: Algorithm name (e.g., 'ES256')
            key_type: JWK key type (e.g., 'EC')

        Returns:
            True if compatible, False otherwise
        """
        alg = AlgorithmRegistry.get_algorithm(algorithm)
        if not alg:
            return False
        return key_type in alg.key_types

    @staticmethod
    def list_algorithms() -> list:
        """List all supported algorithms."""
        return list(AlgorithmRegistry.ALGORITHMS.keys())

    @staticmethod
    def get_hash_algorithm(jsf_algorithm: str) -> Optional[str]:
        """Get hash algorithm for an algorithm."""
        alg = AlgorithmRegistry.get_algorithm(jsf_algorithm)
        return alg.hash_algorithm if alg else None

    @staticmethod
    def get_algorithm_type(jsf_algorithm: str) -> Optional[AlgorithmType]:
        """Get algorithm type for an algorithm."""
        alg = AlgorithmRegistry.get_algorithm(jsf_algorithm)
        return alg.algorithm_type if alg else None
