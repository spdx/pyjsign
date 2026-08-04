#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Signing support backed by a HashiCorp Vault server's Transit secrets
engine (https://developer.hashicorp.com/vault/docs/secrets/transit).

This module lets ``JSFSignature`` and ``JSSSignature`` sign with a private
key that never leaves Vault: ``VaultTransitSigner.sign()`` calls Vault's
``/transit/sign/:name`` endpoint to perform the actual cryptographic
operation, while only the *public* key (fetched from Vault) is ever
held locally, for JWK/keyId/publicKey purposes.

Only asymmetric signing algorithms are supported (ECDSA, RSA PKCS#1
v1.5, RSA-PSS, Ed25519), matching the algorithms this project already
implements locally for JSF/JSS; HMAC-via-Vault is out of scope. Vault
authentication is token-based only (VAULT_ADDR/VAULT_TOKEN).

The ``hvac`` package (https://pypi.org/project/hvac/) is an optional
dependency (``pip install pyjsign[vault]``); it is imported lazily so that
importing ``pyjsign`` never requires it.
"""

import base64
from typing import Any, Dict, Optional, cast

from .base64url import base64url_decode
from .jwk_handler import RawKey
from .signer import Signer

# Maps each Vault-supported JSF algorithm to the Vault transit
# parameters needed to sign with it: the set of Vault key types
# ("type" field from read_key()) it is compatible with, the Vault
# hash_algorithm to request (None for Ed25519, which hashes
# internally and does not accept a hash_algorithm parameter), and the
# Vault signature_algorithm to request (only meaningful for RSA keys).
_ALGORITHM_MAP: Dict[str, Dict[str, Any]] = {
    "ES256": {"vault_key_types": {"ecdsa-p256"}, "hash_algorithm": "sha2-256"},
    "ES384": {"vault_key_types": {"ecdsa-p384"}, "hash_algorithm": "sha2-384"},
    "ES512": {"vault_key_types": {"ecdsa-p521"}, "hash_algorithm": "sha2-512"},
    "RS256": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-256",
        "signature_algorithm": "pkcs1v15",
    },
    "RS384": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-384",
        "signature_algorithm": "pkcs1v15",
    },
    "RS512": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-512",
        "signature_algorithm": "pkcs1v15",
    },
    "PS256": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-256",
        "signature_algorithm": "pss",
    },
    "PS384": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-384",
        "signature_algorithm": "pss",
    },
    "PS512": {
        "vault_key_types": {"rsa-2048", "rsa-3072", "rsa-4096"},
        "hash_algorithm": "sha2-512",
        "signature_algorithm": "pss",
    },
    "Ed25519": {"vault_key_types": {"ed25519"}, "hash_algorithm": None},
    "EdDSA": {"vault_key_types": {"ed25519"}, "hash_algorithm": None},
}


def _require_hvac() -> Any:
    """Import and return the ``hvac`` module, with an actionable error if missing."""
    try:
        import hvac
    except ImportError as e:
        raise ImportError(
            "The 'hvac' package is required for HashiCorp Vault signing support. "
            "Install it with: pip install pyjsign[vault]"
        ) from e
    return hvac


class VaultTransitSigner(Signer):
    """
    Signs data using a named key held in a HashiCorp Vault Transit
    secrets engine mount, without ever exposing the private key
    material locally.

    Example:
        >>> import hvac
        >>> from pyjsign import JSFSignature
        >>> from pyjsign.vault_signer import VaultTransitSigner
        >>> client = hvac.Client(url="https://vault.example.com:8200", token="s.xxxxxxxx")
        >>> vault_signer = VaultTransitSigner(client, key_name="my-signing-key")
        >>> signer = JSFSignature(
        ...     key=vault_signer.public_key("ES256"),
        ...     algorithm="ES256",
        ...     signer=vault_signer,
        ...     include_public_key=True,
        ... )
        >>> signed = signer.sign({"data": "test"})
    """

    def __init__(
        self,
        client: Any,
        key_name: str,
        mount_point: str = "transit",
        key_version: Optional[int] = None,
    ):
        """
        Args:
            client: An ``hvac.Client`` instance, already configured with
                a Vault address and a valid token.
            key_name: Name of the Transit key in Vault to sign/read
                the public key with.
            mount_point: Path the Transit secrets engine is mounted at
                (default: "transit").
            key_version: Optional specific key version to use. If not
                given, the key's latest version is used.
        """
        self.client = client
        self.key_name = key_name
        self.mount_point = mount_point
        self.key_version = key_version

    def _read_key_data(self) -> Any:
        """Fetch this key's ``read_key()`` response ``data`` payload from Vault."""
        response = self.client.secrets.transit.read_key(
            name=self.key_name,
            mount_point=self.mount_point,
        )
        return response["data"]

    def public_key(self, algorithm: str) -> RawKey:
        """
        Fetch this Vault key's public key for use with the given
        signing algorithm.

        Raises:
            ValueError: If ``algorithm`` is unsupported for Vault
                signing, or the Vault key's actual type is
                incompatible with ``algorithm``.
        """
        mapping = _ALGORITHM_MAP.get(algorithm)
        if mapping is None:
            raise ValueError(
                f"Algorithm {algorithm!r} is not supported for HashiCorp Vault signing"
            )

        data = self._read_key_data()
        vault_key_type = data["type"]
        if vault_key_type not in mapping["vault_key_types"]:
            raise ValueError(
                f"Vault key {self.key_name!r} has type {vault_key_type!r}, "
                f"which is incompatible with algorithm {algorithm!r}"
            )

        version = str(self.key_version or data["latest_version"])
        try:
            key_entry = data["keys"][version]
        except KeyError:
            raise ValueError(f"Vault key {self.key_name!r} has no version {version!r}") from None
        public_key_field = key_entry["public_key"]

        if vault_key_type == "ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            raw_bytes = base64.b64decode(public_key_field)
            return Ed25519PublicKey.from_public_bytes(raw_bytes)

        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        # `mapping["vault_key_types"]` already restricts this to EC/RSA
        # key types, so the loaded public key is always one of RawKey's
        # EC/RSA members.
        return cast(RawKey, load_pem_public_key(public_key_field.encode("ascii")))

    def sign(self, algorithm: str, data: bytes) -> bytes:
        """
        Sign ``data`` using this Vault key, and return the raw signature
        bytes in the same format the caller's local signing methods
        produce (e.g. concatenated fixed-width r||s for ECDSA).

        Raises:
            ValueError: If ``algorithm`` is not supported for Vault
                signing.
        """
        mapping = _ALGORITHM_MAP.get(algorithm)
        if mapping is None:
            raise ValueError(
                f"Algorithm {algorithm!r} is not supported for HashiCorp Vault signing"
            )

        response = self.client.secrets.transit.sign_data(
            name=self.key_name,
            hash_input=base64.b64encode(data).decode("ascii"),
            hash_algorithm=mapping["hash_algorithm"],
            signature_algorithm=mapping.get("signature_algorithm"),
            marshaling_algorithm="jws",
            key_version=self.key_version,
            mount_point=self.mount_point,
        )

        signature_value = response["data"]["signature"]
        # Vault's response is "vault:v<version>:<base64url-signature>".
        encoded_signature = signature_value.rsplit(":", 1)[-1]
        return base64url_decode(encoded_signature)


def build_vault_client(
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    namespace: Optional[str] = None,
) -> Any:
    """
    Build an ``hvac.Client``, reading ``VAULT_ADDR``/``VAULT_TOKEN``
    environment variables as defaults when ``vault_addr``/``vault_token``
    are not given (matching the standard ``vault`` CLI's conventions).

    Raises:
        ImportError: If the optional ``hvac`` dependency is not
            installed.
        ValueError: If no Vault address or token is available from
            either the arguments or the environment.
    """
    import os

    hvac = _require_hvac()

    addr = vault_addr or os.environ.get("VAULT_ADDR")
    token = vault_token or os.environ.get("VAULT_TOKEN")

    if not addr:
        raise ValueError(
            "No Vault address given: pass --vault-addr or set the VAULT_ADDR environment variable"
        )
    if not token:
        raise ValueError(
            "No Vault token given: pass --vault-token or set the VAULT_TOKEN environment variable"
        )

    return hvac.Client(url=addr, token=token, namespace=namespace)
