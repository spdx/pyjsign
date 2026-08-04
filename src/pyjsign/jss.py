#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
ITU-T X.590 "JSON signature scheme" (JSS) implementation.

JSS is a distinct-but-related JSON signature format from JSF (this
package's other supported format): signature objects are stored in a
top-level JSON array property (by default ``"signatures"``), each
signature is independently self-describing (embedding its own key
material) and its ``value`` is computed as::

    base64url(sign(algorithm, key, hash(jcs(<JSON object with signature object>))))

i.e. JCS canonicalization, followed by an *explicit* hashing step (named
by ``hash_algorithm``, separate from any hashing internal to
``algorithm`` itself), and finally signing that hash.

Only single- and multi-signature documents are supported (independent
entries in the ``signatures`` array); JSS countersigning (nested
``signature`` property, signature chains) is not yet implemented.
"""

import hashlib
from typing import Any, Callable, Dict, List, Optional, Union, cast

import joserfc.jwk
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from .algorithm_registry import AlgorithmRegistry, AlgorithmType
from .base64url import base64url_decode, base64url_encode
from .canonicalization import canonicalize
from .certificate import CertificateHandler
from .jwk_handler import JWK_KEY_CLASSES, JWKKey
from .signer import Signer

PublicKeyType = Union[
    ec.EllipticCurvePublicKey,
    rsa.RSAPublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
]
PrivateKeyType = Union[
    ec.EllipticCurvePrivateKey,
    rsa.RSAPrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
]

# JSS's "hash_algorithm" property uses IANA hash function names
# (https://www.iana.org/assignments/named-information/named-information.xhtml),
# e.g. "sha-256", not JWA-style names like "SHA256".
_HASH_ALGORITHMS: Dict[str, "type[hashes.HashAlgorithm]"] = {
    "sha-256": hashes.SHA256,
    "sha-384": hashes.SHA384,
    "sha-512": hashes.SHA512,
}
_HASHLIB_NAMES: Dict[str, str] = {
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
}

# Properties that self-describe the key used for a JSS signature entry;
# clause 6.2 requires exactly one to be present.
_KEY_LOCATOR_PROPERTIES = ("public_key", "public_cert_chain", "cert_url", "thumbprint")


def _get_hash_algorithm(hash_algorithm: str) -> hashes.HashAlgorithm:
    """Get the ``cryptography`` hash algorithm instance for a JSS ``hash_algorithm`` name."""
    try:
        return _HASH_ALGORITHMS[hash_algorithm]()
    except KeyError:
        raise ValueError(f"Unsupported hash_algorithm: {hash_algorithm}") from None


def _compute_digest(hash_algorithm: str, data: bytes) -> bytes:
    """Hash ``data`` using the hashlib algorithm named by a JSS ``hash_algorithm`` name."""
    try:
        name = _HASHLIB_NAMES[hash_algorithm]
    except KeyError:
        raise ValueError(f"Unsupported hash_algorithm: {hash_algorithm}") from None
    return hashlib.new(name, data).digest()


def _key_type(key: Union[PrivateKeyType, PublicKeyType]) -> str:
    """Determine the JWK-style key type ("EC"/"RSA"/"OKP") of a ``cryptography`` key object."""
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "EC"
    elif isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA"
    elif isinstance(
        key,
        (
            ed25519.Ed25519PublicKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PublicKey,
            ed448.Ed448PrivateKey,
        ),
    ):
        return "OKP"
    else:
        raise TypeError(f"Unsupported key type: {type(key)}")


def _pem_body_to_public_key(pem_body: str) -> PublicKeyType:
    """Parse a JSS ``public_key`` PEM body (no header/footer) into a public key object."""
    pem = f"-----BEGIN PUBLIC KEY-----\n{pem_body}\n-----END PUBLIC KEY-----\n".encode("ascii")
    return cast(PublicKeyType, load_pem_public_key(pem))


def _public_key_to_pem_body(public_key: PublicKeyType) -> str:
    """Encode a public key as a JSS ``public_key`` PEM body (no header/footer/newlines)."""
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))


def _sign_hash(
    private_key: PrivateKeyType,
    algorithm: str,
    digest: bytes,
    hash_alg: hashes.HashAlgorithm,
) -> bytes:
    """Sign an already-computed digest per the JSS "sign(algorithm, key, hash(...))" model."""
    alg_type = AlgorithmRegistry.get_algorithm_type(algorithm)

    if alg_type == AlgorithmType.ECDSA:
        ec_key = cast(ec.EllipticCurvePrivateKey, private_key)
        der_sig = ec_key.sign(digest, ec.ECDSA(Prehashed(hash_alg)))
        r, s = decode_dss_signature(der_sig)
        curve_order = (ec_key.curve.key_size + 7) // 8
        return r.to_bytes(curve_order, "big") + s.to_bytes(curve_order, "big")
    elif alg_type == AlgorithmType.RSA_PKCS1:
        rsa_key = cast(rsa.RSAPrivateKey, private_key)
        return rsa_key.sign(digest, padding.PKCS1v15(), Prehashed(hash_alg))
    elif alg_type == AlgorithmType.RSA_PSS:
        rsa_key = cast(rsa.RSAPrivateKey, private_key)
        pss_padding = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH)
        return rsa_key.sign(digest, pss_padding, Prehashed(hash_alg))
    elif alg_type == AlgorithmType.EDDSA:
        eddsa_key = cast(Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey], private_key)
        # EdDSA has no standard "prehash" mode usable here; JSS's pseudo
        # code signs the digest bytes directly as the message.
        return eddsa_key.sign(digest)
    else:
        raise ValueError(f"Unsupported JSS algorithm: {algorithm}")


def _verify_hash(
    public_key: PublicKeyType,
    algorithm: str,
    digest: bytes,
    hash_alg: hashes.HashAlgorithm,
    signature: bytes,
) -> bool:
    """Verify a signature over an already-computed digest. Returns False on any failure."""
    alg_type = AlgorithmRegistry.get_algorithm_type(algorithm)

    try:
        if alg_type == AlgorithmType.ECDSA:
            ec_key = cast(ec.EllipticCurvePublicKey, public_key)
            curve_order = (ec_key.curve.key_size + 7) // 8
            if len(signature) != 2 * curve_order:
                return False
            r = int.from_bytes(signature[:curve_order], "big")
            s = int.from_bytes(signature[curve_order:], "big")
            ec_key.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hash_alg)))
            return True
        elif alg_type == AlgorithmType.RSA_PKCS1:
            rsa_key = cast(rsa.RSAPublicKey, public_key)
            rsa_key.verify(signature, digest, padding.PKCS1v15(), Prehashed(hash_alg))
            return True
        elif alg_type == AlgorithmType.RSA_PSS:
            rsa_key = cast(rsa.RSAPublicKey, public_key)
            pss_padding = padding.PSS(
                mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH
            )
            rsa_key.verify(signature, digest, pss_padding, Prehashed(hash_alg))
            return True
        elif alg_type == AlgorithmType.EDDSA:
            eddsa_key = cast(Union[ed25519.Ed25519PublicKey, ed448.Ed448PublicKey], public_key)
            eddsa_key.verify(signature, digest)
            return True
        else:
            return False
    except Exception:
        return False


class JSSSignature:
    """
    Signer/verifier for ITU-T X.590 "JSON signature scheme" (JSS)
    documents.

    Only JWA-style algorithms (ES256/384/512, RS256/384/512,
    PS256/384/512, Ed25519, Ed448) are supported; post-quantum
    algorithms (XMSS/LMS) named in the JSS vocabulary are not.
    Countersigning (nested ``signature`` property) is not supported --
    only single- and multi-signature documents (independent entries in
    the ``signatures`` array).

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ed25519
        >>> from pyjsign import JSSSignature
        >>> private_key = ed25519.Ed25519PrivateKey.generate()
        >>> signer = JSSSignature(private_key, "Ed25519", include_public_key=True)
        >>> signed = signer.sign({"statement": "Hello signed world!"})
        >>> JSSSignature.verify(signed)
        True
    """

    def __init__(
        self,
        key: Union[Dict[str, Any], JWKKey, PrivateKeyType, PublicKeyType],
        algorithm: str,
        hash_algorithm: str = "sha-256",
        signatures_property: str = "signatures",
        include_public_key: bool = False,
        certificate_path: Optional[List[Any]] = None,
        cert_url: Optional[str] = None,
        thumbprint: Optional[bytes] = None,
        signer: Optional[Signer] = None,
    ):
        """
        Initialize JSSSignature.

        Args:
            key: A ``cryptography`` private key (to sign) or public key
                (to embed/verify only), or a JWK dictionary/``joserfc`` key
                object holding an EC, RSA, or OKP key (unwrapped to the
                underlying ``cryptography`` key; JSS has no symmetric/HMAC
                algorithm support, unlike JSF). When ``signer`` is given,
                this is expected to be the corresponding public key.
            algorithm: JSS signing algorithm name (e.g. "ES256",
                "Ed25519").
            hash_algorithm: JSS hash algorithm name used to hash the
                canonicalized JSON before signing (e.g. "sha-256",
                "sha-384", "sha-512").
            signatures_property: Name of the top-level array property
                holding JSS signature objects (default: "signatures").
            include_public_key: Embed this instance's public key (PEM
                body, no header/footer) as "public_key". Ignored if
                ``certificate_path``, ``cert_url``, or ``thumbprint`` is set,
                since those take precedence in that order.
            certificate_path: Optional ordered list (leaf-to-root) of
                X.509 certificates to embed as "public_cert_chain".
                Takes precedence over ``cert_url``, ``thumbprint``, and
                ``include_public_key``.
            cert_url: Optional URI to embed as "cert_url". Takes
                precedence over ``thumbprint`` and ``include_public_key``.
            thumbprint: Optional raw SHA-256 X.509 certificate
                thumbprint bytes to embed (base64url-encoded) as
                "thumbprint". Takes precedence over
                ``include_public_key``.
            signer: Optional ``Signer`` instance performing the actual
                signing operation instead of local private-key crypto
                (e.g. a HashiCorp Vault Transit key, see
                ``pyjsign.vault_signer``). When given, ``signer.sign(algorithm,
                digest)`` is called with the JSS digest (hash of the
                canonicalized JSON) to obtain the raw signature bytes.

        Raises:
            ValueError: If ``algorithm`` or ``hash_algorithm`` is
                unsupported, or ``algorithm`` is incompatible with ``key``'s
                type.
        """
        if not AlgorithmRegistry.get_algorithm(algorithm):
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if hash_algorithm not in _HASH_ALGORITHMS:
            raise ValueError(f"Unsupported hash_algorithm: {hash_algorithm}")

        if isinstance(key, JWK_KEY_CLASSES):
            key = cast(Union[PrivateKeyType, PublicKeyType], key.raw_value)
        elif isinstance(key, dict):
            key = cast(Union[PrivateKeyType, PublicKeyType], joserfc.jwk.import_key(key).raw_value)

        self.key = key
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        self.signatures_property = signatures_property
        self.include_public_key = include_public_key
        self.certificate_path = certificate_path
        self.cert_url = cert_url
        self.thumbprint = thumbprint
        self._external_signer = signer

        key_type = _key_type(key)
        if not AlgorithmRegistry.validate_algorithm_key_type(algorithm, key_type):
            raise ValueError(f"Algorithm {algorithm} incompatible with key type {key_type}")

    def _ensure_private_key(self) -> None:
        """Raise ValueError if this instance's key is public-only (unless using ``signer``)."""
        if self._external_signer is not None:
            return
        if isinstance(
            self.key,
            (
                ec.EllipticCurvePublicKey,
                rsa.RSAPublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ),
        ):
            raise ValueError("Cannot sign with a public key")

    def _public_key(self) -> PublicKeyType:
        """Get this instance's public key, deriving it from a private key if needed."""
        if hasattr(self.key, "public_key"):
            return cast(PublicKeyType, self.key.public_key())
        return cast(PublicKeyType, self.key)

    def _build_entry(self) -> Dict[str, Any]:
        """Build an incomplete JSS signature object (no "value" yet)."""
        entry: Dict[str, Any] = {
            "hash_algorithm": self.hash_algorithm,
            "algorithm": self.algorithm,
        }

        if self.certificate_path:
            entry["public_cert_chain"] = CertificateHandler.encode_certificate_path(
                self.certificate_path
            )
        elif self.cert_url:
            entry["cert_url"] = self.cert_url
        elif self.thumbprint:
            entry["thumbprint"] = base64url_encode(self.thumbprint)
        elif self.include_public_key:
            entry["public_key"] = _public_key_to_pem_body(self._public_key())

        if not any(name in entry for name in _KEY_LOCATOR_PROPERTIES):
            raise ValueError(
                "One of include_public_key, certificate_path, cert_url, or thumbprint "
                "must be set so the signature is self-describing"
            )

        return entry

    def sign(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a JSON object, appending a new JSS signature object to
        ``obj[signatures_property]`` (creating the array if absent).

        Any pre-existing entries are preserved (added back before the
        new entry), but are excluded from what this new signature
        itself covers, per the JSS signing algorithm (clause 7.1):
        only this instance's own (initially value-less) signature
        object is present in the array while it is canonicalized,
        hashed, and signed.

        Args:
            obj: Object to sign

        Returns:
            A new dict with the new signature object appended

        Raises:
            ValueError: If this instance's key is public-only (and no
                ``signer`` was given), if ``signatures_property`` is
                present but not a JSON array, or if none of
                ``include_public_key``/``certificate_path``/``cert_url``/
                ``thumbprint`` is set
        """
        self._ensure_private_key()

        existing = obj.get(self.signatures_property, [])
        if self.signatures_property in obj and not isinstance(existing, list):
            raise ValueError(f"'{self.signatures_property}' property must be a JSON array")

        entry = self._build_entry()

        signed_obj = dict(obj)
        signed_obj[self.signatures_property] = [entry]

        canonical = canonicalize(signed_obj)
        digest = _compute_digest(self.hash_algorithm, canonical)

        if self._external_signer is not None:
            raw_signature = self._external_signer.sign(self.algorithm, digest)
        else:
            hash_alg = _get_hash_algorithm(self.hash_algorithm)
            raw_signature = _sign_hash(
                cast(PrivateKeyType, self.key), self.algorithm, digest, hash_alg
            )

        entry["value"] = base64url_encode(raw_signature)
        signed_obj[self.signatures_property] = list(existing) + [entry]

        return signed_obj

    @staticmethod
    def sign_multi(
        obj: Dict[str, Any],
        signers: List["JSSSignature"],
    ) -> Dict[str, Any]:
        """
        Sign a JSON object with multiple independent JSS signers,
        appending one signature object per signer (in order).

        Args:
            obj: Object to sign
            signers: Ordered list of ``JSSSignature`` instances, all
                sharing the same ``signatures_property``

        Returns:
            A new dict with one signature object appended per signer

        Raises:
            ValueError: If ``signers`` is empty, or the signers don't all
                share the same ``signatures_property``

        Example:
            >>> signer_a = JSSSignature(key_a, "ES256", include_public_key=True)
            >>> signer_b = JSSSignature(key_b, "Ed25519", include_public_key=True)
            >>> signed = JSSSignature.sign_multi({"statement": "..."}, [signer_a, signer_b])
            >>> JSSSignature.verify(signed)
            True
        """
        if not signers:
            raise ValueError("sign_multi() requires at least one signer")

        signatures_property = signers[0].signatures_property
        if any(signer.signatures_property != signatures_property for signer in signers):
            raise ValueError("All signers passed to sign_multi() must share signatures_property")

        result = obj
        for signer in signers:
            result = signer.sign(result)
        return result

    @staticmethod
    def _resolve_entry_public_key(
        entry: Dict[str, Any],
        resolve_key: Optional[Callable[[Dict[str, Any]], PublicKeyType]],
    ) -> PublicKeyType:
        """Resolve the public key for a JSS signature entry (clause 8.1.3)."""
        if "public_key" in entry:
            return _pem_body_to_public_key(entry["public_key"])
        if "public_cert_chain" in entry:
            certs = CertificateHandler.parse_certificate_path(entry["public_cert_chain"])
            return cast(PublicKeyType, certs[0].public_key())
        if "cert_url" in entry or "thumbprint" in entry:
            if resolve_key is None:
                raise ValueError(
                    "Signature entry uses 'cert_url' or 'thumbprint'; a resolve_key "
                    "callback is required to verify it"
                )
            return resolve_key(entry)
        raise ValueError(
            "Signature entry has none of public_key, public_cert_chain, cert_url, " "or thumbprint"
        )

    @staticmethod
    def _verify_entry(
        obj: Dict[str, Any],
        signatures_property: str,
        index: int,
        resolve_key: Optional[Callable[[Dict[str, Any]], PublicKeyType]],
    ) -> bool:
        """Verify a single entry (by index) of ``obj[signatures_property]``."""
        entries = obj[signatures_property]
        entry = dict(entries[index])

        if "value" not in entry or "hash_algorithm" not in entry or "algorithm" not in entry:
            return False

        signature_value = entry.pop("value")

        try:
            public_key = JSSSignature._resolve_entry_public_key(entry, resolve_key)
        except ValueError:
            return False

        temp_obj = dict(obj)
        temp_obj[signatures_property] = [entry]

        try:
            canonical = canonicalize(temp_obj)
            digest = _compute_digest(entry["hash_algorithm"], canonical)
            hash_alg = _get_hash_algorithm(entry["hash_algorithm"])
            signature = base64url_decode(signature_value)
            return _verify_hash(public_key, entry["algorithm"], digest, hash_alg, signature)
        except Exception:
            return False

    @staticmethod
    def verify(
        obj: Dict[str, Any],
        signatures_property: str = "signatures",
        resolve_key: Optional[Callable[[Dict[str, Any]], PublicKeyType]] = None,
    ) -> bool:
        """
        Verify every JSS signature object present in
        ``obj[signatures_property]``.

        Each entry is independently self-describing (per clause 6.2, at
        least one of "public_key"/"public_cert_chain"/"cert_url"/
        "thumbprint" must be present); ``resolve_key``, if given, is
        called for entries that only carry "cert_url" or "thumbprint"
        and must return the corresponding public key.

        Args:
            obj: The (possibly) signed JSON object
            signatures_property: Name of the top-level array property
                holding JSS signature objects (default: "signatures")
            resolve_key: Optional callback invoked with a signature
                entry (its "value" removed) to resolve a public key
                for entries using "cert_url"/"thumbprint"

        Returns:
            True only if ``signatures_property`` is present, holds a
            non-empty JSON array, and every entry verifies
            successfully. False otherwise (never raises for
            verification failures).
        """
        entries = obj.get(signatures_property)
        if not isinstance(entries, list) or not entries:
            return False

        return all(
            JSSSignature._verify_entry(obj, signatures_property, index, resolve_key)
            for index in range(len(entries))
        )

    @staticmethod
    def get_certificate_chain(
        obj: Dict[str, Any], signatures_property: str = "signatures"
    ) -> Optional[List[x509.Certificate]]:
        """
        Extract the certificate chain embedded in a signed object's first
        signature entry, for the caller to validate independently (chain
        of trust, expiry, revocation, etc. are not checked by this
        library).

        Args:
            obj: Signed JSON object
            signatures_property: Name of the top-level array property
                holding JSS signature objects (default: "signatures")

        Returns:
            Leaf-to-root list of ``x509.Certificate``, or None if the entry
            has no "public_cert_chain"

        Raises:
            ValueError: If ``signatures_property`` is missing or malformed

        Example:
            >>> chain = JSSSignature.get_certificate_chain(signed_obj)
            >>> if chain is not None:
            ...     leaf_cert = chain[0]
        """
        return JSSSignature.get_certificate_chains(obj, signatures_property=signatures_property)[0]

    @staticmethod
    def get_certificate_chains(
        obj: Dict[str, Any], signatures_property: str = "signatures"
    ) -> List[Optional[List[x509.Certificate]]]:
        """
        Extract every embedded certificate chain from a signed object's
        ``signatures_property`` array, one entry per signature, in order,
        for the caller to validate independently (chain of trust,
        expiry, revocation, etc. are not checked by this library).

        Args:
            obj: Signed JSON object
            signatures_property: Name of the top-level array property
                holding JSS signature objects (default: "signatures")

        Returns:
            List with one item per signature entry: a leaf-to-root list of
            ``x509.Certificate`` if the entry has a "public_cert_chain",
            else None for that position

        Raises:
            ValueError: If ``signatures_property`` is missing or malformed
        """
        if signatures_property not in obj:
            raise ValueError(f"Missing signatures property: {signatures_property}")

        entries = obj[signatures_property]
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"{signatures_property} must be a non-empty array")

        chains: List[Optional[List[x509.Certificate]]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Malformed signature entry")
            if "public_cert_chain" in entry:
                chains.append(CertificateHandler.parse_certificate_path(entry["public_cert_chain"]))
            else:
                chains.append(None)

        return chains
