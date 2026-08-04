#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
JSF Signature implementation.
Handles signing and verification for EC, RSA, OKP, and symmetric keys.
"""

import hashlib
import hmac
from typing import Any, Dict, List, Optional, Union, cast

import joserfc.jwk
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .algorithm_registry import AlgorithmRegistry, AlgorithmType
from .base64url import base64url_decode, base64url_encode
from .canonicalization import canonicalize
from .certificate import CertificateHandler
from .jwk_handler import JWK_KEY_CLASSES, JWKHandler, JWKKey, RawKey
from .signer import Signer


class JSFSignature:
    """
    JSON Signature Format implementation.
    Supports signing and verification with EC, RSA, OKP, and symmetric keys.

    Example:
        >>> from pyjsign import JSFSignature
        >>> ec_key = {
        ...     "kty": "EC",
        ...     "crv": "P-256",
        ...     "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        ...     "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        ...     "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
        ... }
        >>> signer = JSFSignature(ec_key, "ES256")
        >>> signed = signer.sign({"name": "Joe", "id": 2200063})
        >>> verifier = JSFSignature(ec_key, "ES256")
        >>> verifier.verify(signed)
        True
    """

    # Reserved signaturecore/Global Signature Options property names that
    # must not be (re)used as extension property names (JSF spec section 5).
    _RESERVED_PROPERTY_NAMES = frozenset(
        {
            "algorithm",
            "certificatePath",
            "chain",
            "extensions",
            "excludes",
            "keyId",
            "publicKey",
            "signers",
            "value",
        }
    )

    def __init__(
        self,
        key: Union[Dict[str, Any], JWKKey, RawKey],
        algorithm: str,
        signature_property: str = "signature",
        certificate_path: Optional[List[Any]] = None,
        include_public_key: bool = False,
        signer: Optional[Signer] = None,
    ):
        """
        Initialize JSFSignature.

        Args:
            key: JWK dictionary or cryptographic key object
            algorithm: Algorithm name (e.g., 'ES256', 'RS256')
            signature_property: Name of signature property in JSON (default: 'signature')
            certificate_path: Optional ordered list (leaf-to-root) of X.509
                certificates to embed as "certificatePath" whenever this
                instance signs. Each entry is either an ``x509.Certificate``
                object or raw DER-encoded bytes. Takes precedence over
                ``include_public_key=True``: if both are set, only
                "certificatePath" is embedded and ``include_public_key`` is
                silently ignored.
            include_public_key: Embed this instance's public key as
                "publicKey" whenever it signs. Ignored (no-op) for
                symmetric (oct/HMAC) keys, since there is no public key to
                embed and doing so would expose the secret key material.
                Also ignored (no-op) whenever ``certificate_path`` is set,
                since ``certificate_path`` takes precedence.
            signer: Optional ``Signer`` instance performing the actual
                signing operation instead of local private-key crypto,
                e.g. to delegate to a remote signer such as a HashiCorp
                Vault Transit key (see ``pyjsign.vault_signer``). When
                given, ``key`` is expected to be the corresponding
                *public* key (used only for JWK/keyId/publicKey
                purposes); the "Cannot sign with a public key" check is
                skipped, and ``sign()``/``sign_multi()``/``sign_chain()``
                call ``signer.sign(algorithm, canonicalized_signing_input)``
                to obtain the raw signature bytes instead of signing
                locally.
        """
        self.signature_property = signature_property
        self.algorithm = algorithm
        self.certificate_path = certificate_path
        self.include_public_key = include_public_key
        self._external_signer = signer

        # Validate algorithm
        if not AlgorithmRegistry.get_algorithm(algorithm):
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        self.jwk: JWKKey
        self.key: RawKey

        if isinstance(key, JWK_KEY_CLASSES):
            self.jwk = key
            self.key = cast(RawKey, self.jwk.raw_value)
        elif isinstance(key, dict):
            self.jwk = joserfc.jwk.import_key(key)
            self.key = cast(RawKey, self.jwk.raw_value)
        else:
            self.key = key
            self.jwk = JWKHandler.to_jwk(key)

        jwk_key_type = self._get_jwk_key_type()

        if not AlgorithmRegistry.validate_algorithm_key_type(algorithm, jwk_key_type):
            raise ValueError(f"Algorithm {algorithm} incompatible with key type {jwk_key_type}")

    def _get_jwk_key_type(self) -> str:
        """Determine JWK key type from key object."""
        if isinstance(self.key, bytes):
            return "oct"
        elif isinstance(self.key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
            return "EC"
        elif isinstance(self.key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
            return "RSA"
        elif isinstance(
            self.key,
            (
                ed25519.Ed25519PublicKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PublicKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            return "OKP"
        else:
            raise TypeError(f"Unsupported key type: {type(self.key)}")

    def _ensure_private_key(self) -> None:
        """Raise ValueError if this instance's key is public-only."""
        if self._external_signer is not None:
            # An external signer (e.g. a HashiCorp Vault Transit key)
            # performs the actual signing operation remotely; `self.key`
            # is intentionally the public key only.
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

    def _build_signer_core(self, extensions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Build a signaturecore object (algorithm/keyId/publicKey/
        certificatePath/extensions) without a value.

        If both ``certificate_path`` and ``include_public_key`` are set on this
        instance, ``certificate_path`` takes precedence: "certificatePath" is
        embedded and ``include_public_key`` is silently ignored.
        """
        sig_obj: Dict[str, Any] = {"algorithm": self.algorithm}

        if self.jwk.kid:
            sig_obj["keyId"] = self.jwk.kid
        if self.certificate_path:
            sig_obj["certificatePath"] = CertificateHandler.encode_certificate_path(
                self.certificate_path
            )
        elif self.include_public_key and not isinstance(self.jwk, joserfc.jwk.OctKey):
            sig_obj["publicKey"] = self.jwk.as_dict(private=False)
            if "kid" in sig_obj["publicKey"]:
                del sig_obj["publicKey"]["kid"]
        if extensions:
            JSFSignature._validate_extensions(extensions)
            sig_obj["extensions"] = list(extensions.keys())
            sig_obj.update(extensions)

        return sig_obj

    @staticmethod
    def _validate_extensions(extensions: Dict[str, Any]) -> None:
        """
        Validate an ``extensions`` mapping passed to sign()/sign_multi()/
        sign_chain(): must be a dict whose keys don't clash with the JSF
        reserved property names.

        Raises:
            ValueError: If ``extensions`` is not a dict, or any key is a
                reserved JSF property name
        """
        if not isinstance(extensions, dict):
            raise ValueError("extensions must be a dict mapping property name to value")

        reserved = [name for name in extensions if name in JSFSignature._RESERVED_PROPERTY_NAMES]
        if reserved:
            raise ValueError(f"Extension property names must not be JSF reserved words: {reserved}")

    def sign(
        self,
        obj: Dict[str, Any],
        excludes: Optional[list] = None,
        extensions: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Sign a JSON object.

        Args:
            obj: Object to sign
            excludes: Optional list of top-level property names to exclude
                from the signature process. Per the JSF spec, both these
                properties AND the "excludes" property itself are unsigned;
                verify() requires an explicit ``allowed_excludes`` allow-list
                to accept them.
            extensions: Optional dict mapping application-specific extension
                property names to their values. Unlike ``excludes``, these
                properties (and the "extensions" list naming them) are
                added directly to the signaturecore object and so are fully
                covered by the signature. Names must not clash with JSF
                reserved words (algorithm/certificatePath/chain/extensions/
                excludes/keyId/publicKey/signers/value).

        Returns:
            Signed object with signature property added

        Raises:
            ValueError: If key is not private, or ``extensions`` uses a
                reserved property name

        Example:
            >>> signed = signer.sign({"mySignedData": "x", "myUnsignedData": "y"},
            ...                       excludes=["myUnsignedData"])
            >>> signed = signer.sign({"data": "value"},
            ...                       extensions={"otherExt": "Cool Stuff"})
            >>> signer_with_cert = JSFSignature(private_key, "ES256",
            ...                                 certificate_path=[leaf_cert, root_cert])
            >>> signed = signer_with_cert.sign({"data": "value"})
        """
        self._ensure_private_key()

        signed_obj = dict(obj)

        sig_obj = self._build_signer_core(extensions=extensions)
        if excludes:
            sig_obj["excludes"] = list(excludes)

        # Build the data to sign: the excluded top-level properties and the
        # "excludes" property itself are unsigned per the JSF spec, so both
        # are omitted from the canonicalized data. Extension properties are
        # already part of sig_obj/core_for_signing and are therefore signed.
        temp_obj = dict(signed_obj)
        for name in excludes or []:
            temp_obj.pop(name, None)
        core_for_signing = dict(sig_obj)
        core_for_signing.pop("excludes", None)
        temp_obj[self.signature_property] = core_for_signing

        canonical = canonicalize(temp_obj)
        signature_value = self._compute_signature(canonical)

        sig_obj["value"] = signature_value
        signed_obj[self.signature_property] = sig_obj

        return signed_obj

    @staticmethod
    def _check_allowed_excludes(
        excludes: Optional[Any], allowed_excludes: Optional[List[str]], context: str = ""
    ) -> None:
        """
        Validate an entry's "excludes" property against a caller-supplied
        allow-list.

        Per the JSF spec, "excludes" (and the data it names) is unsigned:
        an attacker can add or modify it without invalidating the
        signature. A conforming implementation must therefore let the
        caller decide which excluded property names are acceptable rather
        than trusting the document blindly.

        Args:
            excludes: The entry's "excludes" value, if any (None if absent)
            allowed_excludes: Property names the caller permits being
                excluded. ``None`` means no exclusions are accepted at all.
            context: Optional human-readable suffix for error messages
                (e.g. " for signer 1")

        Raises:
            ValueError: If ``excludes`` is malformed, or names a property not
                present in ``allowed_excludes`` (including when
                ``allowed_excludes`` is None)
        """
        if excludes is None:
            return

        if not isinstance(excludes, list) or not all(isinstance(name, str) for name in excludes):
            raise ValueError(f"excludes{context} must be an array of property name strings")

        if allowed_excludes is None:
            raise ValueError(
                f"Signature{context} contains an unsigned 'excludes' property but no "
                "allowed_excludes was provided; pass allowed_excludes explicitly to accept it"
            )

        not_allowed = [name for name in excludes if name not in allowed_excludes]
        if not_allowed:
            raise ValueError(
                f"excludes{context} names properties not permitted by "
                f"allowed_excludes: {not_allowed}"
            )

    @staticmethod
    def _check_known_extensions(
        entry: Dict[str, Any], known_extensions: Optional[List[str]], context: str = ""
    ) -> None:
        """
        Validate an entry's "extensions" property.

        Unlike "excludes", extension properties are part of the
        signaturecore object and are therefore fully covered by the
        signature: accepting an unrecognized extension carries no integrity
        risk. Still, the JSF spec requires implementations to offer an
        option to only accept predefined extension property names (the
        "crit" pattern from JWS), so unknown extensions are rejected only
        when the caller opts in via ``known_extensions``.

        Args:
            entry: The signaturecore object (or entry) potentially holding
                an "extensions" property
            known_extensions: Extension property names the caller
                recognizes/accepts. ``None`` means any extension is accepted.
            context: Optional human-readable suffix for error messages
                (e.g. " for signer 1")

        Raises:
            ValueError: If "extensions" is malformed, names a property
                missing from ``entry``, or (when ``known_extensions`` is given)
                names a property not present in ``known_extensions``
        """
        extension_names = entry.get("extensions")
        if extension_names is None:
            return

        if not isinstance(extension_names, list) or not all(
            isinstance(name, str) for name in extension_names
        ):
            raise ValueError(f"extensions{context} must be an array of property name strings")

        missing = [name for name in extension_names if name not in entry]
        if missing:
            raise ValueError(
                f"extensions{context} names properties missing from the signature object: {missing}"
            )

        if known_extensions is not None:
            unknown = [name for name in extension_names if name not in known_extensions]
            if unknown:
                raise ValueError(
                    f"extensions{context} contains properties not permitted by "
                    f"known_extensions: {unknown}"
                )

    @staticmethod
    def _existing_entries(
        obj: Dict[str, Any], signature_property: str, array_key: str, method_name: str
    ) -> list:
        """
        If ``obj`` already carries a ``signature_property``, verify it holds an
        appendable structure (a dict with an ``array_key`` list, e.g.
        "signers" for sign_multi()/"chain" for sign_chain()) and return its
        existing entries so a new call can append to them. Returns an empty
        list if ``signature_property`` is absent.

        Raises:
            ValueError: If ``signature_property`` is present but is not an
                appendable structure of the expected kind (e.g. a plain
                sign() signature, or the other construct's array key)
        """
        if signature_property not in obj:
            return []

        holder = obj[signature_property]
        other_key = "chain" if array_key == "signers" else "signers"
        if (
            isinstance(holder, dict)
            and isinstance(holder.get(array_key), list)
            and other_key not in holder
        ):
            return list(holder[array_key])

        raise ValueError(
            f"Object already contains a '{signature_property}' property that is not "
            f"an appendable {'multi-signature' if array_key == 'signers' else 'signature-chain'} "
            f"object; {method_name}() cannot append to it"
        )

    @staticmethod
    def sign_multi(
        obj: Dict[str, Any],
        signers: List["JSFSignature"],
        excludes: Optional[list] = None,
        extensions: Optional[Dict[str, Any]] = None,
        signature_property: str = "signature",
    ) -> Dict[str, Any]:
        """
        Sign a JSON object with multiple independent signatures, per the JSF
        "Multiple Signatures" construct (spec section 8).

        Each signer adds its own signature to a shared "signers" array under
        ``signature_property``, computed *independently* of the other signers:
        for each signer, the canonicalization is performed as though the
        "signers" array contained only that signer's own (value-less) entry.

        If ``obj`` already holds a multi-signature under ``signature_property``
        (e.g. from a prior sign_multi() call), the new signers are appended
        to the existing "signers" array instead of replacing it.

        Args:
            obj: Object to sign
            signers: List of pre-configured JSFSignature instances, one per
                signature to add. Each instance's own ``signature_property`` is
                ignored; the shared ``signature_property`` argument below is
                used for the top level property instead. Each instance's
                own ``include_public_key``/``certificate_path`` settings are
                honored per-signer.
            excludes: Optional list of top-level property names to exclude
                from the signature process (recorded identically on every
                new signer entry). Per the JSF spec, both these properties
                AND the "excludes" property itself are unsigned;
                verify_multi() requires an explicit ``allowed_excludes``
                allow-list to accept them.
            extensions: Optional dict mapping application-specific extension
                property names to their values, applied identically to
                every new signer entry. Unlike ``excludes``, these properties
                are added directly to each signaturecore object and are
                therefore fully covered by that signer's signature. Names
                must not clash with JSF reserved words.
            signature_property: Name of the shared signature property in
                JSON (default: 'signature')

        Returns:
            Signed object with a "signers" array (existing entries, if any,
            plus the newly added ones) under ``signature_property``

        Raises:
            ValueError: If ``signers`` is empty, any signer holds a
                public-only key, ``extensions`` uses a reserved property
                name, or ``obj`` already contains a ``signature_property`` that
                is not an appendable multi-signature object

        Example:
            >>> ec_signer = JSFSignature(ec_key, "ES256", include_public_key=True)
            >>> rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
            >>> signed = JSFSignature.sign_multi({"data": "test"}, [ec_signer, rsa_signer])
            >>> keys = JSFSignature.get_public_keys(signed)
            >>> JSFSignature.verify_multi(signed, keys=keys)
            True
        """
        if not signers:
            raise ValueError("signers must contain at least one JSFSignature")

        existing_signers = JSFSignature._existing_entries(
            obj, signature_property, "signers", "sign_multi"
        )

        for signer in signers:
            signer._ensure_private_key()

        signed_obj = dict(obj)
        cores = [signer._build_signer_core(extensions=extensions) for signer in signers]

        for signer, core in zip(signers, cores):
            if excludes:
                core["excludes"] = list(excludes)

            # Per the JSF Multiple Signatures algorithm, each signature is
            # computed against the object with only its OWN signer entry
            # present in the "signers" array; the others (including any
            # pre-existing entries being appended to) are excluded, and the
            # separating ',' characters excluded. The excluded top-level
            # properties and the "excludes" property itself are unsigned,
            # so both are omitted from the canonicalized data. Extension
            # properties remain part of the core and are therefore signed.
            temp_obj = dict(signed_obj)
            for name in excludes or []:
                temp_obj.pop(name, None)
            core_for_signing = dict(core)
            core_for_signing.pop("excludes", None)
            temp_obj[signature_property] = {"signers": [core_for_signing]}
            canonical = canonicalize(temp_obj)
            core["value"] = signer._compute_signature(canonical)

        signed_obj[signature_property] = {"signers": existing_signers + cores}
        return signed_obj

    @staticmethod
    def _extract_certificate_key(entry: Dict[str, Any], index: int) -> Optional[Any]:
        """Resolve a verification key from an entry's "certificatePath", if present."""
        if "certificatePath" not in entry:
            return None

        certs = CertificateHandler.parse_certificate_path(entry["certificatePath"])
        if not certs:
            raise ValueError(f"Empty certificatePath for signer {index}")
        return certs[0].public_key()

    @staticmethod
    def _extract_embedded_public_key(entry: Dict[str, Any], index: int) -> Optional[Any]:
        """Resolve a verification key from an entry's "publicKey", if present."""
        if "publicKey" not in entry:
            return None

        public_key_jwk = entry["publicKey"]
        if isinstance(public_key_jwk, dict) and public_key_jwk.get("kty") == "oct":
            raise ValueError(
                f"Embedded publicKey for signer {index} has kty 'oct': symmetric "
                "keys are secrets and must never be embedded as a publicKey"
            )
        try:
            jwk = joserfc.jwk.import_key(public_key_jwk)
        except Exception as e:
            raise ValueError(f"Invalid embedded publicKey for signer {index}: {e}") from e
        return jwk.raw_value

    @staticmethod
    def _resolve_verification_key(
        entry: Dict[str, Any], keys: Optional[Union[list, Dict[str, Any]]], index: int
    ) -> Any:
        """
        Resolve the verification key for one signer entry of a
        verify_multi()/verify_chain() call: a matching key must be supplied
        explicitly via ``keys`` (use get_public_keys() to extract keys
        embedded via "publicKey"/"certificatePath" instead).
        """
        key_id = entry.get("keyId")
        if isinstance(keys, dict):
            if key_id is None or key_id not in keys:
                raise ValueError(f"No key provided for signer {index} (keyId={key_id!r})")
            return keys[key_id]

        if isinstance(keys, list):
            if index >= len(keys):
                raise ValueError(f"No key provided for signer {index}")
            return keys[index]

        raise ValueError(f"Cannot resolve verification key for signer {index}: no key supplied")

    @staticmethod
    def verify_multi(
        obj: Dict[str, Any],
        keys: Optional[Union[list, Dict[str, Any]]] = None,
        signature_property: str = "signature",
        allowed_excludes: Optional[List[str]] = None,
        known_extensions: Optional[List[str]] = None,
    ) -> bool:
        """
        Verify all signatures in a JSF "Multiple Signatures" object.

        Args:
            obj: Signed object containing a ``signature_property`` holding a
                "signers" array (see sign_multi())
            keys: Keys to use for verification, needed for every signer
                entry. Use get_public_keys() first if you need to resolve
                keys embedded via "publicKey"/"certificatePath" instead. May
                be a list of keys aligned positionally with the "signers"
                array, or a dict mapping "keyId" -> key.
            signature_property: Name of the shared signature property in
                JSON (default: 'signature')
            allowed_excludes: Property names permitted to appear in a
                signer's "excludes" list. Since "excludes" (and the data it
                names) is unsigned, any signer entry carrying an "excludes"
                property is rejected unless every name it lists is present
                here.
            known_extensions: Extension property names recognized/accepted
                by the caller, checked per signer entry. ``None`` (default)
                accepts any extensions, since they are part of each
                signaturecore object and so are fully covered by that
                signer's signature.

        Returns:
            True only if ``signature_property`` holds a non-empty "signers"
            array and every signer's signature verifies successfully

        Raises:
            ValueError: If the signature property is missing/malformed, a
                signer's verification key cannot be resolved, a signer's
                "excludes" property is not permitted by ``allowed_excludes``,
                or a signer's "extensions" property is malformed or (when
                ``known_extensions`` is given) names a property not in it

        Example:
            >>> keys = JSFSignature.get_public_keys(signed)
            >>> JSFSignature.verify_multi(signed, keys=keys)
            True
            >>> JSFSignature.verify_multi(signed, keys={"my-key-id": public_key})
            True
        """
        if signature_property not in obj:
            raise ValueError(f"Missing signature property: {signature_property}")

        sig_holder = obj[signature_property]
        if not isinstance(sig_holder, dict) or "signers" not in sig_holder:
            raise ValueError("Signature property is not a multisignature object")

        signer_entries = sig_holder["signers"]
        if not isinstance(signer_entries, list) or not signer_entries:
            raise ValueError("signers must be a non-empty array")

        for index, entry in enumerate(signer_entries):
            if not isinstance(entry, dict) or "value" not in entry or "algorithm" not in entry:
                raise ValueError(f"Malformed signer entry at index {index}")

            algorithm = entry["algorithm"]
            signature_value = entry["value"]

            verification_key = JSFSignature._resolve_verification_key(entry, keys, index)
            verifier = JSFSignature(verification_key, algorithm)

            entry_excludes = entry.get("excludes")
            JSFSignature._check_allowed_excludes(
                entry_excludes, allowed_excludes, context=f" for signer {index}"
            )
            JSFSignature._check_known_extensions(
                entry, known_extensions, context=f" for signer {index}"
            )

            # Rebuild the per-signer canonical form: only this signer's
            # entry (without its "value" and unsigned "excludes") present
            # in the "signers" array, and with any of its excluded
            # top-level properties removed.
            core = dict(entry)
            del core["value"]
            core.pop("excludes", None)
            temp_obj = dict(obj)
            for name in entry_excludes or []:
                temp_obj.pop(name, None)
            temp_obj[signature_property] = {"signers": [core]}
            canonical = canonicalize(temp_obj)

            if not verifier._verify_signature(canonical, signature_value):
                return False

        return True

    @staticmethod
    def sign_chain(
        obj: Dict[str, Any],
        signers: List["JSFSignature"],
        excludes: Optional[list] = None,
        extensions: Optional[Dict[str, Any]] = None,
        signature_property: str = "signature",
    ) -> Dict[str, Any]:
        """
        Sign a JSON object with a signature chain, per the JSF "Signature
        Chains" construct (spec section 9).

        Unlike sign_multi(), each signature in the chain signs the data
        *and* every preceding (already finalized) signature entry: for
        signer i, the canonicalization is performed with the "chain" array
        containing the finalized entries 0..i-1 (with their "value")
        followed by signer i's own value-less entry.

        If ``obj`` already holds a signature chain under ``signature_property``
        (e.g. from a prior sign_chain() call), the new signers extend the
        existing chain: each new entry covers all previously finalized
        entries too, exactly as if the whole chain had been signed in one
        call.

        Args:
            obj: Object to sign
            signers: Ordered list of pre-configured JSFSignature instances,
                one per signature to add, from first to last in the chain.
                Each instance's own ``signature_property`` is ignored; the
                shared ``signature_property`` argument below is used for the
                top level property instead. Each instance's own
                ``include_public_key``/``certificate_path`` settings are
                honored per-signer.
            excludes: Optional list of top-level property names to exclude
                from the signature process (recorded identically on every
                new chain entry). Per the JSF spec, both these properties
                AND the "excludes" property itself are unsigned;
                verify_chain() requires an explicit ``allowed_excludes``
                allow-list to accept them.
            extensions: Optional dict mapping application-specific extension
                property names to their values, applied identically to
                every new chain entry. Unlike ``excludes``, these properties
                are added directly to each signaturecore object and are
                therefore fully covered by that entry's signature (and all
                subsequent entries in the chain). Names must not clash with
                JSF reserved words.
            signature_property: Name of the shared signature property in
                JSON (default: 'signature')

        Returns:
            Signed object with a "chain" array (existing entries, if any,
            plus the newly added ones) under ``signature_property``

        Raises:
            ValueError: If ``signers`` is empty, any signer holds a
                public-only key, ``extensions`` uses a reserved property
                name, or ``obj`` already contains a ``signature_property`` that
                is not an appendable signature chain object

        Example:
            >>> ec_signer = JSFSignature(ec_key, "ES256", include_public_key=True)
            >>> rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
            >>> signed = JSFSignature.sign_chain({"data": "test"}, [ec_signer, rsa_signer])
            >>> keys = JSFSignature.get_public_keys(signed)
            >>> JSFSignature.verify_chain(signed, keys=keys)
            True
        """
        if not signers:
            raise ValueError("signers must contain at least one JSFSignature")

        existing_chain = JSFSignature._existing_entries(
            obj, signature_property, "chain", "sign_chain"
        )

        for signer in signers:
            signer._ensure_private_key()

        signed_obj = dict(obj)
        chain: List[Dict[str, Any]] = list(existing_chain)

        for signer in signers:
            core = signer._build_signer_core(extensions=extensions)
            if excludes:
                core["excludes"] = list(excludes)

            # Per the JSF Signature Chains algorithm, each signature covers
            # the data plus every *preceding* (already finalized) chain
            # entry; only array-wise higher order entries are omitted. The
            # excluded top-level properties and the "excludes" property
            # itself are unsigned, so both are omitted from the
            # canonicalized data for this entry. Extension properties
            # remain part of the core and are therefore signed.
            temp_obj = dict(signed_obj)
            for name in excludes or []:
                temp_obj.pop(name, None)
            core_for_signing = dict(core)
            core_for_signing.pop("excludes", None)
            temp_obj[signature_property] = {"chain": chain + [core_for_signing]}
            canonical = canonicalize(temp_obj)
            core["value"] = signer._compute_signature(canonical)

            chain.append(core)

        signed_obj[signature_property] = {"chain": chain}
        return signed_obj

    @staticmethod
    def verify_chain(
        obj: Dict[str, Any],
        keys: Optional[Union[list, Dict[str, Any]]] = None,
        signature_property: str = "signature",
        allowed_excludes: Optional[List[str]] = None,
        known_extensions: Optional[List[str]] = None,
    ) -> bool:
        """
        Verify a JSF "Signature Chains" object.

        Args:
            obj: Signed object containing a ``signature_property`` holding a
                "chain" array (see sign_chain())
            keys: Keys to use for verification, needed for every chain
                entry. Use get_public_keys() first if you need to resolve
                keys embedded via "publicKey"/"certificatePath" instead. May
                be a list of keys aligned positionally with the "chain"
                array, or a dict mapping "keyId" -> key.
            signature_property: Name of the shared signature property in
                JSON (default: 'signature')
            allowed_excludes: Property names permitted to appear in a chain
                entry's "excludes" list. Since "excludes" (and the data it
                names) is unsigned, any entry carrying an "excludes"
                property is rejected unless every name it lists is present
                here.
            known_extensions: Extension property names recognized/accepted
                by the caller, checked per chain entry. ``None`` (default)
                accepts any extensions, since they are part of each
                signaturecore object and so are fully covered by that
                entry's signature.

        Returns:
            True only if ``signature_property`` holds a non-empty "chain"
            array and every entry's signature verifies successfully

        Raises:
            ValueError: If the signature property is missing/malformed, an
                entry's verification key cannot be resolved, an entry's
                "excludes" property is not permitted by ``allowed_excludes``,
                or an entry's "extensions" property is malformed or (when
                ``known_extensions`` is given) names a property not in it

        Example:
            >>> keys = JSFSignature.get_public_keys(signed)
            >>> JSFSignature.verify_chain(signed, keys=keys)
            True
        """
        if signature_property not in obj:
            raise ValueError(f"Missing signature property: {signature_property}")

        sig_holder = obj[signature_property]
        if not isinstance(sig_holder, dict) or "chain" not in sig_holder:
            raise ValueError("Signature property is not a signaturechain object")

        chain_entries = sig_holder["chain"]
        if not isinstance(chain_entries, list) or not chain_entries:
            raise ValueError("chain must be a non-empty array")

        verified_prefix: List[Dict[str, Any]] = []

        for index, entry in enumerate(chain_entries):
            if not isinstance(entry, dict) or "value" not in entry or "algorithm" not in entry:
                raise ValueError(f"Malformed chain entry at index {index}")

            algorithm = entry["algorithm"]
            signature_value = entry["value"]

            verification_key = JSFSignature._resolve_verification_key(entry, keys, index)
            verifier = JSFSignature(verification_key, algorithm)

            entry_excludes = entry.get("excludes")
            JSFSignature._check_allowed_excludes(
                entry_excludes, allowed_excludes, context=f" for chain entry {index}"
            )
            JSFSignature._check_known_extensions(
                entry, known_extensions, context=f" for chain entry {index}"
            )

            # Rebuild the per-entry canonical form: the finalized (with
            # "value") preceding entries followed by this entry without
            # its own "value" or unsigned "excludes", and with any of its
            # excluded top-level properties removed.
            core = dict(entry)
            del core["value"]
            core.pop("excludes", None)
            temp_obj = dict(obj)
            for name in entry_excludes or []:
                temp_obj.pop(name, None)
            temp_obj[signature_property] = {"chain": verified_prefix + [core]}
            canonical = canonicalize(temp_obj)

            if not verifier._verify_signature(canonical, signature_value):
                return False

            verified_prefix.append(entry)

        return True

    @staticmethod
    def get_public_key(obj: Dict[str, Any], signature_property: str = "signature") -> Optional[Any]:
        """
        Extract the public key embedded in a signed object's signature property.

        Args:
            obj: Signed JSON object
            signature_property: Name of signature property in JSON (default: 'signature')

        Returns:
            Cryptographic public key object if a publicKey is embedded in the
            signature, None if no publicKey is present

        Raises:
            ValueError: If the signature property is missing, malformed, or the
                embedded publicKey cannot be parsed

        Example:
            >>> public_key = JSFSignature.get_public_key(signed_obj)
            >>> if public_key is not None:
            ...     JSFSignature(public_key, "ES256").verify(signed_obj)
        """
        return JSFSignature.get_public_keys(
            obj, signature_property=signature_property, allow_none=True
        )[0]

    @staticmethod
    def get_public_keys(
        obj: Dict[str, Any], signature_property: str = "signature", allow_none: bool = False
    ) -> List[Any]:
        """
        Extract every embedded public key from a signed object's
        ``signature_property`` and return the raw public key objects,
        suitable for passing directly to verify_multi()/verify_chain()
        (via ``keys=``) without the caller needing to already possess/parse
        the keys.

        Works with a plain sign() signature (returns a single-element
        list), a sign_multi() "signers" array, or a sign_chain() "chain"
        array (one key per entry, in order).

        Args:
            obj: Signed JSON object
            signature_property: Name of signature property in JSON
                (default: 'signature')

        Returns:
            List of raw public key objects, one per signature entry found

        Raises:
            ValueError: If the signature property is missing/malformed, or
                any entry lacks an embedded "publicKey"/"certificatePath"
                (or embeds an unusable/symmetric 'oct' key)

        Example:
            >>> keys = JSFSignature.get_public_keys(signed_obj)
            >>> JSFSignature.verify_multi(signed_obj, keys=keys)
            True
        """
        entries = JSFSignature._resolve_entries(obj, signature_property)

        keys = []
        for index, entry in enumerate(entries):
            key = JSFSignature._extract_certificate_key(entry, index)
            if key is None:
                key = JSFSignature._extract_embedded_public_key(entry, index)
            if key is None and not allow_none:
                raise ValueError(
                    f"No embedded publicKey/certificatePath found for signature entry {index}"
                )
            keys.append(key)

        return keys

    @staticmethod
    def _resolve_entries(obj: Dict[str, Any], signature_property: str) -> List[Dict[str, Any]]:
        """Return the signature entries (single/signers/chain) for ``signature_property``."""
        if signature_property not in obj:
            raise ValueError(f"Missing signature property: {signature_property}")

        sig_holder = obj[signature_property]
        if not isinstance(sig_holder, dict):
            raise ValueError("Signature property must be an object")

        if "signers" in sig_holder:
            entries = sig_holder["signers"]
        elif "chain" in sig_holder:
            entries = sig_holder["chain"]
        else:
            entries = [sig_holder]

        if not isinstance(entries, list) or not entries:
            raise ValueError("Signature property has no signature entries")

        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or "algorithm" not in entry:
                raise ValueError(f"Malformed signature entry at index {index}")

        return entries

    @staticmethod
    def get_certificate_chain(
        obj: Dict[str, Any], signature_property: str = "signature"
    ) -> Optional[List[x509.Certificate]]:
        """
        Extract the certificate chain embedded in a signed object's first
        signature entry, for the caller to validate independently (chain
        of trust, expiry, revocation, etc. are not checked by this
        library).

        Args:
            obj: Signed JSON object
            signature_property: Name of signature property in JSON (default: 'signature')

        Returns:
            Leaf-to-root list of ``x509.Certificate``, or None if the entry
            has no "certificatePath"

        Raises:
            ValueError: If the signature property is missing or malformed

        Example:
            >>> chain = JSFSignature.get_certificate_chain(signed_obj)
            >>> if chain is not None:
            ...     leaf_cert = chain[0]
        """
        return JSFSignature.get_certificate_chains(obj, signature_property=signature_property)[0]

    @staticmethod
    def get_certificate_chains(
        obj: Dict[str, Any], signature_property: str = "signature"
    ) -> List[Optional[List[x509.Certificate]]]:
        """
        Extract every embedded certificate chain from a signed object's
        ``signature_property``, one entry per signature (single/``signers``/
        ``chain``, in order), for the caller to validate independently
        (chain of trust, expiry, revocation, etc. are not checked by this
        library).

        Args:
            obj: Signed JSON object
            signature_property: Name of signature property in JSON (default: 'signature')

        Returns:
            List with one item per signature entry: a leaf-to-root list of
            ``x509.Certificate`` if the entry has a "certificatePath", else
            None for that position

        Raises:
            ValueError: If the signature property is missing or malformed

        Example:
            >>> chains = JSFSignature.get_certificate_chains(signed_obj)
        """
        entries = JSFSignature._resolve_entries(obj, signature_property)

        chains: List[Optional[List[x509.Certificate]]] = []
        for entry in entries:
            if "certificatePath" in entry:
                chains.append(CertificateHandler.parse_certificate_path(entry["certificatePath"]))
            else:
                chains.append(None)

        return chains

    def verify(
        self,
        obj: Dict[str, Any],
        allowed_excludes: Optional[List[str]] = None,
        known_extensions: Optional[List[str]] = None,
    ) -> bool:
        """
        Verify a signed JSON object.

        Args:
            obj: Signed object to verify
            allowed_excludes: Property names permitted to appear in the
                signature's "excludes" list. Since "excludes" (and the data
                it names) is unsigned, a signature carrying an "excludes"
                property is rejected unless every name it lists is present
                here.
            known_extensions: Extension property names recognized/accepted
                by the caller. ``None`` (default) accepts any extensions,
                since they are part of the signaturecore object and so are
                fully covered by the signature. Pass a list to reject any
                signature carrying an extension property name outside it.

        Returns:
            True if signature is valid

        Raises:
            ValueError: If signature is invalid or missing, the "excludes"
                property is not permitted by ``allowed_excludes``, or the
                "extensions" property is malformed or (when
                ``known_extensions`` is given) names a property not in it

        Example:
            >>> verifier.verify(signed_obj)
            True
            >>> verifier.verify(signed_obj, allowed_excludes=["myUnsignedData"])
            True
            >>> verifier.verify(signed_obj, known_extensions=["otherExt"])
            True
        """
        if self.signature_property not in obj:
            raise ValueError(f"Missing signature property: {self.signature_property}")

        sig_obj = obj[self.signature_property]
        if not isinstance(sig_obj, dict):
            raise ValueError("Signature property must be an object")

        if "value" not in sig_obj:
            raise ValueError("Signature missing value")

        signature_value = sig_obj["value"]
        algorithm = sig_obj.get("algorithm")

        if not algorithm:
            raise ValueError("Signature missing algorithm")

        if algorithm != self.algorithm:
            raise ValueError(f"Algorithm mismatch: {algorithm} != {self.algorithm}")

        excludes = sig_obj.get("excludes")
        JSFSignature._check_allowed_excludes(excludes, allowed_excludes)
        JSFSignature._check_known_extensions(sig_obj, known_extensions)

        # Rebuild the object for verification: drop the signature value and
        # the unsigned "excludes" property, and remove its excluded
        # top-level properties (both are unsigned per the JSF spec).
        verify_obj = dict(obj)
        temp_sig = dict(sig_obj)
        del temp_sig["value"]
        temp_sig.pop("excludes", None)
        for name in excludes or []:
            verify_obj.pop(name, None)
        verify_obj[self.signature_property] = temp_sig

        canonical = canonicalize(verify_obj)
        return self._verify_signature(canonical, signature_value)

    def _compute_signature(self, data: bytes) -> str:
        """Compute signature value for given data."""
        if self._external_signer is not None:
            return base64url_encode(self._external_signer.sign(self.algorithm, data))

        alg_type = AlgorithmRegistry.get_algorithm_type(self.algorithm)

        if alg_type == AlgorithmType.ECDSA:
            return self._sign_ecdsa(data)
        elif alg_type == AlgorithmType.RSA_PKCS1:
            return self._sign_rsa_pkcs1(data)
        elif alg_type == AlgorithmType.RSA_PSS:
            return self._sign_rsa_pss(data)
        elif alg_type == AlgorithmType.HMAC:
            return self._sign_hmac(data)
        elif alg_type == AlgorithmType.EDDSA:
            return self._sign_eddsa(data)
        else:
            raise ValueError(f"Unknown algorithm type: {alg_type}")

    def _verify_signature(self, data: bytes, signature_value: str) -> bool:
        """Verify signature value for given data."""
        alg_type = AlgorithmRegistry.get_algorithm_type(self.algorithm)

        try:
            if alg_type == AlgorithmType.ECDSA:
                return self._verify_ecdsa(data, signature_value)
            elif alg_type == AlgorithmType.RSA_PKCS1:
                return self._verify_rsa_pkcs1(data, signature_value)
            elif alg_type == AlgorithmType.RSA_PSS:
                return self._verify_rsa_pss(data, signature_value)
            elif alg_type == AlgorithmType.HMAC:
                return self._verify_hmac(data, signature_value)
            elif alg_type == AlgorithmType.EDDSA:
                return self._verify_eddsa(data, signature_value)
            else:
                return False
        except Exception:
            return False

    # ECDSA implementation
    def _sign_ecdsa(self, data: bytes) -> str:
        """Sign data with ECDSA."""
        hash_alg = self._get_hash_algorithm()
        key = cast(ec.EllipticCurvePrivateKey, self.key)
        signature = key.sign(data, ec.ECDSA(hash_alg))

        # Convert DER signature to raw format (concatenated r and s)
        r, s = decode_dss_signature(signature)
        curve_order = (key.curve.key_size + 7) // 8

        r_bytes = r.to_bytes(curve_order, "big")
        s_bytes = s.to_bytes(curve_order, "big")

        return base64url_encode(r_bytes + s_bytes)

    def _verify_ecdsa(self, data: bytes, signature_value: str) -> bool:
        """Verify ECDSA signature."""
        hash_alg = self._get_hash_algorithm()

        try:
            sig_bytes = base64url_decode(signature_value)

            # Get the public key for verification
            public_key: ec.EllipticCurvePublicKey
            if isinstance(self.key, ec.EllipticCurvePrivateKey):
                public_key = self.key.public_key()
            else:
                public_key = cast(ec.EllipticCurvePublicKey, self.key)
            curve_order = (public_key.curve.key_size + 7) // 8

            if len(sig_bytes) != 2 * curve_order:
                return False

            r = int.from_bytes(sig_bytes[:curve_order], "big")
            s = int.from_bytes(sig_bytes[curve_order:], "big")

            der_sig = encode_dss_signature(r, s)

            public_key.verify(der_sig, data, ec.ECDSA(hash_alg))
            return True
        except Exception:
            return False

    # RSA PKCS#1 v1.5 implementation
    def _sign_rsa_pkcs1(self, data: bytes) -> str:
        """Sign data with RSA PKCS#1 v1.5."""
        hash_alg = self._get_hash_algorithm()
        key = cast(rsa.RSAPrivateKey, self.key)
        signature = key.sign(data, padding.PKCS1v15(), hash_alg)
        return base64url_encode(signature)

    def _verify_rsa_pkcs1(self, data: bytes, signature_value: str) -> bool:
        """Verify RSA PKCS#1 v1.5 signature."""
        hash_alg = self._get_hash_algorithm()

        try:
            sig_bytes = base64url_decode(signature_value)

            # Get the public key for verification
            public_key: rsa.RSAPublicKey
            if isinstance(self.key, rsa.RSAPrivateKey):
                public_key = self.key.public_key()
            else:
                public_key = cast(rsa.RSAPublicKey, self.key)

            public_key.verify(sig_bytes, data, padding.PKCS1v15(), hash_alg)
            return True
        except Exception:
            return False

    # RSA PSS implementation
    def _sign_rsa_pss(self, data: bytes) -> str:
        """Sign data with RSA PSS."""
        hash_alg = self._get_hash_algorithm()
        pss_padding = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH)
        key = cast(rsa.RSAPrivateKey, self.key)
        signature = key.sign(data, pss_padding, hash_alg)
        return base64url_encode(signature)

    def _verify_rsa_pss(self, data: bytes, signature_value: str) -> bool:
        """Verify RSA PSS signature."""
        hash_alg = self._get_hash_algorithm()

        try:
            sig_bytes = base64url_decode(signature_value)

            # Get the public key for verification
            public_key: rsa.RSAPublicKey
            if isinstance(self.key, rsa.RSAPrivateKey):
                public_key = self.key.public_key()
            else:
                public_key = cast(rsa.RSAPublicKey, self.key)

            pss_padding = padding.PSS(
                mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH
            )
            public_key.verify(sig_bytes, data, pss_padding, hash_alg)
            return True
        except Exception:
            return False

    # HMAC implementation
    def _sign_hmac(self, data: bytes) -> str:
        """Sign data with HMAC."""
        hash_name = AlgorithmRegistry.get_hash_algorithm(self.algorithm)
        if hash_name is None:
            raise RuntimeError(f"No hash algorithm registered for {self.algorithm}")
        hash_func = getattr(hashlib, hash_name.lower())

        key = cast(bytes, self.key)
        signature = hmac.new(key, data, hash_func).digest()
        return base64url_encode(signature)

    def _verify_hmac(self, data: bytes, signature_value: str) -> bool:
        """Verify HMAC signature."""
        hash_name = AlgorithmRegistry.get_hash_algorithm(self.algorithm)
        if hash_name is None:
            raise RuntimeError(f"No hash algorithm registered for {self.algorithm}")
        hash_func = getattr(hashlib, hash_name.lower())

        try:
            key = cast(bytes, self.key)
            expected = hmac.new(key, data, hash_func).digest()
            provided = base64url_decode(signature_value)
            return hmac.compare_digest(expected, provided)
        except Exception:
            return False

    # EdDSA implementation
    def _sign_eddsa(self, data: bytes) -> str:
        """Sign data with EdDSA."""
        key = cast(Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey], self.key)
        signature = key.sign(data)
        return base64url_encode(signature)

    def _verify_eddsa(self, data: bytes, signature_value: str) -> bool:
        """Verify EdDSA signature."""
        try:
            sig_bytes = base64url_decode(signature_value)

            # Get the public key for verification
            public_key: Union[ed25519.Ed25519PublicKey, ed448.Ed448PublicKey]
            if isinstance(self.key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
                public_key = self.key.public_key()
            else:
                public_key = cast(Union[ed25519.Ed25519PublicKey, ed448.Ed448PublicKey], self.key)

            public_key.verify(sig_bytes, data)
            return True
        except Exception:
            return False

    def _get_hash_algorithm(self) -> hashes.HashAlgorithm:
        """Get cryptography hash algorithm from JSF algorithm."""
        hash_name = AlgorithmRegistry.get_hash_algorithm(self.algorithm)

        hash_map = {
            "SHA256": hashes.SHA256(),
            "SHA384": hashes.SHA384(),
            "SHA512": hashes.SHA512(),
        }

        if hash_name not in hash_map:
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")

        return hash_map[hash_name]
