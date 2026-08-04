#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Comprehensive tests for JSF implementation.
Tests all algorithms: EC, RSA, HMAC, EdDSA.
"""

import pytest

from pyjsign.algorithm_registry import AlgorithmRegistry
from pyjsign.canonicalization import canonicalize
from pyjsign.jsf import JSFSignature
from pyjsign.jwk_handler import JWKHandler


class TestCanonicalization:
    """Test JSON canonicalization."""

    def test_simple_object(self):
        obj = {"name": "Joe", "id": 2200063}
        canonical = canonicalize(obj)
        assert canonical == b'{"id":2200063,"name":"Joe"}'

    def test_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        canonical = canonicalize(obj)
        assert canonical == b'{"a":2,"m":3,"z":1}'

    def test_nested_objects(self):
        obj = {"outer": {"inner": "value"}, "array": [1, 2, 3]}
        canonical = canonicalize(obj)
        expected = b'{"array":[1,2,3],"outer":{"inner":"value"}}'
        assert canonical == expected

    def test_no_whitespace(self):
        obj = {"a": {"b": {"c": [1, 2, 3]}}}
        canonical = canonicalize(obj)
        assert b" " not in canonical
        assert b"\n" not in canonical


class TestECSignature:
    """Test EC (ECDSA) signatures."""

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_es256_sign_verify(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"now": "2019-02-10T11:23:06Z", "name": "Joe", "id": 2200063}

        signed = signer.sign(obj)
        assert "signature" in signed
        assert "value" in signed["signature"]
        assert "algorithm" in signed["signature"]
        assert signed["signature"]["algorithm"] == "ES256"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed) is True

    def test_es256_tamper_detection(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = signer.sign(obj)

        # Tamper with data
        signed["data"] = "tampered"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed) is False

    def test_es384_sign_verify(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        signer = JSFSignature(private_key, "ES384")
        obj = {"test": "data"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "ES384"

        verifier = JSFSignature(private_key, "ES384")
        assert verifier.verify(signed) is True


class TestExcludes:
    """
    Test the "excludes" property (JSF spec Global Signature Options): a
    list of top-level property names excluded from the signature process.
    Per the spec, "excludes" (and the data it names) is itself unsigned, so
    verify() must reject it unless the caller opts in via allowed_excludes.
    """

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }
    EC_PUBLIC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
    }

    # Official JSF spec Appendix A test vector (p256#es256@excl-jwk.json).
    SPEC_SIGNED_OBJECT = {
        "mySignedData": "something",
        "myUnsignedData": "something else",
        "signature": {
            "algorithm": "ES256",
            "publicKey": EC_PUBLIC_JWK,
            "excludes": ["myUnsignedData"],
            "value": (
                "EWkjHQTGBptNmhCsRw2wHqX64XpWS_4n4ba3DJ8HisvWl4eZYHsx6QCe7NIrwYHJOB6Tr-"
                "yOqN3G7oH9zH27jQ"
            ),
        },
    }

    def test_spec_test_vector_verifies_with_allowed_excludes(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        assert verifier.verify(self.SPEC_SIGNED_OBJECT, allowed_excludes=["myUnsignedData"]) is True

    def test_verify_rejects_excludes_without_allow_list(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        with pytest.raises(ValueError, match="allowed_excludes"):
            verifier.verify(self.SPEC_SIGNED_OBJECT)

    def test_verify_rejects_excludes_name_not_in_allow_list(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        with pytest.raises(ValueError, match="not permitted by allowed_excludes"):
            verifier.verify(self.SPEC_SIGNED_OBJECT, allowed_excludes=["someOtherProperty"])

    def test_sign_verify_round_trip_with_excludes(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"mySignedData": "something", "myUnsignedData": "something else"}
        signed = signer.sign(obj, excludes=["myUnsignedData"])

        assert signed["signature"]["excludes"] == ["myUnsignedData"]

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed, allowed_excludes=["myUnsignedData"]) is True

    def test_excluded_property_can_change_without_invalidating_signature(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"mySignedData": "something", "myUnsignedData": "something else"}
        signed = signer.sign(obj, excludes=["myUnsignedData"])

        tampered = dict(signed)
        tampered["myUnsignedData"] = "a completely different value"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(tampered, allowed_excludes=["myUnsignedData"]) is True

    def test_signed_property_tampering_still_detected_with_excludes(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"mySignedData": "something", "myUnsignedData": "something else"}
        signed = signer.sign(obj, excludes=["myUnsignedData"])

        tampered = dict(signed)
        tampered["mySignedData"] = "tampered"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(tampered, allowed_excludes=["myUnsignedData"]) is False

    def test_excludes_list_itself_can_be_widened_but_is_rejected(self):
        # An attacker adds another (unsigned) property name to "excludes".
        # Since it's not in the caller's allow-list, verification must fail
        # closed rather than silently accepting a wider exclusion set.
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {
            "mySignedData": "something",
            "myUnsignedData": "something else",
            "otherData": "also signed",
        }
        signed = signer.sign(obj, excludes=["myUnsignedData"])

        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["excludes"] = ["myUnsignedData", "otherData"]

        verifier = JSFSignature(self.EC_JWK, "ES256")
        with pytest.raises(ValueError, match="not permitted by allowed_excludes"):
            verifier.verify(tampered, allowed_excludes=["myUnsignedData"])

    def test_verify_without_excludes_present_ignores_allowed_excludes(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"})

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed, allowed_excludes=["irrelevant"]) is True

    def test_excludes_must_be_list_of_strings(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"})
        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["excludes"] = "notAList"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        with pytest.raises(ValueError, match="must be an array of property name strings"):
            verifier.verify(tampered, allowed_excludes=["data"])


class TestExtensions:
    """
    Test the "extensions" property (JSF spec Global Signature Options):
    application-specific properties embedded directly inside the
    signaturecore object itself, and therefore fully covered by the
    signature (unlike "excludes", which are unsigned).
    """

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }
    EC_PUBLIC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
    }

    # Official JSF spec Appendix A test vector (p256#es256@exts-jwk.json).
    SPEC_SIGNED_OBJECT = {
        "now": "2019-02-10T11:23:06Z",
        "name": "Joe",
        "id": 2200063,
        "signature": {
            "algorithm": "ES256",
            "publicKey": EC_PUBLIC_JWK,
            "extensions": ["otherExt", "https://example.com/extension"],
            "otherExt": "Cool Stuff",
            "https://example.com/extension": {"life-is-great": True},
            "value": (
                "jFlU5VEGcq7ezESeKX_JR79rrppnE4uxmnPTLeYth6atfJker7oDon1R3yKLEeGS1"
                "vVntVpuGjxNSdLqIrLd0A"
            ),
        },
    }

    def test_spec_test_vector_verifies(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        assert verifier.verify(self.SPEC_SIGNED_OBJECT) is True

    def test_spec_test_vector_verifies_with_known_extensions(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        assert (
            verifier.verify(
                self.SPEC_SIGNED_OBJECT,
                known_extensions=["otherExt", "https://example.com/extension"],
            )
            is True
        )

    def test_sign_verify_round_trip_with_extensions(self):
        signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"now": "2019-02-10T11:23:06Z", "name": "Joe", "id": 2200063}
        signed = signer.sign(
            obj,
            extensions={
                "otherExt": "Cool Stuff",
                "https://example.com/extension": {"life-is-great": True},
            },
        )

        assert signed["signature"]["extensions"] == [
            "otherExt",
            "https://example.com/extension",
        ]
        assert signed["signature"]["otherExt"] == "Cool Stuff"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed) is True

    def test_extension_value_tampering_detected(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"}, extensions={"otherExt": "Cool Stuff"})

        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["otherExt"] = "Tampered"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(tampered) is False

    def test_sign_rejects_reserved_extension_name(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        with pytest.raises(ValueError, match="reserved words"):
            signer.sign({"data": "test"}, extensions={"algorithm": "evil"})

    def test_verify_rejects_extension_not_in_known_extensions(self):
        verifier = JSFSignature(self.EC_PUBLIC_JWK, "ES256")
        with pytest.raises(ValueError, match="not permitted by known_extensions"):
            verifier.verify(self.SPEC_SIGNED_OBJECT, known_extensions=["otherExt"])

    def test_verify_rejects_extensions_naming_missing_property(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"}, extensions={"otherExt": "Cool Stuff"})

        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["extensions"] = ["otherExt", "missingExt"]

        verifier = JSFSignature(self.EC_JWK, "ES256")
        with pytest.raises(ValueError, match="missing from the signature object"):
            verifier.verify(tampered)

    def test_extensions_must_be_list_of_strings(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"})
        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["extensions"] = "notAList"

        verifier = JSFSignature(self.EC_JWK, "ES256")
        with pytest.raises(ValueError, match="must be an array of property name strings"):
            verifier.verify(tampered)

    def test_verify_without_extensions_present_ignores_known_extensions(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        signed = signer.sign({"data": "test"})

        verifier = JSFSignature(self.EC_JWK, "ES256")
        assert verifier.verify(signed, known_extensions=["irrelevant"]) is True


class TestRSASignature:
    """Test RSA signatures."""

    def test_rs256_sign_verify(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        signer = JSFSignature(private_key, "RS256")
        obj = {"test": "rsa"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "RS256"

        verifier = JSFSignature(private_key, "RS256")
        assert verifier.verify(signed) is True

    def test_ps256_sign_verify(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        signer = JSFSignature(private_key, "PS256")
        obj = {"test": "pss"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "PS256"

        verifier = JSFSignature(private_key, "PS256")
        assert verifier.verify(signed) is True

    def test_rsa_public_key_only(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Sign with private
        signer = JSFSignature(private_key, "RS256")
        obj = {"test": "public"}
        signed = signer.sign(obj)

        # Verify with public
        verifier = JSFSignature(public_key, "RS256")
        assert verifier.verify(signed) is True


class TestHMACSignature:
    """Test HMAC signatures."""

    def test_hs256_sign_verify(self):
        import os

        # Generate symmetric key
        symmetric_key = os.urandom(32)  # 256-bit key

        signer = JSFSignature(symmetric_key, "HS256")
        obj = {"test": "hmac"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "HS256"

        verifier = JSFSignature(symmetric_key, "HS256")
        assert verifier.verify(signed) is True

    def test_hs384_sign_verify(self):
        import os

        symmetric_key = os.urandom(48)  # 384-bit key

        signer = JSFSignature(symmetric_key, "HS384")
        obj = {"data": "test"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "HS384"

        verifier = JSFSignature(symmetric_key, "HS384")
        assert verifier.verify(signed) is True

    def test_include_public_key_ignored_for_symmetric_key(self):
        """include_public_key must be a no-op for symmetric (oct) keys: embedding one
        would expose the HMAC secret via 'publicKey'."""
        import os

        symmetric_key = os.urandom(32)
        signer = JSFSignature(symmetric_key, "HS256", include_public_key=True)
        obj = {"data": "test"}

        signed = signer.sign(obj)
        assert "publicKey" not in signed["signature"]

        verifier = JSFSignature(symmetric_key, "HS256")
        assert verifier.verify(signed) is True

    def test_get_public_key_rejects_embedded_oct_key(self):
        """Even if a signed object somehow embeds an oct key as 'publicKey', reject it."""
        obj = {
            "signature": {
                "algorithm": "HS256",
                "value": "abc",
                "publicKey": {"kty": "oct", "k": "c2VjcmV0"},
            }
        }
        with pytest.raises(ValueError, match="oct"):
            JSFSignature.get_public_key(obj)


class TestEdDSASignature:
    """Test EdDSA signatures."""

    def test_eddsa_ed25519(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()

        signer = JSFSignature(private_key, "EdDSA")
        obj = {"test": "eddsa"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "EdDSA"

        verifier = JSFSignature(private_key, "EdDSA")
        assert verifier.verify(signed) is True

    def test_eddsa_ed448(self):
        from cryptography.hazmat.primitives.asymmetric import ed448

        private_key = ed448.Ed448PrivateKey.generate()

        signer = JSFSignature(private_key, "EdDSA")
        obj = {"test": "ed448"}

        signed = signer.sign(obj)
        assert signed["signature"]["algorithm"] == "EdDSA"

        verifier = JSFSignature(private_key, "EdDSA")
        assert verifier.verify(signed) is True


class TestCustomSignatureProperty:
    """Test custom signature property names."""

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_custom_property_name(self):
        signer = JSFSignature(self.EC_JWK, "ES256", signature_property="authorizationSignature")
        obj = {"data": "test"}

        signed = signer.sign(obj)
        assert "authorizationSignature" in signed
        assert "signature" not in signed

        verifier = JSFSignature(self.EC_JWK, "ES256", signature_property="authorizationSignature")
        assert verifier.verify(signed) is True


class TestGetPublicKey:
    """Test JSFSignature.get_public_key()."""

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_extracts_embedded_public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

        signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = signer.sign(obj)

        public_key = JSFSignature.get_public_key(signed)
        assert isinstance(public_key, EllipticCurvePublicKey)

        # The extracted key can be used to verify the signature.
        verifier = JSFSignature(public_key, "ES256")
        assert verifier.verify(signed) is True

    def test_no_embedded_public_key_returns_none(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = signer.sign(obj)

        assert JSFSignature.get_public_key(signed) is None

    def test_custom_signature_property(self):
        signer = JSFSignature(
            self.EC_JWK, "ES256", signature_property="sig", include_public_key=True
        )
        obj = {"data": "test"}
        signed = signer.sign(obj)

        assert JSFSignature.get_public_key(signed, signature_property="sig") is not None

    def test_missing_signature_property_raises(self):
        with pytest.raises(ValueError, match="Missing signature property"):
            JSFSignature.get_public_key({"data": "test"})

    def test_malformed_signature_property_raises(self):
        with pytest.raises(ValueError, match="must be an object"):
            JSFSignature.get_public_key({"signature": "not-an-object"})

    def test_invalid_embedded_public_key_raises(self):
        obj = {"signature": {"algorithm": "ES256", "value": "abc", "publicKey": {"kty": "bogus"}}}
        with pytest.raises(ValueError, match="Invalid embedded publicKey"):
            JSFSignature.get_public_key(obj)


class TestGetPublicKeys:
    """Test JSFSignature.get_public_keys()."""

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }
    HMAC_KEY = b"a-shared-hmac-secret-key-material"

    def _generate_rsa_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def test_get_public_keys_single_signature(self):
        signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = signer.sign(obj)

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def test_get_public_keys_multi_signature(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_multi(signed, keys=keys) is True

    def test_get_public_keys_signature_chain(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_chain(signed, keys=keys) is True

    def test_get_public_keys_raises_when_no_embedded_key(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = signer.sign(obj)  # no include_public_key

        with pytest.raises(ValueError, match="No embedded publicKey"):
            JSFSignature.get_public_keys(signed)

    def test_get_public_keys_rejects_oct_key_entry(self):
        obj = {
            "data": "test",
            "signature": {
                "algorithm": "HS256",
                "publicKey": {"kty": "oct", "k": "c2VjcmV0"},
                "value": "abc",
            },
        }
        with pytest.raises(ValueError, match="oct"):
            JSFSignature.get_public_keys(obj)

    def test_get_public_keys_missing_signature_property_raises(self):
        with pytest.raises(ValueError, match="Missing signature property"):
            JSFSignature.get_public_keys({"data": "test"})

    def test_get_public_keys_custom_signature_property(self):
        signer = JSFSignature(
            self.EC_JWK, "ES256", signature_property="sig", include_public_key=True
        )
        obj = {"data": "test"}
        signed = signer.sign(obj)

        keys = JSFSignature.get_public_keys(signed, signature_property="sig")
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256", signature_property="sig").verify(signed) is True


class TestGetCertificateChains:
    """Test JSFSignature.get_certificate_chain()/get_certificate_chains()."""

    def _generate_ec_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    def test_get_certificate_chain_single_signature(self):
        key = self._generate_ec_key()
        cert = _self_signed_certificate(key)
        signer = JSFSignature(key, "ES256", certificate_path=[cert])
        signed = signer.sign({"data": "test"})

        chain = JSFSignature.get_certificate_chain(signed)
        assert chain == [cert]

    def test_get_certificate_chains_multi_signature(self):
        key1 = self._generate_ec_key()
        key2 = self._generate_ec_key()
        cert1 = _self_signed_certificate(key1)
        cert2 = _self_signed_certificate(key2)
        signer1 = JSFSignature(key1, "ES256", certificate_path=[cert1])
        signer2 = JSFSignature(key2, "ES256", certificate_path=[cert2])
        signed = JSFSignature.sign_multi({"data": "test"}, [signer1, signer2])

        chains = JSFSignature.get_certificate_chains(signed)
        assert chains == [[cert1], [cert2]]

    def test_get_certificate_chains_signature_chain(self):
        key1 = self._generate_ec_key()
        key2 = self._generate_ec_key()
        cert1 = _self_signed_certificate(key1)
        signer1 = JSFSignature(key1, "ES256", certificate_path=[cert1])
        signer2 = JSFSignature(key2, "ES256")
        signed = JSFSignature.sign_chain({"data": "test"}, [signer1, signer2])

        chains = JSFSignature.get_certificate_chains(signed)
        assert chains == [[cert1], None]

    def test_no_certificate_path_returns_none(self):
        key = self._generate_ec_key()
        signer = JSFSignature(key, "ES256")
        signed = signer.sign({"data": "test"})

        assert JSFSignature.get_certificate_chain(signed) is None

    def test_custom_signature_property(self):
        key = self._generate_ec_key()
        cert = _self_signed_certificate(key)
        signer = JSFSignature(key, "ES256", signature_property="sig", certificate_path=[cert])
        signed = signer.sign({"data": "test"})

        chain = JSFSignature.get_certificate_chain(signed, signature_property="sig")
        assert chain == [cert]

    def test_missing_signature_property_raises(self):
        with pytest.raises(ValueError, match="Missing signature property"):
            JSFSignature.get_certificate_chains({"data": "test"})

    def test_malformed_signature_property_raises(self):
        with pytest.raises(ValueError, match="must be an object"):
            JSFSignature.get_certificate_chains({"signature": "not-an-object"})


class TestCertificatePathNotAutoResolved:
    """
    certificatePath must never be trusted automatically: a signed document's
    own certificatePath is attacker-controllable, so verify()/verify_multi()/
    verify_chain() must not use it to resolve a verification key on their
    own. Callers must supply the key explicitly (optionally extracted via
    get_public_keys(), which does still read certificatePath).
    """

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_verify_ignores_malformed_certificate_path(self):
        # If certificatePath were auto-resolved, this malformed value would
        # raise while parsing it; instead verify() must ignore it entirely
        # and fall back to the instance's own key. certificatePath is baked
        # into the signed data itself (as sign() would if it supported it)
        # so the signature stays valid.
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}

        sig_obj = signer._build_signer_core()
        sig_obj["certificatePath"] = ["not-a-valid-certificate!"]
        temp_obj = dict(obj)
        temp_obj["signature"] = sig_obj
        sig_obj["value"] = signer._compute_signature(canonicalize(temp_obj))
        signed = dict(obj)
        signed["signature"] = sig_obj

        assert signer.verify(signed) is True

    def test_verify_multi_requires_explicit_key_despite_certificate_path(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [signer])
        signed["signature"]["signers"][0]["certificatePath"] = ["not-a-valid-certificate!"]

        with pytest.raises(ValueError, match="no key supplied"):
            JSFSignature.verify_multi(signed)

    def test_verify_chain_requires_explicit_key_despite_certificate_path(self):
        signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [signer])
        signed["signature"]["chain"][0]["certificatePath"] = ["not-a-valid-certificate!"]

        with pytest.raises(ValueError, match="no key supplied"):
            JSFSignature.verify_chain(signed)


def _self_signed_certificate(private_key):
    """Build a self-signed x509.Certificate for `private_key`."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyjsign-test")])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256(), default_backend())
    )


def _self_signed_certificate_b64(private_key) -> str:
    """Build a base64-encoded DER self-signed certificate for `private_key`."""
    import base64

    from cryptography.hazmat.primitives import serialization

    der = _self_signed_certificate(private_key).public_bytes(encoding=serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


class TestVerifyUsingEmbeddedCertificate:
    """
    Test verifying using a public key extracted from a "certificatePath"
    embedded in the signed document via get_public_keys() (sign() itself has
    no built-in support for embedding a certificatePath, so these tests
    build the signaturecore manually, the same way sign() would if it did).
    """

    def _generate_ec_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    @staticmethod
    def _resign_multi_entry_with_certificate(
        signed, index, signer, private_key, signature_property="signature"
    ):
        """
        Re-sign one sign_multi() "signers" entry with a "certificatePath"
        baked into the signed core (mirrors sign_multi()'s own per-entry
        canonicalization, since certificatePath must be part of the signed
        data, not appended afterwards).
        """
        entries = signed[signature_property]["signers"]
        core = dict(entries[index])
        del core["value"]
        core["certificatePath"] = [_self_signed_certificate_b64(private_key)]
        temp_obj = {k: v for k, v in signed.items() if k != signature_property}
        temp_obj[signature_property] = {"signers": [core]}
        core["value"] = signer._compute_signature(canonicalize(temp_obj))
        entries[index] = core

    @staticmethod
    def _resign_chain_entry_with_certificate(
        signed, index, signer, private_key, signature_property="signature"
    ):
        """Same as above, but for a sign_chain() "chain" entry."""
        chain = signed[signature_property]["chain"]
        core = dict(chain[index])
        del core["value"]
        core["certificatePath"] = [_self_signed_certificate_b64(private_key)]
        temp_obj = {k: v for k, v in signed.items() if k != signature_property}
        temp_obj[signature_property] = {"chain": chain[:index] + [core]}
        core["value"] = signer._compute_signature(canonicalize(temp_obj))
        chain[index] = core

    def test_get_public_keys_extracts_certificate_path(self):
        private_key = self._generate_ec_key()
        signer = JSFSignature(private_key, "ES256")
        obj = {"data": "test"}

        sig_obj = signer._build_signer_core()
        sig_obj["certificatePath"] = [_self_signed_certificate_b64(private_key)]
        temp_obj = dict(obj)
        temp_obj["signature"] = {k: v for k, v in sig_obj.items() if k != "value"}
        sig_obj["value"] = signer._compute_signature(canonicalize(temp_obj))
        signed = dict(obj)
        signed["signature"] = sig_obj

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def test_verify_multi_using_certificate_path_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_key = self._generate_ec_key()
        ec_signer = JSFSignature(ec_key, "ES256")
        rsa_signer = JSFSignature(rsa_key, "RS256")
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        # sign_multi() has no built-in certificatePath support; bake it into
        # each entry's signed core (re-signing), then confirm its presence
        # is ignored by verify_multi() unless explicitly resolved via
        # get_public_keys().
        self._resign_multi_entry_with_certificate(signed, 0, ec_signer, ec_key)
        self._resign_multi_entry_with_certificate(signed, 1, rsa_signer, rsa_key)

        with pytest.raises(ValueError, match="no key supplied"):
            JSFSignature.verify_multi(signed)

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_multi(signed, keys=keys) is True

    def test_verify_chain_using_certificate_path_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_key = self._generate_ec_key()
        ec_signer = JSFSignature(ec_key, "ES256")
        rsa_signer = JSFSignature(rsa_key, "RS256")
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        self._resign_chain_entry_with_certificate(signed, 0, ec_signer, ec_key)
        # The chain's second entry covers the (now re-signed) first entry
        # too, so it must also be re-signed after entry 0 changes.
        self._resign_chain_entry_with_certificate(signed, 1, rsa_signer, rsa_key)

        with pytest.raises(ValueError, match="no key supplied"):
            JSFSignature.verify_chain(signed)

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_chain(signed, keys=keys) is True

    def test_get_public_keys_prefers_certificate_path_over_public_key(self):
        # When both "certificatePath" and "publicKey" are present, the
        # certificate must take precedence (matches _extract_certificate_key
        # being checked before _extract_embedded_public_key).
        private_key = self._generate_ec_key()
        signer = JSFSignature(private_key, "ES256", include_public_key=True)
        obj = {"data": "test"}

        sig_obj = signer._build_signer_core()
        sig_obj["certificatePath"] = [_self_signed_certificate_b64(private_key)]
        temp_obj = dict(obj)
        temp_obj["signature"] = {k: v for k, v in sig_obj.items() if k != "value"}
        sig_obj["value"] = signer._compute_signature(canonicalize(temp_obj))
        signed = dict(obj)
        signed["signature"] = sig_obj

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def _generate_rsa_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )


class TestSignWithCertificatePath:
    """
    Test embedding a "certificatePath" while signing, via the
    JSFSignature(..., certificate_path=...) constructor parameter.
    """

    def _generate_ec_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    def _generate_rsa_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def test_sign_embeds_certificate_path(self):
        private_key = self._generate_ec_key()
        cert = _self_signed_certificate(private_key)
        signer = JSFSignature(private_key, "ES256", certificate_path=[cert])

        signed = signer.sign({"data": "test"})

        assert "certificatePath" in signed["signature"]
        assert len(signed["signature"]["certificatePath"]) == 1
        assert "publicKey" not in signed["signature"]

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def test_sign_embeds_certificate_path_as_der_bytes(self):
        from cryptography.hazmat.primitives import serialization

        private_key = self._generate_ec_key()
        cert_der = _self_signed_certificate(private_key).public_bytes(
            encoding=serialization.Encoding.DER
        )
        signer = JSFSignature(private_key, "ES256", certificate_path=[cert_der])

        signed = signer.sign({"data": "test"})

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def test_sign_embeds_multi_certificate_chain_in_order(self):
        # Two certs (e.g. leaf + a stand-in "root"); order must be preserved.
        private_key = self._generate_ec_key()
        other_key = self._generate_ec_key()
        leaf_cert = _self_signed_certificate(private_key)
        root_cert = _self_signed_certificate(other_key)
        signer = JSFSignature(private_key, "ES256", certificate_path=[leaf_cert, root_cert])

        signed = signer.sign({"data": "test"})

        cert_path = signed["signature"]["certificatePath"]
        assert len(cert_path) == 2

        from pyjsign.certificate import CertificateHandler

        parsed = CertificateHandler.parse_certificate_path(cert_path)
        assert parsed[0].public_key().public_numbers() == private_key.public_key().public_numbers()
        assert parsed[1].public_key().public_numbers() == other_key.public_key().public_numbers()

        # Still verifiable via the leaf key extracted by get_public_keys().
        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 1
        assert JSFSignature(keys[0], "ES256").verify(signed) is True

    def test_sign_certificate_path_takes_precedence_over_include_public_key(self):
        private_key = self._generate_ec_key()
        cert = _self_signed_certificate(private_key)
        signer = JSFSignature(
            private_key, "ES256", certificate_path=[cert], include_public_key=True
        )

        signed = signer.sign({"data": "test"})

        assert "certificatePath" in signed["signature"]
        assert "publicKey" not in signed["signature"]
        assert signer.verify(signed) is True

    def test_sign_multi_with_per_signer_certificates(self):
        rsa_key = self._generate_rsa_key()
        ec_key = self._generate_ec_key()
        ec_cert = _self_signed_certificate(ec_key)
        ec_signer = JSFSignature(ec_key, "ES256", certificate_path=[ec_cert])
        # This signer has no certificate; embeds a raw publicKey instead.
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}

        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        entries = signed["signature"]["signers"]
        assert "certificatePath" in entries[0]
        assert "certificatePath" not in entries[1]
        assert "publicKey" in entries[1]

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_multi(signed, keys=keys) is True

    def test_sign_chain_with_per_signer_certificates(self):
        rsa_key = self._generate_rsa_key()
        ec_key = self._generate_ec_key()
        ec_cert = _self_signed_certificate(ec_key)
        rsa_cert = _self_signed_certificate(rsa_key)
        ec_signer = JSFSignature(ec_key, "ES256", certificate_path=[ec_cert])
        rsa_signer = JSFSignature(rsa_key, "RS256", certificate_path=[rsa_cert])
        obj = {"data": "test"}

        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        entries = signed["signature"]["chain"]
        assert "certificatePath" in entries[0]
        assert "certificatePath" in entries[1]

        keys = JSFSignature.get_public_keys(signed)
        assert len(keys) == 2
        assert JSFSignature.verify_chain(signed, keys=keys) is True

    def test_sign_multi_certificate_path_takes_precedence_over_include_public_key(self):
        ec_key = self._generate_ec_key()
        ec_cert = _self_signed_certificate(ec_key)
        ec_signer = JSFSignature(
            ec_key, "ES256", certificate_path=[ec_cert], include_public_key=True
        )
        obj = {"data": "test"}

        signed = JSFSignature.sign_multi(obj, [ec_signer])

        entry = signed["signature"]["signers"][0]
        assert "certificatePath" in entry
        assert "publicKey" not in entry


class TestMultiSignature:
    """Test JSFSignature.sign_multi()/verify_multi() (JSF Multiple Signatures)."""

    EC_JWK = {
        "kid": "ec-key-1",
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }
    HMAC_KEY = b"a-shared-hmac-secret-key-material"

    def _generate_rsa_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def test_sign_and_verify_multi_with_embedded_public_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)

        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        assert "signers" in signed["signature"]
        assert len(signed["signature"]["signers"]) == 2
        for entry in signed["signature"]["signers"]:
            assert "publicKey" in entry
            assert "value" in entry

        assert JSFSignature.verify_multi(signed, keys=JSFSignature.get_public_keys(signed)) is True

    def test_verify_multi_detects_tampering(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer])

        tampered = dict(signed)
        tampered["data"] = "tampered"
        keys = JSFSignature.get_public_keys(signed)
        assert JSFSignature.verify_multi(tampered, keys=keys) is False

    def test_verify_multi_with_keyid_lookup(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        rsa_signer = JSFSignature(JWKHandler.to_jwk(rsa_key), "RS256")

        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        # No embedded publicKey/certificatePath: keys must be supplied by caller.
        keys_by_id = {
            "ec-key-1": JSFSignature(self.EC_JWK, "ES256").key,
        }
        # rsa_signer has no keyId (no "kid" set on the joserfc key), so it must
        # be supplied positionally instead when a dict is used for the other key.
        with pytest.raises(ValueError, match="No key provided for signer 1"):
            JSFSignature.verify_multi(signed, keys=keys_by_id)

    def test_verify_multi_with_positional_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        rsa_signer = JSFSignature(rsa_key, "RS256")

        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [ec_signer, rsa_signer])

        assert JSFSignature.verify_multi(signed, keys=[ec_signer.key, rsa_key.public_key()]) is True

    def test_sign_multi_include_public_key_ignored_for_symmetric_key(self):
        hmac_signer = JSFSignature(self.HMAC_KEY, "HS256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(obj, [hmac_signer])

        assert "publicKey" not in signed["signature"]["signers"][0]
        assert JSFSignature.verify_multi(signed, keys=[self.HMAC_KEY]) is True

    def test_sign_multi_empty_signers_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            JSFSignature.sign_multi({"data": "test"}, [])

    def test_sign_multi_rejects_public_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec as ec_module

        private_key = ec_module.generate_private_key(ec_module.SECP256R1(), default_backend())
        public_signer = JSFSignature(private_key.public_key(), "ES256")

        with pytest.raises(ValueError, match="Cannot sign with a public key"):
            JSFSignature.sign_multi({"data": "test"}, [public_signer])

    def test_verify_multi_missing_signature_property_raises(self):
        with pytest.raises(ValueError, match="Missing signature property"):
            JSFSignature.verify_multi({"data": "test"})

    def test_verify_multi_not_a_multisignature_raises(self):
        signed = {"data": "test", "signature": {"algorithm": "ES256", "value": "abc"}}
        with pytest.raises(ValueError, match="not a multisignature object"):
            JSFSignature.verify_multi(signed)

    def test_verify_multi_empty_signers_raises(self):
        signed = {"data": "test", "signature": {"signers": []}}
        with pytest.raises(ValueError, match="non-empty array"):
            JSFSignature.verify_multi(signed)

    def test_verify_multi_malformed_entry_raises(self):
        signed = {"data": "test", "signature": {"signers": [{"algorithm": "ES256"}]}}
        with pytest.raises(ValueError, match="Malformed signer entry"):
            JSFSignature.verify_multi(signed)

    def test_verify_multi_ignores_embedded_public_key_without_keys(self):
        # publicKey is no longer auto-resolved by verify_multi(); without an
        # explicit certificatePath or `keys` argument, it must raise.
        signed = {
            "data": "test",
            "signature": {
                "signers": [
                    {
                        "algorithm": "HS256",
                        "publicKey": {"kty": "oct", "k": "c2VjcmV0"},
                        "value": "abc",
                    }
                ]
            },
        }
        with pytest.raises(ValueError, match="Cannot resolve verification key"):
            JSFSignature.verify_multi(signed)

    def test_spec_multi_signature_vector(self):
        """Matches the literal JSF spec Appendix A multisignature test vector."""
        signed = {
            "now": "2019-02-10T11:23:06Z",
            "name": "Joe",
            "id": 2200063,
            "signature": {
                "signers": [
                    {
                        "algorithm": "ES256",
                        "publicKey": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
                            "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
                        },
                        "value": (
                            "Nmkfbz5AfQbLW7m3uZrc12yrXoP-skILw58Z9KRPFW0OYyrnuagJTVvKAfpaZ6Sz"
                            "nQ69IGM_J8bBnsuois6JAg"
                        ),
                    },
                    {
                        "algorithm": "RS256",
                        "publicKey": {
                            "kty": "RSA",
                            "n": (
                                "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-"
                                "dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcr"
                                "WhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR"
                                "15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0G"
                                "s4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia"
                                "8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw"
                            ),
                            "e": "AQAB",
                        },
                        "value": (
                            "JqJPRtttK-_whpZthVGZne1MONlMh5co7s8IWsI1-HAlqyYQTqmIIaIVBUc00MKx"
                            "GZkle99d7GuF2GGKb_7aJtdsA5ZNUYHzYReaX0xg6TKcM9ppWqeFQx_DXR6GlGv3N"
                            "NhNqBy2uCT_vnwErlWlNe_KQd3KJeQDrqHVQHmvCrUnx2ShXQp6MhLkZ6mrAN_J2I"
                            "9z-i6NWFRG91aXfnupKvmrUZ8834ASbo5i2uEXbT8VeG9Ihuwi9iP7hhLmGd3ocUT"
                            "sdtB4jTU2js7Q-F24_99SbIXW50Tfrp_TZWIjF9CqW8278OE4kGsf9Qub4VkR0b7M"
                            "XYFRsE0fxTw4rdPV7A"
                        ),
                    },
                ]
            },
        }
        assert JSFSignature.verify_multi(signed, keys=JSFSignature.get_public_keys(signed)) is True

    def test_sign_multi_appends_to_existing_multi_signature(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}

        signed = JSFSignature.sign_multi(obj, [ec_signer])
        assert len(signed["signature"]["signers"]) == 1

        appended = JSFSignature.sign_multi(signed, [rsa_signer])
        assert len(appended["signature"]["signers"]) == 2
        assert appended["signature"]["signers"][0] == signed["signature"]["signers"][0]
        keys = JSFSignature.get_public_keys(appended)
        assert JSFSignature.verify_multi(appended, keys=keys) is True

    def test_sign_multi_rejects_object_with_plain_signature(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = ec_signer.sign(obj)

        with pytest.raises(ValueError, match="already contains"):
            JSFSignature.sign_multi(signed, [ec_signer])

    def test_sign_multi_rejects_object_with_signature_chain(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        chained = JSFSignature.sign_chain(obj, [ec_signer])

        with pytest.raises(ValueError, match="already contains"):
            JSFSignature.sign_multi(chained, [ec_signer])

    def test_sign_multi_appends_with_custom_signature_property(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test", "mySig": {"signers": []}}

        appended = JSFSignature.sign_multi(obj, [ec_signer], signature_property="mySig")
        assert len(appended["mySig"]["signers"]) == 1
        keys = JSFSignature.get_public_keys(appended, signature_property="mySig")
        assert JSFSignature.verify_multi(appended, keys=keys, signature_property="mySig") is True

    def test_sign_multi_with_excludes(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"mySignedData": "something", "myUnsignedData": "something else"}
        signed = JSFSignature.sign_multi(obj, [ec_signer], excludes=["myUnsignedData"])

        for entry in signed["signature"]["signers"]:
            assert entry["excludes"] == ["myUnsignedData"]

        keys = JSFSignature.get_public_keys(signed)
        with pytest.raises(ValueError, match="allowed_excludes"):
            JSFSignature.verify_multi(signed, keys=keys)
        assert (
            JSFSignature.verify_multi(signed, keys=keys, allowed_excludes=["myUnsignedData"])
            is True
        )

        tampered = dict(signed)
        tampered["myUnsignedData"] = "changed"
        assert (
            JSFSignature.verify_multi(tampered, keys=keys, allowed_excludes=["myUnsignedData"])
            is True
        )

        tampered_signed_data = dict(signed)
        tampered_signed_data["mySignedData"] = "changed"
        assert (
            JSFSignature.verify_multi(
                tampered_signed_data, keys=keys, allowed_excludes=["myUnsignedData"]
            )
            is False
        )

    def test_sign_multi_with_extensions(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_multi(
            obj,
            [ec_signer],
            extensions={"otherExt": "Cool Stuff"},
        )

        for entry in signed["signature"]["signers"]:
            assert entry["extensions"] == ["otherExt"]
            assert entry["otherExt"] == "Cool Stuff"

        keys = JSFSignature.get_public_keys(signed)
        assert JSFSignature.verify_multi(signed, keys=keys) is True

        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["signers"] = [dict(tampered["signature"]["signers"][0])]
        tampered["signature"]["signers"][0]["otherExt"] = "Tampered"
        assert JSFSignature.verify_multi(tampered, keys=keys) is False


class TestSignatureChain:
    """Test JSFSignature.sign_chain()/verify_chain() (JSF Signature Chains)."""

    EC_JWK = {
        "kid": "ec-key-1",
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }
    HMAC_KEY = b"a-shared-hmac-secret-key-material"

    def _generate_rsa_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def test_sign_and_verify_chain_with_embedded_public_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)

        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        assert "chain" in signed["signature"]
        assert len(signed["signature"]["chain"]) == 2
        for entry in signed["signature"]["chain"]:
            assert "publicKey" in entry
            assert "value" in entry

        assert JSFSignature.verify_chain(signed, keys=JSFSignature.get_public_keys(signed)) is True

    def test_verify_chain_detects_payload_tampering(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer])

        tampered = dict(signed)
        tampered["data"] = "tampered"
        keys = JSFSignature.get_public_keys(signed)
        assert JSFSignature.verify_chain(tampered, keys=keys) is False

    def test_verify_chain_detects_earlier_entry_tampering(self):
        """Tampering with an earlier chain entry invalidates later signatures too."""
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)

        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])
        keys = JSFSignature.get_public_keys(signed)

        tampered = {**signed, "signature": {"chain": list(signed["signature"]["chain"])}}
        tampered["signature"]["chain"][0] = dict(tampered["signature"]["chain"][0])
        tampered["signature"]["chain"][0]["keyId"] = "forged"
        assert JSFSignature.verify_chain(tampered, keys=keys) is False

    def test_verify_chain_with_keyid_lookup(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        rsa_signer = JSFSignature(JWKHandler.to_jwk(rsa_key), "RS256")

        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        keys_by_id = {
            "ec-key-1": JSFSignature(self.EC_JWK, "ES256").key,
        }
        # rsa_signer has no keyId, no publicKey, no certificatePath: unresolvable.
        with pytest.raises(ValueError, match="No key provided for signer 1"):
            JSFSignature.verify_chain(signed, keys=keys_by_id)

    def test_verify_chain_with_positional_keys(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        rsa_signer = JSFSignature(rsa_key, "RS256")

        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [ec_signer, rsa_signer])

        assert JSFSignature.verify_chain(signed, keys=[ec_signer.key, rsa_key.public_key()]) is True

    def test_sign_chain_include_public_key_ignored_for_symmetric_key(self):
        hmac_signer = JSFSignature(self.HMAC_KEY, "HS256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(obj, [hmac_signer])

        assert "publicKey" not in signed["signature"]["chain"][0]
        assert JSFSignature.verify_chain(signed, keys=[self.HMAC_KEY]) is True

    def test_sign_chain_empty_signers_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            JSFSignature.sign_chain({"data": "test"}, [])

    def test_sign_chain_rejects_public_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec as ec_module

        private_key = ec_module.generate_private_key(ec_module.SECP256R1(), default_backend())
        public_signer = JSFSignature(private_key.public_key(), "ES256")

        with pytest.raises(ValueError, match="Cannot sign with a public key"):
            JSFSignature.sign_chain({"data": "test"}, [public_signer])

    def test_verify_chain_missing_signature_property_raises(self):
        with pytest.raises(ValueError, match="Missing signature property"):
            JSFSignature.verify_chain({"data": "test"})

    def test_verify_chain_not_a_signaturechain_raises(self):
        signed = {"data": "test", "signature": {"algorithm": "ES256", "value": "abc"}}
        with pytest.raises(ValueError, match="not a signaturechain object"):
            JSFSignature.verify_chain(signed)

    def test_verify_chain_empty_chain_raises(self):
        signed = {"data": "test", "signature": {"chain": []}}
        with pytest.raises(ValueError, match="non-empty array"):
            JSFSignature.verify_chain(signed)

    def test_verify_chain_malformed_entry_raises(self):
        signed = {"data": "test", "signature": {"chain": [{"algorithm": "ES256"}]}}
        with pytest.raises(ValueError, match="Malformed chain entry"):
            JSFSignature.verify_chain(signed)

    def test_verify_chain_ignores_embedded_public_key_without_keys(self):
        # publicKey is no longer auto-resolved by verify_chain(); without an
        # explicit certificatePath or `keys` argument, it must raise.
        signed = {
            "data": "test",
            "signature": {
                "chain": [
                    {
                        "algorithm": "HS256",
                        "publicKey": {"kty": "oct", "k": "c2VjcmV0"},
                        "value": "abc",
                    }
                ]
            },
        }
        with pytest.raises(ValueError, match="Cannot resolve verification key"):
            JSFSignature.verify_chain(signed)

    def test_spec_signature_chain_vector(self):
        """Matches the literal JSF spec Appendix A signature chain test vector."""
        signed = {
            "now": "2019-02-10T11:23:06Z",
            "name": "Joe",
            "id": 2200063,
            "signature": {
                "chain": [
                    {
                        "algorithm": "ES256",
                        "publicKey": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
                            "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
                        },
                        "value": (
                            "VJKH2mR8qwq5vPLbwA9i-IYoSdI8lLQ9Orz9vANsOCMw0FQB4KjEuBfdKJ1D2JSF"
                            "oX7KcaMvCz24sT5cbeN8TA"
                        ),
                    },
                    {
                        "algorithm": "RS256",
                        "publicKey": {
                            "kty": "RSA",
                            "n": (
                                "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-"
                                "dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcr"
                                "WhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR"
                                "15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0G"
                                "s4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia"
                                "8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw"
                            ),
                            "e": "AQAB",
                        },
                        "value": (
                            "YhGrlUD-wwoMLxTgZcDLlRq_dlUV300yffV6ejjbxhszocSI1qGu8Yn0p1vVTfgx"
                            "PfR1VErQ_ME-XFAfck1_1vrrrWdv9Vg5SzHrhu5YnJAhT7QUq3gR1s3iH9nS9xcA7"
                            "HB3nuYc94z_vfDY2s3u-q-858Q6jnIGy0ejpOeEK7jSqwTbDkwRo5tguXmArMQHY9"
                            "2NB8Pt2hI_11ZJH1CuShKixTtKP6DOu8Q8f8wgjC2AHcTjogeW7bMcH6k4kjdQGkw"
                            "WWHSCjLVTxqxkpMcdkn2gaFBtaxzWd7kXAxMF8MyjoXV_J-cQn5fU6uImR8MbMVYU"
                            "mpPMVbvToEfXSZBiuw"
                        ),
                    },
                ]
            },
        }
        assert JSFSignature.verify_chain(signed, keys=JSFSignature.get_public_keys(signed)) is True

    def test_sign_chain_extends_existing_chain(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}

        signed = JSFSignature.sign_chain(obj, [ec_signer])
        assert len(signed["signature"]["chain"]) == 1

        extended = JSFSignature.sign_chain(signed, [rsa_signer])
        assert len(extended["signature"]["chain"]) == 2
        assert extended["signature"]["chain"][0] == signed["signature"]["chain"][0]
        keys = JSFSignature.get_public_keys(extended)
        assert JSFSignature.verify_chain(extended, keys=keys) is True

    def test_sign_chain_extension_detects_earlier_entry_tampering(self):
        rsa_key = self._generate_rsa_key()
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        rsa_signer = JSFSignature(rsa_key, "RS256", include_public_key=True)
        obj = {"data": "test"}

        signed = JSFSignature.sign_chain(obj, [ec_signer])
        extended = JSFSignature.sign_chain(signed, [rsa_signer])
        keys = JSFSignature.get_public_keys(extended)

        tampered = dict(extended)
        tampered["signature"] = dict(extended["signature"])
        tampered["signature"]["chain"] = list(extended["signature"]["chain"])
        tampered_first = dict(tampered["signature"]["chain"][0])
        last_char = tampered_first["value"][-1]
        replacement = "A" if last_char != "A" else "B"
        tampered_first["value"] = tampered_first["value"][:-1] + replacement
        tampered["signature"]["chain"][0] = tampered_first

        assert JSFSignature.verify_chain(tampered, keys=keys) is False

    def test_sign_chain_rejects_object_with_plain_signature(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        signed = ec_signer.sign(obj)

        with pytest.raises(ValueError, match="already contains"):
            JSFSignature.sign_chain(signed, [ec_signer])

    def test_sign_chain_rejects_object_with_multi_signature(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256")
        obj = {"data": "test"}
        multi = JSFSignature.sign_multi(obj, [ec_signer])

        with pytest.raises(ValueError, match="already contains"):
            JSFSignature.sign_chain(multi, [ec_signer])

    def test_sign_chain_extends_with_custom_signature_property(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test", "mySig": {"chain": []}}

        extended = JSFSignature.sign_chain(obj, [ec_signer], signature_property="mySig")
        assert len(extended["mySig"]["chain"]) == 1
        keys = JSFSignature.get_public_keys(extended, signature_property="mySig")
        assert JSFSignature.verify_chain(extended, keys=keys, signature_property="mySig") is True

    def test_sign_chain_with_excludes(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"mySignedData": "something", "myUnsignedData": "something else"}
        signed = JSFSignature.sign_chain(obj, [ec_signer], excludes=["myUnsignedData"])

        for entry in signed["signature"]["chain"]:
            assert entry["excludes"] == ["myUnsignedData"]

        keys = JSFSignature.get_public_keys(signed)
        with pytest.raises(ValueError, match="allowed_excludes"):
            JSFSignature.verify_chain(signed, keys=keys)
        assert (
            JSFSignature.verify_chain(signed, keys=keys, allowed_excludes=["myUnsignedData"])
            is True
        )

        tampered = dict(signed)
        tampered["myUnsignedData"] = "changed"
        assert (
            JSFSignature.verify_chain(tampered, keys=keys, allowed_excludes=["myUnsignedData"])
            is True
        )

        tampered_signed_data = dict(signed)
        tampered_signed_data["mySignedData"] = "changed"
        assert (
            JSFSignature.verify_chain(
                tampered_signed_data, keys=keys, allowed_excludes=["myUnsignedData"]
            )
            is False
        )

    def test_sign_chain_with_extensions(self):
        ec_signer = JSFSignature(self.EC_JWK, "ES256", include_public_key=True)
        obj = {"data": "test"}
        signed = JSFSignature.sign_chain(
            obj,
            [ec_signer],
            extensions={"otherExt": "Cool Stuff"},
        )

        for entry in signed["signature"]["chain"]:
            assert entry["extensions"] == ["otherExt"]
            assert entry["otherExt"] == "Cool Stuff"

        keys = JSFSignature.get_public_keys(signed)
        assert JSFSignature.verify_chain(signed, keys=keys) is True

        tampered = dict(signed)
        tampered["signature"] = dict(tampered["signature"])
        tampered["signature"]["chain"] = [dict(tampered["signature"]["chain"][0])]
        tampered["signature"]["chain"][0]["otherExt"] = "Tampered"
        assert JSFSignature.verify_chain(tampered, keys=keys) is False


class TestAlgorithmRegistry:
    """Test algorithm registry."""

    def test_list_algorithms(self):
        algs = AlgorithmRegistry.list_algorithms()
        assert "ES256" in algs
        assert "RS256" in algs
        assert "PS256" in algs
        assert "HS256" in algs
        assert "EdDSA" in algs

    def test_validate_algorithm_key_type(self):
        assert AlgorithmRegistry.validate_algorithm_key_type("ES256", "EC")
        assert AlgorithmRegistry.validate_algorithm_key_type("RS256", "RSA")
        assert AlgorithmRegistry.validate_algorithm_key_type("HS256", "oct")
        assert AlgorithmRegistry.validate_algorithm_key_type("EdDSA", "OKP")

        assert not AlgorithmRegistry.validate_algorithm_key_type("ES256", "RSA")
        assert not AlgorithmRegistry.validate_algorithm_key_type("RS256", "EC")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
