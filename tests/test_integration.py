#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Integration tests using JSF specification examples.
Tests real-world signing scenarios from https://cyberphone.github.io/doc/security/jsf.html
"""

import json

import pytest

from pyjsign import JSFSignature


class TestJSFSpecExamples:
    """Test with examples from the JSF specification."""

    # P-256 key from JSF spec
    P256_KEY = {
        "kid": "example.com:p256",
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    TEST_OBJECT = {"now": "2019-02-10T11:23:06Z", "name": "Joe", "id": 2200063}

    def test_basic_signing_with_public_key(self):
        """Test signing with embedded publicKey (from JSF spec)."""
        signer = JSFSignature(self.P256_KEY, "ES256", include_public_key=True)
        obj = dict(self.TEST_OBJECT)

        signed = signer.sign(obj)

        # Verify structure matches JSF spec
        assert "signature" in signed
        sig_obj = signed["signature"]
        assert sig_obj["algorithm"] == "ES256"
        assert "publicKey" in sig_obj
        assert "value" in sig_obj

        # Verify signature is valid
        verifier = JSFSignature(self.P256_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_signing_without_embedded_key(self):
        """Test signing without embedding public key."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate new key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        signer = JSFSignature(private_key, "ES256")
        obj = dict(self.TEST_OBJECT)

        signed = signer.sign(obj)

        sig_obj = signed["signature"]
        assert sig_obj["algorithm"] == "ES256"
        # When using key objects (not JWK), public key is not automatically added

        # Can still verify with same key
        verifier = JSFSignature(private_key, "ES256")
        assert verifier.verify(signed) is True

    def test_custom_signature_property_name(self):
        """
        Test with custom signature property name (like authorizationSignature in JSF spec).
        """
        signer = JSFSignature(self.P256_KEY, "ES256", signature_property="authorizationSignature")
        obj = dict(self.TEST_OBJECT)

        signed = signer.sign(obj)

        # Should use custom property name
        assert "authorizationSignature" in signed
        assert "signature" not in signed

        assert signed["authorizationSignature"]["algorithm"] == "ES256"
        assert "value" in signed["authorizationSignature"]

        # Verify with same property name
        verifier = JSFSignature(self.P256_KEY, "ES256", signature_property="authorizationSignature")
        assert verifier.verify(signed) is True

    def test_data_with_non_ascii_characters(self):
        """Test signing data with non-ASCII characters."""
        signer = JSFSignature(self.P256_KEY, "ES256")
        obj = {"message": "Hello, 世界! مرحبا 🌍", "emoji": "👍"}

        signed = signer.sign(obj)
        assert "signature" in signed

        verifier = JSFSignature(self.P256_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_large_object_signing(self):
        """Test signing a large complex object."""
        signer = JSFSignature(self.P256_KEY, "ES256")

        large_obj = {
            "name": "Test",
            "nested": {"level1": {"level2": {"level3": {"data": list(range(100))}}}},
            "array": [{"id": i, "value": f"item{i}"} for i in range(50)],
        }

        signed = signer.sign(large_obj)

        verifier = JSFSignature(self.P256_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_roundtrip_json_serialization(self):
        """Test that signed object can be JSON serialized and deserialized."""
        signer = JSFSignature(self.P256_KEY, "ES256")
        obj = dict(self.TEST_OBJECT)

        signed = signer.sign(obj)

        # Serialize to JSON
        json_str = json.dumps(signed)

        # Deserialize from JSON
        deserialized = json.loads(json_str)

        # Verify deserialized object
        verifier = JSFSignature(self.P256_KEY, "ES256")
        assert verifier.verify(deserialized) is True

    def test_multiple_algorithms(self):
        """Test signing with different algorithms."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        obj = {"test": "data"}

        # Test ES384
        private_key_384 = ec.generate_private_key(ec.SECP384R1(), default_backend())
        signer_384 = JSFSignature(private_key_384, "ES384")
        signed_384 = signer_384.sign(obj)
        assert signed_384["signature"]["algorithm"] == "ES384"

        verifier_384 = JSFSignature(private_key_384, "ES384")
        assert verifier_384.verify(signed_384) is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    EC_KEY = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_empty_object(self):
        """Test signing empty object."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        signed = signer.sign({})

        verifier = JSFSignature(self.EC_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_object_with_null_values(self):
        """Test signing object with null values."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        obj = {"a": None, "b": "value", "c": None}

        signed = signer.sign(obj)

        verifier = JSFSignature(self.EC_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_object_with_empty_arrays(self):
        """Test signing object with empty arrays."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        obj = {"arr": [], "data": "test"}

        signed = signer.sign(obj)

        verifier = JSFSignature(self.EC_KEY, "ES256")
        assert verifier.verify(signed) is True

    def test_signature_missing_value(self):
        """Test verification fails when signature value is missing."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        signed = signer.sign({"test": "data"})

        # Remove signature value
        del signed["signature"]["value"]

        verifier = JSFSignature(self.EC_KEY, "ES256")
        with pytest.raises(ValueError):
            verifier.verify(signed)

    def test_signature_missing_algorithm(self):
        """Test verification fails when algorithm is missing."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        signed = signer.sign({"test": "data"})

        # Remove algorithm
        del signed["signature"]["algorithm"]

        verifier = JSFSignature(self.EC_KEY, "ES256")
        with pytest.raises(ValueError):
            verifier.verify(signed)

    def test_algorithm_mismatch(self):
        """Test verification fails when algorithms don't match."""
        signer = JSFSignature(self.EC_KEY, "ES256")
        signed = signer.sign({"test": "data"})

        # Try to verify with different algorithm
        verifier = JSFSignature(self.EC_KEY, "ES384")
        with pytest.raises(ValueError):
            verifier.verify(signed)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
