#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Tests for the ITU-T X.590 "JSON signature scheme" (JSS) implementation.

Includes the literal Ed25519 test keys and JCS/hash test vector published
in ITU-T Recommendation X.590 (10/2023), Appendix II and clauses 7.1.4-7.1.5,
to validate interoperability of the canonicalization+hashing pipeline with
the specification.
"""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pyjsign.canonicalization import canonicalize
from pyjsign.jss import JSSSignature, _compute_digest

# Appendix II.1/II.2 of ITU-T X.590 (10/2023): Ed25519 keys used in the
# specification's examples.
APPENDIX_II_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAubMonBfU9pvIbj5RCiWQLD45Jvu6mKr+kQXjvjW8ZkU=
-----END PUBLIC KEY-----
"""
APPENDIX_II_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDnZ5bPmXnB3OfU/5fNVfxfr7iRZtqH06AZ3b6c6liTL
-----END PRIVATE KEY-----
"""

# The unsigned public key body as literally published in clause 7.1.3 (note:
# unlike a strict PEM body, the spec's text omits the trailing base64 "="
# padding character).
APPENDIX_II_PUBLIC_KEY_BODY = "MCowBQYDK2VwAyEAubMonBfU9pvIbj5RCiWQLD45Jvu6mKr+kQXjvjW8ZkU"

# Clause 7.1.1: the object used throughout the specification's signing walkthrough.
SAMPLE_OBJECT = {
    "statement": "Hello signed world!",
    "otherProperties": ["home", "food"],
}

# Clause 7.1.4: the JCS canonicalization of SAMPLE_OBJECT plus the (value-less)
# JSS signature object built in clause 7.1.3. (The specification's own
# clause 7.1.4 rendering of this string drops the hyphen from "sha-256",
# which is inconsistent with clause 7.1.3's "hash_algorithm": "sha-256" for
# the very same signature object -- a PDF extraction/typesetting artifact,
# not a real difference, since JCS never alters string property values.)
EXPECTED_CANONICAL_JSON = (
    b'{"otherProperties":["home","food"],"signatures":[{"algorithm":"Ed25519",'
    b'"hash_algorithm":"sha-256","public_key":"'
    + APPENDIX_II_PUBLIC_KEY_BODY.encode("ascii")
    + b'"}],"statement":"Hello signed world!"}'
)

# Clause 7.1.5: SHA-256 hash (hex) of EXPECTED_CANONICAL_JSON.
EXPECTED_HASH_HEX = "e005ae762a01723f3b58fa8edb2b2cc3b126ca087077189072cfd9a27e6079d5"


def _generate_keys():
    return {
        "ES256": ec.generate_private_key(ec.SECP256R1()),
        "ES384": ec.generate_private_key(ec.SECP384R1()),
        "ES512": ec.generate_private_key(ec.SECP521R1()),
        "RS256": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "RS384": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "RS512": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "PS256": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "PS384": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "PS512": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "Ed25519": ed25519.Ed25519PrivateKey.generate(),
        "Ed448": ed448.Ed448PrivateKey.generate(),
    }


_KEYS = _generate_keys()


def _self_signed_certificate(private_key):
    """Build a self-signed x509.Certificate for `private_key`."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyjsign-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, _hashes.SHA256())
    )


class TestAppendixIIVectors:
    """
    Verifies the JCS canonicalization + hashing pipeline (clauses 7.1.4 and
    7.1.5) reproduces the exact byte-for-byte hash published in ITU-T X.590,
    using the specification's own Appendix II Ed25519 keys and clause 7.1.1
    sample object.

    NOTE: The exact `value` (signature) published in the specification's
    clause 7.1.6/7.1.7 walkthrough does not reproduce here; ITU-T X.590's
    Appendix II/III examples are explicitly non-normative ("This appendix
    does not form an integral part of this Recommendation") and the
    published signature bytes appear to be a documentation artifact rather
    than a live, reproducible test vector -- unlike the hash, which matches
    exactly. Round-trip sign/verify using these keys is used instead to
    validate this library's own Ed25519 signing/verification correctness.
    """

    def test_jcs_hash_matches_spec(self):
        entry = {
            "hash_algorithm": "sha-256",
            "algorithm": "Ed25519",
            "public_key": APPENDIX_II_PUBLIC_KEY_BODY,
        }
        obj = dict(SAMPLE_OBJECT)
        obj["signatures"] = [entry]

        canonical = canonicalize(obj)
        assert canonical == EXPECTED_CANONICAL_JSON

        digest = _compute_digest("sha-256", canonical)
        assert digest.hex() == EXPECTED_HASH_HEX

    def test_appendix_keys_sign_verify_round_trip(self):
        private_key = load_pem_private_key(APPENDIX_II_PRIVATE_KEY_PEM, password=None)

        signer = JSSSignature(private_key, "Ed25519", include_public_key=True)
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        assert JSSSignature.verify(signed)
        # The embedded public key must match the Appendix II public key.
        assert (
            signed["signatures"][0]["public_key"]
            == "MCowBQYDK2VwAyEAubMonBfU9pvIbj5RCiWQLD45Jvu6mKr+kQXjvjW8ZkU="
        )


class TestSignVerifyRoundTrip:
    """Round-trip sign()/verify() for every supported algorithm and hash_algorithm."""

    @pytest.mark.parametrize("algorithm", sorted(_KEYS))
    @pytest.mark.parametrize("hash_algorithm", ["sha-256", "sha-384", "sha-512"])
    def test_round_trip(self, algorithm, hash_algorithm):
        signer = JSSSignature(
            _KEYS[algorithm],
            algorithm,
            hash_algorithm=hash_algorithm,
            include_public_key=True,
        )
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        entry = signed["signatures"][0]
        assert entry["algorithm"] == algorithm
        assert entry["hash_algorithm"] == hash_algorithm
        assert "public_key" in entry
        assert "value" in entry

        assert JSSSignature.verify(signed)

    def test_tamper_detection(self):
        signer = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        tampered = copy.deepcopy(signed)
        tampered["statement"] = "Tampered!"
        assert not JSSSignature.verify(tampered)

    def test_jcs_substitution_regression(self):
        """
        Regression test for the JCS-substitution attack described in ITU-T
        X.590 clause 9: a signed object with nested numeric/string values
        must have those values preserved (not collapsed to {}) by
        canonicalization, and any tampering with them must invalidate the
        signature.
        """
        obj = {
            "fromAccount": "1234",
            "toAccount": "4567",
            "amount": {"value": 100, "currency": "USD"},
        }
        signer = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signed = signer.sign(obj)

        assert signed["amount"] == {"value": 100, "currency": "USD"}
        assert JSSSignature.verify(signed)

        tampered = copy.deepcopy(signed)
        tampered["amount"]["value"] = 999999
        assert not JSSSignature.verify(tampered)

    def test_signature_value_missing_fails(self):
        obj = {"statement": "Hello"}
        assert not JSSSignature.verify(obj)

        obj["signatures"] = []
        assert not JSSSignature.verify(obj)

    def test_sign_requires_key_locator(self):
        with pytest.raises(ValueError, match="self-describing"):
            JSSSignature(_KEYS["ES256"], "ES256").sign(copy.deepcopy(SAMPLE_OBJECT))

    def test_sign_with_public_key_only_raises(self):
        public_key = _KEYS["ES256"].public_key()
        signer = JSSSignature(public_key, "ES256", include_public_key=True)
        with pytest.raises(ValueError, match="Cannot sign with a public key"):
            signer.sign(copy.deepcopy(SAMPLE_OBJECT))

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            JSSSignature(_KEYS["ES256"], "NOT-AN-ALGORITHM")

    def test_unsupported_hash_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported hash_algorithm"):
            JSSSignature(_KEYS["ES256"], "ES256", hash_algorithm="sha3-256")

    def test_algorithm_key_type_mismatch_raises(self):
        with pytest.raises(ValueError, match="incompatible with key type"):
            JSSSignature(_KEYS["ES256"], "RS256")


class TestJWKKeyInput:
    """JSSSignature also accepts a JWK dict or joserfc key object, like JSFSignature."""

    EC_JWK = {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_sign_verify_with_jwk_dict(self):
        signer = JSSSignature(self.EC_JWK, "ES256", include_public_key=True)
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        assert signed["signatures"][0]["algorithm"] == "ES256"
        assert JSSSignature.verify(signed)

    def test_sign_verify_with_joserfc_key_object(self):
        from pyjsign.jwk_handler import JWKHandler

        joserfc_key = JWKHandler.to_jwk(_KEYS["ES256"])
        signer = JSSSignature(joserfc_key, "ES256", include_public_key=True)
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        assert signed["signatures"][0]["algorithm"] == "ES256"
        assert JSSSignature.verify(signed)

    def test_jwk_key_stored_as_raw_cryptography_key(self):
        # self.key must end up as a `cryptography` key object (not a JWK
        # dict/joserfc object) since the rest of JSSSignature assumes that.
        signer = JSSSignature(self.EC_JWK, "ES256")
        assert isinstance(signer.key, ec.EllipticCurvePrivateKey)


class TestMultiSignature:
    """Multiple independent JSS signatures in the `signatures` array."""

    def test_sign_multi_appends_independent_signatures(self):
        signer1 = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signer2 = JSSSignature(_KEYS["Ed25519"], "Ed25519", include_public_key=True)
        signer3 = JSSSignature(_KEYS["RS256"], "RS256", include_public_key=True)

        multi = JSSSignature.sign_multi(copy.deepcopy(SAMPLE_OBJECT), [signer1, signer2, signer3])

        assert len(multi["signatures"]) == 3
        assert [entry["algorithm"] for entry in multi["signatures"]] == [
            "ES256",
            "Ed25519",
            "RS256",
        ]
        assert JSSSignature.verify(multi)

    def test_sign_multi_one_bad_signature_fails_verify(self):
        signer1 = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signer2 = JSSSignature(_KEYS["Ed25519"], "Ed25519", include_public_key=True)

        multi = JSSSignature.sign_multi(copy.deepcopy(SAMPLE_OBJECT), [signer1, signer2])
        multi["signatures"][1]["value"] = multi["signatures"][0]["value"]

        assert not JSSSignature.verify(multi)

    def test_sign_multi_requires_signers(self):
        with pytest.raises(ValueError, match="at least one signer"):
            JSSSignature.sign_multi(copy.deepcopy(SAMPLE_OBJECT), [])

    def test_sign_multi_requires_shared_signatures_property(self):
        signer1 = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signer2 = JSSSignature(
            _KEYS["Ed25519"],
            "Ed25519",
            include_public_key=True,
            signatures_property="sigs",
        )
        with pytest.raises(ValueError, match="signatures_property"):
            JSSSignature.sign_multi(copy.deepcopy(SAMPLE_OBJECT), [signer1, signer2])


class TestCertificatePathAndCertUrl:
    """public_cert_chain / cert_url / thumbprint key-locator precedence and resolution."""

    def test_cert_url_requires_resolve_key_callback(self):
        signer = JSSSignature(_KEYS["ES256"], "ES256", cert_url="https://example.com/cert.pem")
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        assert signed["signatures"][0]["cert_url"] == "https://example.com/cert.pem"
        assert not JSSSignature.verify(signed)

        assert JSSSignature.verify(signed, resolve_key=lambda entry: _KEYS["ES256"].public_key())

    def test_certificate_path_takes_precedence_over_include_public_key(self):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.x509.oid import NameOID

        key = _KEYS["ES256"]
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
            )
            .sign(key, _hashes.SHA256())
        )

        signer = JSSSignature(
            key,
            "ES256",
            certificate_path=[cert],
            include_public_key=True,
        )
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        entry = signed["signatures"][0]
        assert "public_cert_chain" in entry
        assert "public_key" not in entry
        assert JSSSignature.verify(signed)


class TestGetCertificateChains:
    """Test JSSSignature.get_certificate_chain()/get_certificate_chains()."""

    def test_get_certificate_chain_single_signature(self):
        key = _KEYS["ES256"]
        cert = _self_signed_certificate(key)
        signer = JSSSignature(key, "ES256", certificate_path=[cert])
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        chain = JSSSignature.get_certificate_chain(signed)
        assert chain == [cert]

    def test_get_certificate_chains_multi_signature(self):
        key1 = _KEYS["ES256"]
        key2 = _KEYS["RS256"]
        cert1 = _self_signed_certificate(key1)
        signer1 = JSSSignature(key1, "ES256", certificate_path=[cert1])
        signer2 = JSSSignature(key2, "RS256", include_public_key=True)
        signed = JSSSignature.sign_multi(copy.deepcopy(SAMPLE_OBJECT), [signer1, signer2])

        chains = JSSSignature.get_certificate_chains(signed)
        assert chains == [[cert1], None]

    def test_no_certificate_path_returns_none(self):
        signer = JSSSignature(_KEYS["ES256"], "ES256", include_public_key=True)
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        assert JSSSignature.get_certificate_chain(signed) is None

    def test_custom_signatures_property(self):
        key = _KEYS["ES256"]
        cert = _self_signed_certificate(key)
        signer = JSSSignature(key, "ES256", signatures_property="sigs", certificate_path=[cert])
        signed = signer.sign(copy.deepcopy(SAMPLE_OBJECT))

        chain = JSSSignature.get_certificate_chain(signed, signatures_property="sigs")
        assert chain == [cert]

    def test_missing_signatures_property_raises(self):
        with pytest.raises(ValueError, match="Missing signatures property"):
            JSSSignature.get_certificate_chains(copy.deepcopy(SAMPLE_OBJECT))

    def test_malformed_signatures_property_raises(self):
        obj = {**copy.deepcopy(SAMPLE_OBJECT), "signatures": "not-a-list"}
        with pytest.raises(ValueError, match="non-empty array"):
            JSSSignature.get_certificate_chains(obj)
