#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Tests for `pyjsign.vault_signer.VaultTransitSigner`, using a mocked
`hvac.Client` (no real Vault server involved). The mock performs real
cryptographic signing with a locally generated key, in order to
mimic real Vault Transit responses closely enough that the resulting
JSF signatures are genuinely valid and can be checked with
`JSFSignature.verify()`.
"""

import base64

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pyjsign.jsf import JSFSignature
from pyjsign.vault_signer import VaultTransitSigner, build_vault_client

_HASH_ALGORITHMS = {
    "sha2-256": hashes.SHA256(),
    "sha2-384": hashes.SHA384(),
    "sha2-512": hashes.SHA512(),
}


class FakeTransit:
    """
    Stand-in for `hvac.Client(...).secrets.transit`, backed by a real
    local private key so it produces genuinely valid signatures/public
    keys shaped like Vault's actual Transit API responses.
    """

    def __init__(self, private_key, vault_key_type, version=1):
        self.private_key = private_key
        self.vault_key_type = vault_key_type
        self.version = version

    def read_key(self, name, mount_point="transit"):
        public_key = self.private_key.public_key()
        if self.vault_key_type == "ed25519":
            raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            public_key_field = base64.b64encode(raw).decode("ascii")
        else:
            public_key_field = public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

        return {
            "data": {
                "name": name,
                "type": self.vault_key_type,
                "latest_version": self.version,
                "keys": {
                    str(self.version): {
                        "public_key": public_key_field,
                        "creation_time": "2024-01-01T00:00:00Z",
                    }
                },
            }
        }

    def sign_data(
        self,
        name,
        hash_input,
        hash_algorithm=None,
        signature_algorithm=None,
        marshaling_algorithm=None,
        key_version=None,
        mount_point="transit",
    ):
        data = base64.b64decode(hash_input)

        if self.vault_key_type.startswith("ecdsa"):
            hash_alg = _HASH_ALGORITHMS[hash_algorithm]
            der_sig = self.private_key.sign(data, ec.ECDSA(hash_alg))
            r, s = decode_dss_signature(der_sig)
            curve_order = (self.private_key.curve.key_size + 7) // 8
            sig_bytes = r.to_bytes(curve_order, "big") + s.to_bytes(curve_order, "big")
        elif self.vault_key_type.startswith("rsa"):
            hash_alg = _HASH_ALGORITHMS[hash_algorithm]
            if signature_algorithm == "pss":
                rsa_padding = padding.PSS(
                    mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                rsa_padding = padding.PKCS1v15()
            sig_bytes = self.private_key.sign(data, rsa_padding, hash_alg)
        elif self.vault_key_type == "ed25519":
            sig_bytes = self.private_key.sign(data)
        else:
            raise AssertionError(f"Unsupported fake vault key type: {self.vault_key_type}")

        # Mimic Vault's "jws" marshaling: unpadded base64url encoding.
        encoded = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
        return {"data": {"signature": f"vault:v{self.version}:{encoded}"}}


class FakeSecrets:
    def __init__(self, transit):
        self.transit = transit


class FakeVaultClient:
    def __init__(self, transit):
        self.secrets = FakeSecrets(transit)


@pytest.fixture
def ec_private_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


@pytest.fixture
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


@pytest.fixture
def ed25519_private_key():
    return ed25519.Ed25519PrivateKey.generate()


class TestVaultTransitSigner:
    @pytest.mark.parametrize("algorithm", ["ES256", "ES384", "ES512"])
    def test_ecdsa_sign_and_verify(self, algorithm):
        curve = {"ES256": ec.SECP256R1(), "ES384": ec.SECP384R1(), "ES512": ec.SECP521R1()}[
            algorithm
        ]
        vault_key_type = {"ES256": "ecdsa-p256", "ES384": "ecdsa-p384", "ES512": "ecdsa-p521"}[
            algorithm
        ]
        private_key = ec.generate_private_key(curve, default_backend())
        client = FakeVaultClient(FakeTransit(private_key, vault_key_type))
        vault_signer = VaultTransitSigner(client, "my-ec-key")

        public_key = vault_signer.public_key(algorithm)
        signer = JSFSignature(public_key, algorithm, signer=vault_signer)

        signed = signer.sign({"hello": "world"})

        verifier = JSFSignature(public_key, algorithm)
        assert verifier.verify(signed)

    @pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
    def test_rsa_sign_and_verify(self, rsa_private_key, algorithm):
        client = FakeVaultClient(FakeTransit(rsa_private_key, "rsa-2048"))
        vault_signer = VaultTransitSigner(client, "my-rsa-key")

        public_key = vault_signer.public_key(algorithm)
        signer = JSFSignature(public_key, algorithm, signer=vault_signer)

        signed = signer.sign({"hello": "world"})

        verifier = JSFSignature(public_key, algorithm)
        assert verifier.verify(signed)

    @pytest.mark.parametrize("algorithm", ["Ed25519", "EdDSA"])
    def test_ed25519_sign_and_verify(self, ed25519_private_key, algorithm):
        client = FakeVaultClient(FakeTransit(ed25519_private_key, "ed25519"))
        vault_signer = VaultTransitSigner(client, "my-ed25519-key")

        public_key = vault_signer.public_key(algorithm)
        signer = JSFSignature(public_key, algorithm, signer=vault_signer)

        signed = signer.sign({"hello": "world"})

        verifier = JSFSignature(public_key, algorithm)
        assert verifier.verify(signed)

    def test_public_key_rejects_incompatible_vault_key_type(self, rsa_private_key):
        client = FakeVaultClient(FakeTransit(rsa_private_key, "rsa-2048"))
        vault_signer = VaultTransitSigner(client, "my-rsa-key")

        with pytest.raises(ValueError, match="incompatible"):
            vault_signer.public_key("ES256")

    def test_public_key_rejects_unsupported_algorithm(self, ec_private_key):
        client = FakeVaultClient(FakeTransit(ec_private_key, "ecdsa-p256"))
        vault_signer = VaultTransitSigner(client, "my-ec-key")

        with pytest.raises(ValueError, match="not supported"):
            vault_signer.public_key("HS256")

    def test_sign_rejects_unsupported_algorithm(self, ec_private_key):
        client = FakeVaultClient(FakeTransit(ec_private_key, "ecdsa-p256"))
        vault_signer = VaultTransitSigner(client, "my-ec-key")

        with pytest.raises(ValueError, match="not supported"):
            vault_signer.sign("HS256", b"data")

    def test_public_key_missing_version_raises(self, ec_private_key):
        client = FakeVaultClient(FakeTransit(ec_private_key, "ecdsa-p256"))
        vault_signer = VaultTransitSigner(client, "my-ec-key", key_version=2)

        with pytest.raises(ValueError, match="no version"):
            vault_signer.public_key("ES256")


class TestBuildVaultClient:
    def test_missing_addr_raises(self, monkeypatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        with pytest.raises(ValueError, match="address"):
            build_vault_client()

    def test_missing_token_raises(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        with pytest.raises(ValueError, match="token"):
            build_vault_client()

    def test_builds_client_from_env(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        client = build_vault_client()
        assert client.url == "http://127.0.0.1:8200"

    def test_builds_client_from_args(self, monkeypatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        client = build_vault_client(vault_addr="http://vault.example.com", vault_token="tok")
        assert client.url == "http://vault.example.com"
