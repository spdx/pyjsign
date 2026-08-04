#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Tests for the pyjsign jss sign/verify command-line subcommands."""

import json

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from pyjsign import cli


@pytest.fixture
def ec_private_key():
    """Generate a fresh P-256 private key for testing."""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


@pytest.fixture
def ed25519_private_key():
    """Generate a fresh Ed25519 private key for testing."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def pem_file(tmp_path, ec_private_key):
    """Write an unencrypted PKCS8 PEM private-key file (EC) and return its path."""
    pem = ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "key.pem"
    path.write_bytes(pem)
    return str(path)


@pytest.fixture
def ed25519_pem_file(tmp_path, ed25519_private_key):
    """Write an unencrypted PKCS8 PEM private-key file (Ed25519) and return its path."""
    pem = ed25519_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "ed25519_key.pem"
    path.write_bytes(pem)
    return str(path)


def _self_signed_certificate_pem(private_key) -> bytes:
    """Build a self-signed certificate (PEM-encoded) for `private_key`."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyjsign-cli-jss-test")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


@pytest.fixture
def cert_file(tmp_path, ec_private_key):
    """Write a self-signed PEM certificate for `ec_private_key` and return its path."""
    path = tmp_path / "cert.pem"
    path.write_bytes(_self_signed_certificate_pem(ec_private_key))
    return str(path)


@pytest.fixture
def jwk_file(tmp_path, ec_private_key):
    """Write a JWK private-key JSON file (EC) and return its path."""
    from pyjsign.jwk_handler import JWKHandler

    jwk = JWKHandler.to_jwk(ec_private_key)
    path = tmp_path / "key.jwk"
    path.write_text(json.dumps(jwk.as_dict(private=True)))
    return str(path)


@pytest.fixture
def data_file(tmp_path):
    """Write a plain JSON document to sign and return its path."""
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"hello": "world", "id": 42}))
    return str(path)


class TestSignJssCommand:
    def test_sign_to_stdout(self, data_file, pem_file, capsys):
        rc = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["hello"] == "world"
        entry = signed["signatures"][0]
        assert entry["algorithm"] == "ES256"
        assert entry["hash_algorithm"] == "sha-256"
        assert "public_key" in entry
        assert "value" in entry

    def test_sign_to_output_file(self, data_file, pem_file, tmp_path):
        output = tmp_path / "signed.json"
        rc = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e", "-o", str(output)])

        assert rc == 0
        signed = json.loads(output.read_text())
        assert signed["signatures"][0]["algorithm"] == "ES256"

    def test_sign_with_custom_hash_algorithm(self, data_file, pem_file, capsys):
        rc = cli.main(
            ["jss", "sign", data_file, "-k", pem_file, "ES384", "-e", "--hash-algorithm", "sha-384"]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signatures"][0]["hash_algorithm"] == "sha-384"

    def test_sign_with_custom_property_name(self, data_file, pem_file, capsys):
        rc = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e", "-p", "sigs"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "sigs" in signed
        assert "signatures" not in signed

    def test_sign_with_certificate(self, data_file, pem_file, cert_file, capsys):
        rc = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        entry = signed["signatures"][0]
        assert "public_cert_chain" in entry
        assert "public_key" not in entry

    def test_sign_multi(self, data_file, pem_file, ed25519_pem_file, capsys):
        rc = cli.main(
            [
                "jss",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-e",
                "-k",
                ed25519_pem_file,
                "Ed25519",
                "-e",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert len(signed["signatures"]) == 2
        assert [e["algorithm"] for e in signed["signatures"]] == ["ES256", "Ed25519"]

    def test_sign_requires_key(self, data_file, capsys):
        rc = cli.main(["jss", "sign", data_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "must be provided" in captured.err

    def test_sign_without_key_locator_fails(self, data_file, pem_file, capsys):
        rc = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "self-describing" in captured.err

    def test_sign_with_jwk_to_stdout(self, data_file, jwk_file, capsys):
        # Regression test: -j/--jwk previously passed the unconverted joserfc
        # key object to JSSSignature, which only accepts cryptography keys,
        # raising "Unsupported key type".
        rc = cli.main(["jss", "sign", data_file, "-j", jwk_file, "ES256", "-e"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        entry = signed["signatures"][0]
        assert entry["algorithm"] == "ES256"
        assert "public_key" in entry


class TestVerifyJssCommand:
    def test_verify_valid_signature(self, data_file, pem_file, capsys):
        cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e", "-o", data_file])
        capsys.readouterr()

        rc = cli.main(["jss", "verify", data_file])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out

    def test_verify_tampered_signature_fails(self, data_file, pem_file):
        cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e", "-o", data_file])

        signed = json.loads(open(data_file).read())
        signed["hello"] = "tampered"
        with open(data_file, "w") as f:
            json.dump(signed, f)

        rc = cli.main(["jss", "verify", data_file])
        assert rc == 1

    def test_verify_multi_signature(self, data_file, pem_file, ed25519_pem_file):
        cli.main(
            [
                "jss",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-e",
                "-k",
                ed25519_pem_file,
                "Ed25519",
                "-e",
                "-o",
                data_file,
            ]
        )

        rc = cli.main(["jss", "verify", data_file])
        assert rc == 0

    def test_verify_with_custom_property_name(self, data_file, pem_file):
        cli.main(
            ["jss", "sign", data_file, "-k", pem_file, "ES256", "-e", "-p", "sigs", "-o", data_file]
        )

        rc = cli.main(["jss", "verify", data_file, "-p", "sigs"])
        assert rc == 0

    def test_verify_missing_signatures_fails(self, data_file):
        rc = cli.main(["jss", "verify", data_file])
        assert rc == 1
