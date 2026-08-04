#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Tests for the pyjsign command-line interface."""

import json
import subprocess
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pyjsign import cli
from pyjsign.jwk_handler import JWKHandler


@pytest.fixture
def ec_private_key():
    """Generate a fresh P-256 private key for testing."""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


@pytest.fixture
def rsa_private_key():
    """Generate a fresh RSA private key for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


@pytest.fixture
def jwk_file(tmp_path, ec_private_key):
    """Write a private-key JWK (JSON) file (EC) and return its path."""
    jwk = JWKHandler.to_jwk(ec_private_key)
    path = tmp_path / "key.jwk"
    path.write_text(json.dumps(jwk.as_dict(private=True)))
    return str(path)


@pytest.fixture
def rsa_jwk_file(tmp_path, rsa_private_key):
    """Write a private-key JWK (JSON) file (RSA) and return its path."""
    jwk = JWKHandler.to_jwk(rsa_private_key)
    path = tmp_path / "rsa_key.jwk"
    path.write_text(json.dumps(jwk.as_dict(private=True)))
    return str(path)


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
def rsa_pem_file(tmp_path, rsa_private_key):
    """Write an unencrypted PKCS8 PEM private-key file (RSA) and return its path."""
    pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "rsa_key.pem"
    path.write_bytes(pem)
    return str(path)


def _self_signed_certificate_pem(private_key) -> bytes:
    """Build a self-signed certificate (PEM-encoded) for `private_key`."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyjsign-cli-test")])
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
def rsa_cert_file(tmp_path, rsa_private_key):
    """Write a self-signed PEM certificate for `rsa_private_key` and return its path."""
    path = tmp_path / "rsa_cert.pem"
    path.write_bytes(_self_signed_certificate_pem(rsa_private_key))
    return str(path)


@pytest.fixture
def data_file(tmp_path):
    """Write a plain JSON document to sign and return its path."""
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"hello": "world", "id": 42}))
    return str(path)


class TestInvocation:
    def test_command(self):
        subprocess.run(["pyjsign", "--version"], check=True)

    def test_run_as_module(self):
        subprocess.run([sys.executable, "-m", "pyjsign", "--version"], check=True)


class TestAliasCommands:
    def test_pyjsf_command_installed(self):
        subprocess.run(["pyjsf", "--help"], check=True, capture_output=True)

    def test_pyjss_command_installed(self):
        subprocess.run(["pyjss", "--help"], check=True, capture_output=True)

    def test_main_jsf_matches_pyjsign_jsf(self, data_file, jwk_file, capsys):
        rc = cli.main_jsf(["sign", data_file, "-j", jwk_file, "ES256"])
        jsf_out = capsys.readouterr().out

        rc_direct = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256"])
        direct_out = capsys.readouterr().out

        assert rc == 0 and rc_direct == 0
        assert json.loads(jsf_out)["hello"] == "world"
        assert json.loads(direct_out)["hello"] == "world"

    def test_main_jss_matches_pyjsign_jss(self, data_file, pem_file, capsys):
        rc = cli.main_jss(["sign", data_file, "-k", pem_file, "ES256", "-e"])
        jss_out = capsys.readouterr().out

        rc_direct = cli.main(["jss", "sign", data_file, "-k", pem_file, "ES256", "-e"])
        direct_out = capsys.readouterr().out

        assert rc == 0 and rc_direct == 0
        assert json.loads(jss_out)["hello"] == "world"
        assert json.loads(direct_out)["hello"] == "world"

    def test_main_jsf_no_subcommand_errors(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main_jsf([])
        assert exc_info.value.code == 2

    def test_main_jss_no_subcommand_errors(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main_jss([])
        assert exc_info.value.code == 2


class TestListAlgorithms:
    def test_list_algorithms_success(self, capsys):
        rc = cli.main(["list-algorithms"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "Supported algorithms:" in captured.out
        assert "ES256" in captured.out
        assert "RS256" in captured.out
        assert "HS256" in captured.out


class TestNoCommand:
    def test_no_command_prints_help_and_fails(self, capsys):
        rc = cli.main([])
        captured = capsys.readouterr()

        assert rc == 1
        assert "usage" in captured.out.lower()


class TestSignCommand:
    def test_sign_with_jwk_to_stdout(self, data_file, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["hello"] == "world"
        assert signed["signature"]["algorithm"] == "ES256"
        assert "value" in signed["signature"]

    def test_sign_with_jwk_to_output_file(self, data_file, jwk_file, tmp_path):
        output = tmp_path / "signed.json"
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256", "-o", str(output)])

        assert rc == 0
        signed = json.loads(output.read_text())
        assert signed["signature"]["algorithm"] == "ES256"

    def test_sign_with_pem_key(self, data_file, pem_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-k", pem_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["algorithm"] == "ES256"

    def test_sign_with_same_input_and_output_file(self, data_file, pem_file):
        # Signing in-place must not truncate the input before it's fully read.
        original = json.loads(open(data_file).read())
        rc = cli.main(["jsf", "sign", data_file, "-k", pem_file, "ES256", "-o", data_file])

        assert rc == 0
        signed = json.loads(open(data_file).read())
        assert signed["signature"]["algorithm"] == "ES256"
        for key, value in original.items():
            assert signed[key] == value

    def test_sign_with_custom_property_name(self, data_file, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256", "-p", "sig"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "sig" in signed
        assert "signature" not in signed

    def test_sign_with_exclude(self, tmp_path, jwk_file, capsys):
        data = tmp_path / "data.json"
        data.write_text(json.dumps({"mySignedData": "something", "myUnsignedData": "else"}))

        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-x", "myUnsignedData"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["excludes"] == ["myUnsignedData"]

    def test_sign_with_multiple_excludes(self, tmp_path, jwk_file, capsys):
        data = tmp_path / "data.json"
        data.write_text(json.dumps({"a": 1, "b": 2, "c": 3}))

        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-x", "b", "-x", "c"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["excludes"] == ["b", "c"]

    def test_sign_with_extension(self, tmp_path, jwk_file, capsys):
        data = tmp_path / "data.json"
        data.write_text(json.dumps({"data": "test"}))

        rc = cli.main(
            [
                "jsf",
                "sign",
                str(data),
                "-j",
                jwk_file,
                "ES256",
                "--extension",
                "otherExt",
                '"Cool Stuff"',
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["extensions"] == ["otherExt"]
        assert signed["signature"]["otherExt"] == "Cool Stuff"

    def test_sign_with_multiple_extensions_and_non_json_value(self, tmp_path, jwk_file, capsys):
        data = tmp_path / "data.json"
        data.write_text(json.dumps({"data": "test"}))

        rc = cli.main(
            [
                "jsf",
                "sign",
                str(data),
                "-j",
                jwk_file,
                "ES256",
                "--extension",
                "otherExt",
                "Cool Stuff",
                "--extension",
                "flag",
                "true",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["extensions"] == ["otherExt", "flag"]
        # Not valid JSON on its own, so kept as a raw string
        assert signed["signature"]["otherExt"] == "Cool Stuff"
        # Valid JSON, so parsed to a real boolean
        assert signed["signature"]["flag"] is True

    def test_sign_reads_from_stdin(self, jwk_file, capsys, monkeypatch):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hello": "world"})))
        rc = cli.main(["jsf", "sign", "-", "-j", jwk_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["hello"] == "world"
        assert signed["signature"]["algorithm"] == "ES256"

    def test_sign_stdin_invalid_json_fails(self, jwk_file, capsys, monkeypatch):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
        rc = cli.main(["jsf", "sign", "-", "-j", jwk_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Invalid JSON on stdin" in captured.err

    def test_sign_missing_key_and_jwk(self, data_file, capsys):
        rc = cli.main(["jsf", "sign", data_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "--key, --jwk, or --vault-key" in captured.err

    def test_sign_incompatible_algorithm(self, data_file, jwk_file, capsys):
        # jwk_file is an EC key; RS256 requires an RSA key.
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "RS256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error" in captured.err

    def test_sign_unknown_algorithm(self, data_file, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "BOGUS123"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error" in captured.err

    def test_sign_missing_input_file(self, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", "/nonexistent/file.json", "-j", jwk_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "not found" in captured.err.lower()

    def test_sign_missing_jwk_file(self, data_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", "/nonexistent/key.jwk", "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "not found" in captured.err.lower()

    def test_sign_invalid_json_input(self, tmp_path, jwk_file, capsys):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not json")

        rc = cli.main(["jsf", "sign", str(bad_file), "-j", jwk_file, "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error" in captured.err

    def test_sign_multi_with_two_keys(self, data_file, jwk_file, rsa_jwk_file, capsys):
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-j",
                jwk_file,
                "ES256",
                "-j",
                rsa_jwk_file,
                "RS256",
                "--multi",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "signers" in signed["signature"]
        assert len(signed["signature"]["signers"]) == 2
        assert [s["algorithm"] for s in signed["signature"]["signers"]] == ["ES256", "RS256"]

    def test_sign_multi_with_exclude(self, tmp_path, jwk_file, rsa_jwk_file, capsys):
        data = tmp_path / "data.json"
        data.write_text(json.dumps({"mySignedData": "something", "myUnsignedData": "else"}))

        rc = cli.main(
            [
                "jsf",
                "sign",
                str(data),
                "-j",
                jwk_file,
                "ES256",
                "-j",
                rsa_jwk_file,
                "RS256",
                "--multi",
                "-x",
                "myUnsignedData",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        for entry in signed["signature"]["signers"]:
            assert entry["excludes"] == ["myUnsignedData"]

    def test_sign_chain_with_mixed_key_and_jwk(self, data_file, pem_file, rsa_jwk_file, capsys):
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-j",
                rsa_jwk_file,
                "RS256",
                "--chain",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "chain" in signed["signature"]
        assert len(signed["signature"]["chain"]) == 2
        assert [s["algorithm"] for s in signed["signature"]["chain"]] == ["ES256", "RS256"]

    def test_sign_single_key_with_multi_flag_wraps_as_multisig(self, data_file, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256", "--multi"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "signers" in signed["signature"]
        assert len(signed["signature"]["signers"]) == 1

    def test_sign_single_key_with_chain_flag_wraps_as_chain(self, data_file, jwk_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256", "--chain"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "chain" in signed["signature"]
        assert len(signed["signature"]["chain"]) == 1

    def test_sign_multiple_keys_without_mode_flag_fails(
        self, data_file, jwk_file, rsa_jwk_file, capsys
    ):
        rc = cli.main(
            ["jsf", "sign", data_file, "-j", jwk_file, "ES256", "-j", rsa_jwk_file, "RS256"]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "--multi or --chain" in captured.err

    def test_sign_multi_and_chain_together_is_argparse_error(self, data_file, jwk_file, capsys):
        with pytest.raises(SystemExit):
            cli.main(["jsf", "sign", data_file, "-j", jwk_file, "ES256", "--multi", "--chain"])


class TestSignCommandCertificate:
    def test_sign_with_cert_embeds_certificate_path(self, data_file, pem_file, cert_file, capsys):
        rc = cli.main(["jsf", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "certificatePath" in signed["signature"]
        assert len(signed["signature"]["certificatePath"]) == 1
        assert "publicKey" not in signed["signature"]

    def test_sign_with_cert_verifies_via_embedded_key(
        self, data_file, pem_file, cert_file, tmp_path, capsys
    ):
        output = tmp_path / "signed.json"
        rc = cli.main(
            ["jsf", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file, "-o", str(output)]
        )
        assert rc == 0

        rc = cli.main(["jsf", "verify", str(output), "--use-embedded-key"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "valid" in captured.out

    def test_sign_multi_with_paired_certs(
        self, data_file, pem_file, cert_file, rsa_pem_file, rsa_cert_file, tmp_path
    ):
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-c",
                cert_file,
                "-k",
                rsa_pem_file,
                "RS256",
                "-c",
                rsa_cert_file,
                "--multi",
                "-o",
                str(output),
            ]
        )

        assert rc == 0
        signed = json.loads(output.read_text())
        entries = signed["signature"]["signers"]
        assert "certificatePath" in entries[0]
        assert "certificatePath" in entries[1]

        rc = cli.main(["jsf", "verify", str(output), "--multi", "--use-embedded-key"])
        assert rc == 0

    def test_sign_multi_with_placeholder_skips_signer_certificate(
        self, data_file, pem_file, cert_file, rsa_pem_file, tmp_path
    ):
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-c",
                cert_file,
                "-k",
                rsa_pem_file,
                "RS256",
                "-c",
                "-",
                "--multi",
                "-o",
                str(output),
            ]
        )

        assert rc == 0
        signed = json.loads(output.read_text())
        entries = signed["signature"]["signers"]
        assert "certificatePath" in entries[0]
        assert "certificatePath" not in entries[1]

    def test_sign_cert_count_mismatch_errors(
        self, data_file, pem_file, cert_file, rsa_pem_file, capsys
    ):
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-c",
                cert_file,
                "-k",
                rsa_pem_file,
                "RS256",
                "--multi",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "--cert must be given once per --key/--jwk" in captured.err

    def test_sign_cert_takes_precedence_over_embed_public_key(
        self, data_file, pem_file, cert_file, tmp_path
    ):
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-c",
                cert_file,
                "-e",
                "-o",
                str(output),
            ]
        )
        assert rc == 0

        signed = json.loads(output.read_text())
        assert "certificatePath" in signed["signature"]
        assert "publicKey" not in signed["signature"]

    def test_sign_cert_missing_file_errors(self, data_file, pem_file, capsys):
        rc = cli.main(
            ["jsf", "sign", data_file, "-k", pem_file, "ES256", "-c", "/nonexistent/cert.pem"]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "Certificate file not found" in captured.err


class TestVerifyCommand:
    def _sign(self, data_file, jwk_file, tmp_path, property_name="signature"):
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-j",
                jwk_file,
                "ES256",
                "-o",
                str(output),
                "-p",
                property_name,
            ]
        )
        assert rc == 0
        return output

    def _sign_with_embedded_key(self, data_file, jwk_file, tmp_path, property_name="signature"):
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-j",
                jwk_file,
                "ES256",
                "-o",
                str(output),
                "-p",
                property_name,
                "-e",
            ]
        )
        assert rc == 0
        return output

    def _sign_multi(self, data_file, jwk_file, rsa_jwk_file, tmp_path, embed=False):
        output = tmp_path / "signed_multi.json"
        args = [
            "jsf",
            "sign",
            data_file,
            "-j",
            jwk_file,
            "ES256",
            "-j",
            rsa_jwk_file,
            "RS256",
            "--multi",
        ]
        if embed:
            args.append("-e")
        args += ["-o", str(output)]
        rc = cli.main(args)
        assert rc == 0
        return output

    def _sign_chain(self, data_file, jwk_file, rsa_jwk_file, tmp_path, embed=False):
        output = tmp_path / "signed_chain.json"
        args = [
            "jsf",
            "sign",
            data_file,
            "-j",
            jwk_file,
            "ES256",
            "-j",
            rsa_jwk_file,
            "RS256",
            "--chain",
        ]
        if embed:
            args.append("-e")
        args += ["-o", str(output)]
        rc = cli.main(args)
        assert rc == 0
        return output

    def test_verify_valid_signature_with_jwk(self, data_file, jwk_file, tmp_path, capsys):
        signed = self._sign(data_file, jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_reads_from_stdin(self, data_file, jwk_file, tmp_path, capsys, monkeypatch):
        import io

        signed = self._sign(data_file, jwk_file, tmp_path)
        monkeypatch.setattr("sys.stdin", io.StringIO(signed.read_text()))
        rc = cli.main(["jsf", "verify", "-", "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_valid_signature_with_pem(self, data_file, jwk_file, pem_file, tmp_path, capsys):
        signed = self._sign(data_file, jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-k", pem_file])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_custom_property_name(self, data_file, jwk_file, tmp_path, capsys):
        signed = self._sign(data_file, jwk_file, tmp_path, property_name="sig")

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-p", "sig"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def _sign_with_excludes(self, jwk_file, tmp_path, excludes):
        data = tmp_path / "excl_data.json"
        data.write_text(json.dumps({"mySignedData": "something", "myUnsignedData": "else"}))
        output = tmp_path / "excl_signed.json"
        args = ["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-o", str(output)]
        for name in excludes:
            args += ["-x", name]
        rc = cli.main(args)
        assert rc == 0
        return output

    def test_verify_with_excludes_requires_allow_exclude(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_excludes(jwk_file, tmp_path, ["myUnsignedData"])

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "allowed_excludes" in captured.err

    def test_verify_with_allow_exclude_succeeds(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_excludes(jwk_file, tmp_path, ["myUnsignedData"])

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-x", "myUnsignedData"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_with_allow_exclude_rejects_unlisted_name(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_excludes(jwk_file, tmp_path, ["myUnsignedData"])

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-x", "someOtherProperty"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "not permitted" in captured.err

    def _sign_with_extensions(self, jwk_file, tmp_path, extension_specs):
        data = tmp_path / "ext_data.json"
        data.write_text(json.dumps({"data": "test"}))
        output = tmp_path / "ext_signed.json"
        args = ["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-o", str(output)]
        for name, value in extension_specs:
            args += ["--extension", name, value]
        rc = cli.main(args)
        assert rc == 0
        return output

    def test_verify_with_extension_succeeds_by_default(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_extensions(jwk_file, tmp_path, [("otherExt", "Cool Stuff")])

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_with_known_extension_succeeds(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_extensions(jwk_file, tmp_path, [("otherExt", "Cool Stuff")])

        rc = cli.main(
            ["jsf", "verify", str(signed), "-j", jwk_file, "--known-extension", "otherExt"]
        )
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_with_known_extension_rejects_unlisted_name(self, jwk_file, tmp_path, capsys):
        signed = self._sign_with_extensions(jwk_file, tmp_path, [("otherExt", "Cool Stuff")])

        rc = cli.main(
            ["jsf", "verify", str(signed), "-j", jwk_file, "--known-extension", "someOtherExt"]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "not permitted" in captured.err

    def test_verify_excluded_property_can_change(self, tmp_path, jwk_file, capsys):
        signed_path = self._sign_with_excludes(jwk_file, tmp_path, ["myUnsignedData"])

        signed = json.loads(signed_path.read_text())
        signed["myUnsignedData"] = "a different value"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(["jsf", "verify", str(signed_path), "-j", jwk_file, "-x", "myUnsignedData"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_tampered_object_fails(self, data_file, jwk_file, tmp_path, capsys):
        signed_path = self._sign(data_file, jwk_file, tmp_path)

        signed = json.loads(signed_path.read_text())
        signed["hello"] = "tampered"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(["jsf", "verify", str(signed_path), "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "invalid" in captured.err.lower()

    def test_verify_missing_key_and_jwk(self, data_file, jwk_file, tmp_path, capsys):
        signed = self._sign(data_file, jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed)])
        captured = capsys.readouterr()

        assert rc == 1
        assert "--key" in captured.err and "--jwk" in captured.err

    def test_verify_with_embedded_public_key(self, data_file, jwk_file, tmp_path, capsys):
        signed = self._sign_with_embedded_key(data_file, jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-e"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_with_embedded_public_key_custom_property(
        self, data_file, jwk_file, tmp_path, capsys
    ):
        signed = self._sign_with_embedded_key(data_file, jwk_file, tmp_path, property_name="sig")

        rc = cli.main(["jsf", "verify", str(signed), "-e", "-p", "sig"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_embedded_key_rejects_tampered_object(
        self, data_file, jwk_file, tmp_path, capsys
    ):
        signed_path = self._sign_with_embedded_key(data_file, jwk_file, tmp_path)

        signed = json.loads(signed_path.read_text())
        signed["hello"] = "tampered"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(["jsf", "verify", str(signed_path), "-e"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "invalid" in captured.err.lower()

    def test_verify_embedded_key_without_embedded_key_present_fails(
        self, data_file, jwk_file, tmp_path, capsys
    ):
        signed = self._sign(data_file, jwk_file, tmp_path)  # no -e, no embedded key

        rc = cli.main(["jsf", "verify", str(signed), "-e"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error" in captured.err

    def test_verify_use_embedded_key_conflicts_with_key_arg(
        self, data_file, jwk_file, pem_file, tmp_path, capsys
    ):
        signed = self._sign_with_embedded_key(data_file, jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-e", "-k", pem_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "cannot be combined" in captured.err

    def test_verify_missing_signature_property(self, tmp_path, jwk_file, capsys):
        unsigned = tmp_path / "unsigned.json"
        unsigned.write_text(json.dumps({"hello": "world"}))

        rc = cli.main(["jsf", "verify", str(unsigned), "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error" in captured.err

    def test_verify_missing_input_file(self, jwk_file, capsys):
        rc = cli.main(["jsf", "verify", "/nonexistent/signed.json", "-j", jwk_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "not found" in captured.err.lower()

    def test_verify_multi_with_explicit_keys(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_multi(data_file, jwk_file, rsa_jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-j", rsa_jwk_file, "--multi"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_multi_tampered_fails(self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys):
        signed_path = self._sign_multi(data_file, jwk_file, rsa_jwk_file, tmp_path)

        signed = json.loads(signed_path.read_text())
        signed["hello"] = "tampered"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(
            ["jsf", "verify", str(signed_path), "-j", jwk_file, "-j", rsa_jwk_file, "--multi"]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "invalid" in captured.err.lower()

    def test_verify_multi_with_embedded_keys_auto_detect(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_multi(data_file, jwk_file, rsa_jwk_file, tmp_path, embed=True)

        rc = cli.main(["jsf", "verify", str(signed), "--use-embedded-key"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_multi_with_embedded_keys_explicit_flag(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_multi(data_file, jwk_file, rsa_jwk_file, tmp_path, embed=True)

        rc = cli.main(["jsf", "verify", str(signed), "--use-embedded-key", "--multi"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_chain_with_explicit_keys(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_chain(data_file, jwk_file, rsa_jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-j", rsa_jwk_file, "--chain"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_chain_tampered_fails(self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys):
        signed_path = self._sign_chain(data_file, jwk_file, rsa_jwk_file, tmp_path)

        signed = json.loads(signed_path.read_text())
        signed["hello"] = "tampered"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(
            ["jsf", "verify", str(signed_path), "-j", jwk_file, "-j", rsa_jwk_file, "--chain"]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "invalid" in captured.err.lower()

    def test_verify_chain_with_embedded_keys_auto_detect(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_chain(data_file, jwk_file, rsa_jwk_file, tmp_path, embed=True)

        rc = cli.main(["jsf", "verify", str(signed), "--use-embedded-key"])
        captured = capsys.readouterr()

        assert rc == 0
        assert "valid" in captured.out.lower()

    def test_verify_multiple_keys_without_mode_flag_fails(
        self, data_file, jwk_file, rsa_jwk_file, tmp_path, capsys
    ):
        signed = self._sign_multi(data_file, jwk_file, rsa_jwk_file, tmp_path)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-j", rsa_jwk_file])
        captured = capsys.readouterr()

        assert rc == 1
        assert "--multi or --chain" in captured.err

    def test_verify_single_key_with_multi_flag_wraps_as_multisig(
        self, data_file, jwk_file, tmp_path, capsys
    ):
        signed = self._sign(data_file, jwk_file, tmp_path)  # plain single-signature doc

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "--multi"])
        captured = capsys.readouterr()

        # A plain single-signature document has no "signers" array, so
        # verify_multi() must reject it even though only one key was given.
        assert rc == 1
        assert "Error" in captured.err


class TestArgparseWiring:
    def test_sign_requires_file_argument(self):
        with pytest.raises(SystemExit):
            cli.main(["jsf", "sign", "-j", "key.jwk", "ES256"])

    def test_sign_key_requires_two_values(self):
        with pytest.raises(SystemExit):
            cli.main(["jsf", "sign", "somefile.json", "-j", "key.jwk"])

    def test_unknown_command(self):
        with pytest.raises(SystemExit):
            cli.main(["bogus-command"])


class TestJsonPath:
    """Test -P/--json-path support: sign/verify a subset of the document."""

    def _data(self, tmp_path):
        data = tmp_path / "data.json"
        data.write_text(
            json.dumps(
                {
                    "documents": [
                        {"id": 1, "value": "a"},
                        {"id": 2, "value": "b"},
                    ],
                    "meta": "unrelated",
                }
            )
        )
        return data

    def test_sign_single_match(self, tmp_path, jwk_file, capsys):
        data = self._data(tmp_path)
        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-P", "$.documents[0]"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "signature" in signed["documents"][0]
        assert "signature" not in signed["documents"][1]
        assert signed["meta"] == "unrelated"

    def test_sign_multiple_matches(self, tmp_path, jwk_file, capsys):
        data = self._data(tmp_path)
        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-P", "$.documents[*]"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "signature" in signed["documents"][0]
        assert "signature" in signed["documents"][1]
        assert (
            signed["documents"][0]["signature"]["value"]
            != signed["documents"][1]["signature"]["value"]
        )

    def test_sign_root_json_path_matches_whole_document(self, tmp_path, jwk_file, capsys):
        data = tmp_path / "root.json"
        data.write_text(json.dumps({"data": "value"}))

        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-P", "$"])
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert "signature" in signed

    def test_sign_json_path_no_matches_errors(self, tmp_path, jwk_file, capsys):
        data = self._data(tmp_path)
        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-P", "$.nonexistent[*]"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "matched no objects" in captured.err

    def test_sign_json_path_non_object_match_errors(self, tmp_path, jwk_file, capsys):
        data = self._data(tmp_path)
        rc = cli.main(["jsf", "sign", str(data), "-j", jwk_file, "ES256", "-P", "$.meta"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "is not a JSON object" in captured.err

    def _sign_documents(self, tmp_path, jwk_file):
        data = self._data(tmp_path)
        output = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                str(data),
                "-j",
                jwk_file,
                "ES256",
                "-P",
                "$.documents[*]",
                "-o",
                str(output),
            ]
        )
        assert rc == 0
        return output

    def test_verify_all_matches_valid(self, tmp_path, jwk_file, capsys):
        signed = self._sign_documents(tmp_path, jwk_file)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-P", "$.documents[*]"])
        captured = capsys.readouterr()

        assert rc == 0
        assert captured.out.count("Signature is valid") == 2

    def test_verify_reports_each_match_and_fails_overall_on_one_invalid(
        self, tmp_path, jwk_file, capsys
    ):
        signed_path = self._sign_documents(tmp_path, jwk_file)

        signed = json.loads(signed_path.read_text())
        signed["documents"][1]["value"] = "tampered"
        signed_path.write_text(json.dumps(signed))

        rc = cli.main(["jsf", "verify", str(signed_path), "-j", jwk_file, "-P", "$.documents[*]"])
        captured = capsys.readouterr()

        # Both matches are still checked/reported even though one fails.
        assert "documents'][0]" in captured.out
        assert "Signature is valid" in captured.out
        assert "documents'][1]" in captured.err
        assert "Signature is invalid" in captured.err
        assert rc == 1

    def test_verify_json_path_no_matches_errors(self, tmp_path, jwk_file, capsys):
        signed = self._sign_documents(tmp_path, jwk_file)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-P", "$.nonexistent[*]"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "matched no objects" in captured.err

    def test_verify_json_path_non_object_match_errors(self, tmp_path, jwk_file, capsys):
        signed = self._sign_documents(tmp_path, jwk_file)

        rc = cli.main(["jsf", "verify", str(signed), "-j", jwk_file, "-P", "$.meta"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "is not a JSON object" in captured.err


class TestSignCommandVault:
    """
    Tests for `pyjsign jsf sign --vault-key`, backed by a mocked `hvac.Client`
    (see `tests.test_vault_signer.FakeVaultClient`/`FakeTransit`) so no
    real Vault server is involved.
    """

    @pytest.fixture
    def vault_client(self, ec_private_key):
        from tests.test_vault_signer import FakeTransit, FakeVaultClient

        return FakeVaultClient(FakeTransit(ec_private_key, "ecdsa-p256"))

    def test_sign_with_vault_key(self, data_file, vault_client, capsys, monkeypatch):
        monkeypatch.setattr("hvac.Client", lambda **kwargs: vault_client)

        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "--vault-key",
                "my-key",
                "ES256",
                "-e",
                "--vault-addr",
                "http://127.0.0.1:8200",
                "--vault-token",
                "test-token",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 0
        signed = json.loads(captured.out)
        assert signed["signature"]["algorithm"] == "ES256"
        assert "publicKey" in signed["signature"]

    def test_sign_and_verify_with_vault_key_round_trip(
        self, data_file, vault_client, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("hvac.Client", lambda **kwargs: vault_client)

        signed_path = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "--vault-key",
                "my-key",
                "ES256",
                "-e",
                "-o",
                str(signed_path),
                "--vault-addr",
                "http://127.0.0.1:8200",
                "--vault-token",
                "test-token",
            ]
        )
        assert rc == 0

        verify_rc = cli.main(["jsf", "verify", str(signed_path), "--use-embedded-key"])
        assert verify_rc == 0

    def test_sign_with_vault_key_uses_env_vars(
        self, data_file, vault_client, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("hvac.Client", lambda **kwargs: vault_client)
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        signed_path = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "--vault-key",
                "my-key",
                "ES256",
                "-e",
                "-o",
                str(signed_path),
            ]
        )
        assert rc == 0

        verify_rc = cli.main(["jsf", "verify", str(signed_path), "--use-embedded-key"])
        assert verify_rc == 0

    def test_sign_with_vault_key_missing_addr_and_token(self, data_file, capsys, monkeypatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        rc = cli.main(["jsf", "sign", data_file, "--vault-key", "my-key", "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "Error: No Vault address given" in captured.err

    def test_sign_with_vault_key_incompatible_key_type(
        self, data_file, vault_client, capsys, monkeypatch
    ):
        monkeypatch.setattr("hvac.Client", lambda **kwargs: vault_client)

        # vault_client's key is an EC key; RS256 requires an RSA key.
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "--vault-key",
                "my-key",
                "RS256",
                "--vault-addr",
                "http://127.0.0.1:8200",
                "--vault-token",
                "test-token",
            ]
        )
        captured = capsys.readouterr()

        assert rc == 1
        assert "incompatible" in captured.err

    def test_sign_with_vault_key_and_local_key_multi(
        self, data_file, vault_client, jwk_file, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("hvac.Client", lambda **kwargs: vault_client)

        signed_path = tmp_path / "signed.json"
        rc = cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-j",
                jwk_file,
                "ES256",
                "--vault-key",
                "my-key",
                "ES256",
                "--multi",
                "-e",
                "-o",
                str(signed_path),
                "--vault-addr",
                "http://127.0.0.1:8200",
                "--vault-token",
                "test-token",
            ]
        )
        assert rc == 0

        verify_rc = cli.main(["jsf", "verify", str(signed_path), "--use-embedded-key", "--multi"])
        assert verify_rc == 0

    def test_sign_with_vault_key_missing_hvac(self, data_file, capsys, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "hvac":
                raise ImportError("No module named 'hvac'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        rc = cli.main(["jsf", "sign", data_file, "--vault-key", "my-key", "ES256"])
        captured = capsys.readouterr()

        assert rc == 1
        assert "pyjsign[vault]" in captured.err


class TestCertsCommand:
    def test_extract_jsf_certificate(self, data_file, pem_file, cert_file, capsys):
        signed_path = data_file
        rc = cli.main(
            ["jsf", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file, "-o", signed_path]
        )
        assert rc == 0

        rc = cli.main(["jsf", "certs", signed_path])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Signature entry 0" in captured.out
        assert "BEGIN CERTIFICATE" in captured.out

    def test_extract_jss_certificate(self, data_file, pem_file, cert_file, capsys):
        signed_path = data_file
        rc = cli.main(
            ["jss", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file, "-o", signed_path]
        )
        assert rc == 0

        rc = cli.main(["jss", "certs", signed_path])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Signature entry 0" in captured.out
        assert "BEGIN CERTIFICATE" in captured.out

    def test_extract_to_output_file(self, data_file, pem_file, cert_file, tmp_path):
        signed_path = data_file
        cli.main(
            ["jsf", "sign", data_file, "-k", pem_file, "ES256", "-c", cert_file, "-o", signed_path]
        )

        output = tmp_path / "chains.pem"
        rc = cli.main(["jsf", "certs", signed_path, "-o", str(output)])
        assert rc == 0
        assert "BEGIN CERTIFICATE" in output.read_text()

    def test_entry_without_certificate_noted(self, data_file, pem_file, capsys):
        signed_path = data_file
        cli.main(["jsf", "sign", data_file, "-k", pem_file, "ES256", "-e", "-o", signed_path])

        rc = cli.main(["jsf", "certs", signed_path])
        captured = capsys.readouterr()
        assert rc == 0
        assert "no embedded certificate chain" in captured.out

    def test_custom_property(self, data_file, pem_file, cert_file, capsys):
        signed_path = data_file
        cli.main(
            [
                "jsf",
                "sign",
                data_file,
                "-k",
                pem_file,
                "ES256",
                "-c",
                cert_file,
                "-p",
                "sig",
                "-o",
                signed_path,
            ]
        )

        rc = cli.main(["jsf", "certs", signed_path, "-p", "sig"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "BEGIN CERTIFICATE" in captured.out

    def test_missing_signature_property_fails(self, data_file, capsys):
        rc = cli.main(["jsf", "certs", data_file])
        captured = capsys.readouterr()
        assert rc == 1
        assert "Error" in captured.err

    def test_requires_file_argument(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["jsf", "certs"])
