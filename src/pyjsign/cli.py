#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Command-line interface for pyjsign."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import joserfc.jwk
import jsonpath
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .algorithm_registry import AlgorithmRegistry
from .jsf import JSFSignature
from .jss import JSSSignature
from .vault_signer import VaultTransitSigner, build_vault_client
from .version import VERSION


class _OrderedKeyAction(argparse.Action):
    """
    Shared argparse.Action for -k/--key, -j/--jwk, and --vault-key.

    Repeated occurrences of any of these flags are appended, in true
    left-to-right command-line order, to one list stored under ``dest``
    (e.g. "keys") as ``(kind, values)`` tuples where ``kind`` is "pem",
    "jwk", or "vault" and ``values`` is whatever argparse parsed for that
    occurrence (a single string normally, or a list when ``nargs=2`` is
    used, as for ``sign``'s ``-k FILE ALGORITHM``). A plain ``action="append"``
    on each flag separately would not preserve the interleaving order
    between occurrences of different flags.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if "--vault-key" in self.option_strings:
            kind = "vault"
        elif "-k" in self.option_strings:
            kind = "pem"
        else:
            kind = "jwk"
        items = getattr(namespace, self.dest, None)
        if items is None:
            items = []
        items.append((kind, values))
        setattr(namespace, self.dest, items)


def load_key(key_file: Path, password: Optional[bytes] = None):
    """Load a private key from a PEM file."""
    if not key_file.exists():
        raise FileNotFoundError(f"Key file not found: {key_file}")

    key_data = key_file.read_bytes()

    try:
        private_key = serialization.load_pem_private_key(
            key_data, password=password, backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")


def load_jwk(jwk_file: Path):
    """
    Load a key from a JWK JSON file as a ``cryptography`` key object.

    ``JSFSignature`` accepts JWK dicts/objects directly, but ``JSSSignature``
    only accepts ``cryptography`` key objects, so this always unwraps to the
    underlying ``cryptography`` key for use with either signature format.
    """
    if not jwk_file.exists():
        raise FileNotFoundError(f"JWK file not found: {jwk_file}")

    jwk_data = json.loads(jwk_file.read_text())

    try:
        key = joserfc.jwk.import_key(jwk_data)
        return key.raw_value
    except Exception as e:
        raise ValueError(f"Failed to load JWK: {e}")


def load_key_spec(kind: str, path_str: str):
    """Load a key given a ``(kind, path)`` spec ("pem" or "jwk")."""
    path = Path(path_str)
    return load_key(path) if kind == "pem" else load_jwk(path)


def load_certificate_path(cert_file_str: str) -> list:
    """
    Load an ordered certificate chain (leaf-to-root) from a PEM file, which
    may contain one or more concatenated certificates.
    """
    cert_file = Path(cert_file_str)
    if not cert_file.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_file}")

    pem_data = cert_file.read_bytes()
    try:
        return x509.load_pem_x509_certificates(pem_data)
    except Exception as e:
        raise ValueError(f"Failed to load certificate(s) from {cert_file}: {e}")


def load_json_file(file_path) -> dict:
    """Load a JSON file, or read from stdin if ``file_path`` is "-"."""
    if str(file_path) == "-":
        try:
            data: dict = json.loads(sys.stdin.read())
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON on stdin: {e}")

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        data = json.loads(file_path.read_text())
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {file_path}: {e}")


def save_json_file(file_path: Path, data: dict) -> None:
    """Save a JSON file."""
    file_path.write_text(json.dumps(data, indent=2))


def parse_extensions(extension_specs) -> Optional[dict]:
    """
    Build an extensions dict from repeated --extension NAME VALUE pairs.

    Each VALUE is parsed as JSON if possible (so numbers/booleans/objects/
    arrays can be provided), falling back to the raw string otherwise.
    """
    if not extension_specs:
        return None

    extensions = {}
    for name, value in extension_specs:
        try:
            extensions[name] = json.loads(value)
        except json.JSONDecodeError:
            extensions[name] = value
    return extensions


def _sign_object(
    obj: dict,
    keys_and_algorithms,
    args,
) -> dict:
    """Sign a single JSON object using the resolved key(s)/algorithm(s) and CLI options."""
    if args.multi or args.chain:
        signers = [
            JSFSignature(
                key,
                algorithm,
                certificate_path=certs,
                include_public_key=args.embed_public_key,
                signer=remote_signer,
            )
            for key, algorithm, certs, remote_signer in keys_and_algorithms
        ]
        sign_func = JSFSignature.sign_multi if args.multi else JSFSignature.sign_chain
        return sign_func(
            obj,
            signers,
            excludes=args.excludes,
            extensions=parse_extensions(args.extensions),
            signature_property=args.property,
        )

    key, algorithm, certs, remote_signer = keys_and_algorithms[0]
    signer = JSFSignature(
        key,
        algorithm,
        signature_property=args.property,
        certificate_path=certs,
        include_public_key=args.embed_public_key,
        signer=remote_signer,
    )
    return signer.sign(
        obj,
        excludes=args.excludes,
        extensions=parse_extensions(args.extensions),
    )


def _sign_jss_object(
    obj: dict,
    keys_and_algorithms,
    args,
) -> dict:
    """Sign a single JSON object as a JSS document using the resolved key(s)/algorithm(s)."""
    signers = [
        JSSSignature(
            key,
            algorithm,
            hash_algorithm=args.hash_algorithm,
            signatures_property=args.property,
            certificate_path=certs,
            include_public_key=args.embed_public_key,
            signer=remote_signer,
        )
        for key, algorithm, certs, remote_signer in keys_and_algorithms
    ]
    return JSSSignature.sign_multi(obj, signers)


def resolve_json_path_matches(obj, json_path: str):
    """
    Resolve a JSONPath expression against ``obj`` and return its matches.

    Every matched object must be a JSON object (dict), since JSF signs
    objects, not scalars/arrays.

    Raises:
        ValueError: If the JSONPath matches nothing, or any match is not a
            JSON object
    """
    matches = list(jsonpath.finditer(json_path, obj))
    if not matches:
        raise ValueError(f"JSON path '{json_path}' matched no objects")

    for match in matches:
        if not isinstance(match.obj, dict):
            raise ValueError(f"JSON path '{json_path}' match at {match.path} is not a JSON object")

    return matches


def cmd_sign(args) -> int:
    """Sign a JSON file with one or more private keys."""
    try:
        obj = load_json_file(args.file)

        key_specs = args.keys or []
        if not key_specs:
            print(
                "Error: At least one --key, --jwk, or --vault-key must be provided",
                file=sys.stderr,
            )
            return 1

        if len(key_specs) > 1 and not (args.multi or args.chain):
            print(
                "Error: --multi or --chain is required when more than one "
                "--key/--jwk/--vault-key is given",
                file=sys.stderr,
            )
            return 1

        cert_specs = args.certs or []
        if cert_specs and len(cert_specs) != len(key_specs):
            print(
                "Error: --cert must be given once per --key/--jwk/--vault-key (in "
                "the same order), using '-' to skip a signer",
                file=sys.stderr,
            )
            return 1

        # Load and validate every key + algorithm pair, in CLI order,
        # paired positionally with any --cert given for that signer. A
        # Vault client is built lazily (once) the first time a
        # --vault-key entry is encountered.
        vault_client = None
        keys_and_algorithms = []
        for index, (kind, (path_str, algorithm)) in enumerate(key_specs):
            remote_signer = None
            if kind == "vault":
                if vault_client is None:
                    vault_client = build_vault_client(args.vault_addr, args.vault_token)
                vault_signer = VaultTransitSigner(
                    vault_client,
                    path_str,
                    mount_point=args.vault_mount_point,
                    key_version=args.vault_key_version,
                )
                key = vault_signer.public_key(algorithm)
                remote_signer = vault_signer
            else:
                key = load_key_spec(kind, path_str)
                try:
                    AlgorithmRegistry.validate_algorithm_key_type(algorithm, key)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1
            cert_spec = cert_specs[index] if index < len(cert_specs) else None
            certs = load_certificate_path(cert_spec) if cert_spec and cert_spec != "-" else None
            keys_and_algorithms.append((key, algorithm, certs, remote_signer))

        if args.json_path:
            # Sign each matched sub-object independently and write the
            # signed result back in place. sign()/sign_multi()/sign_chain()
            # all return new dicts rather than mutating, so each match is
            # replaced within its parent container (or, for the root match
            # itself, `obj` is replaced wholesale).
            matches = resolve_json_path_matches(obj, args.json_path)
            for match in matches:
                signed_target = _sign_object(match.obj, keys_and_algorithms, args)
                if match.parent is None:
                    obj = signed_target
                else:
                    match.parent.obj[match.parts[-1]] = signed_target
            signed_obj = obj
        else:
            signed_obj = _sign_object(obj, keys_and_algorithms, args)

        if args.output:
            save_json_file(args.output, signed_obj)
            print(f"Signed object saved to {args.output}")
        else:
            print(json.dumps(signed_obj, indent=2))

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _verify_object(target: dict, args, key_specs) -> bool:
    """Verify a single signed JSON object using CLI options, returning True/False."""
    if args.property not in target:
        raise ValueError(f"Signature property not found: {args.property}")

    # Determine mode: an explicit --multi/--chain always wins. If keys are
    # being resolved from the document itself (--use-embedded-key) and no
    # mode was given explicitly, auto-detect from the object's own
    # structure. Otherwise (explicit --key/--jwk, no --multi/--chain) this
    # is a plain single-signature verify.
    if args.multi:
        mode = "multi"
    elif args.chain:
        mode = "chain"
    elif args.use_embedded_key:
        sig_holder = target[args.property]
        if isinstance(sig_holder, dict) and "signers" in sig_holder:
            mode = "multi"
        elif isinstance(sig_holder, dict) and "chain" in sig_holder:
            mode = "chain"
        else:
            mode = None
    else:
        mode = None

    if args.use_embedded_key:
        keys = JSFSignature.get_public_keys(target, signature_property=args.property)
    else:
        keys = [load_key_spec(kind, path_str) for kind, path_str in key_specs]

    if mode == "multi":
        return JSFSignature.verify_multi(
            target,
            keys=keys,
            signature_property=args.property,
            allowed_excludes=args.allowed_excludes,
            known_extensions=args.known_extensions,
        )
    elif mode == "chain":
        return JSFSignature.verify_chain(
            target,
            keys=keys,
            signature_property=args.property,
            allowed_excludes=args.allowed_excludes,
            known_extensions=args.known_extensions,
        )

    sig_obj = target[args.property]
    if "algorithm" not in sig_obj:
        raise ValueError("Algorithm not found in signature object")
    algorithm = sig_obj["algorithm"]
    verifier = JSFSignature(keys[0], algorithm, signature_property=args.property)
    return verifier.verify(
        target,
        allowed_excludes=args.allowed_excludes,
        known_extensions=args.known_extensions,
    )


def cmd_verify(args) -> int:
    """Verify a JSON file signature."""
    try:
        signed_obj = load_json_file(args.file)

        key_specs = args.keys or []

        if args.use_embedded_key and key_specs:
            print(
                "Error: --use-embedded-key cannot be combined with --key/--jwk",
                file=sys.stderr,
            )
            return 1

        if not args.use_embedded_key and not key_specs:
            print(
                "Error: Either --key, --jwk, or --use-embedded-key must be provided",
                file=sys.stderr,
            )
            return 1

        if len(key_specs) > 1 and not (args.multi or args.chain):
            print(
                "Error: --multi or --chain is required when more than one " "--key/--jwk is given",
                file=sys.stderr,
            )
            return 1

        if args.json_path:
            # Verify each matched sub-object independently, reporting every
            # match's result; the overall exit code is 1 if any match
            # fails, even though every match is still checked.
            matches = resolve_json_path_matches(signed_obj, args.json_path)
            all_valid = True
            for match in matches:
                try:
                    is_valid = _verify_object(match.obj, args, key_specs)
                except ValueError as e:
                    print(f"✗ {match.path}: Error: {e}", file=sys.stderr)
                    all_valid = False
                    continue
                if is_valid:
                    print(f"✓ {match.path}: Signature is valid")
                else:
                    print(f"✗ {match.path}: Signature is invalid", file=sys.stderr)
                    all_valid = False

            return 0 if all_valid else 1

        is_valid = _verify_object(signed_obj, args, key_specs)

        if is_valid:
            print("✓ Signature is valid")
            return 0
        else:
            print("✗ Signature is invalid", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_sign_jss(args) -> int:
    """Sign a JSON file with one or more private keys, producing a JSS document."""
    try:
        obj = load_json_file(args.file)

        key_specs = args.keys or []
        if not key_specs:
            print(
                "Error: At least one --key, --jwk, or --vault-key must be provided",
                file=sys.stderr,
            )
            return 1

        cert_specs = args.certs or []
        if cert_specs and len(cert_specs) != len(key_specs):
            print(
                "Error: --cert must be given once per --key/--jwk/--vault-key (in "
                "the same order), using '-' to skip a signer",
                file=sys.stderr,
            )
            return 1

        vault_client = None
        keys_and_algorithms = []
        for index, (kind, (path_str, algorithm)) in enumerate(key_specs):
            remote_signer = None
            if kind == "vault":
                if vault_client is None:
                    vault_client = build_vault_client(args.vault_addr, args.vault_token)
                vault_signer = VaultTransitSigner(
                    vault_client,
                    path_str,
                    mount_point=args.vault_mount_point,
                    key_version=args.vault_key_version,
                )
                key = vault_signer.public_key(algorithm)
                remote_signer = vault_signer
            else:
                key = load_key_spec(kind, path_str)
                try:
                    AlgorithmRegistry.validate_algorithm_key_type(algorithm, key)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1
            cert_spec = cert_specs[index] if index < len(cert_specs) else None
            certs = load_certificate_path(cert_spec) if cert_spec and cert_spec != "-" else None
            keys_and_algorithms.append((key, algorithm, certs, remote_signer))

        if args.json_path:
            matches = resolve_json_path_matches(obj, args.json_path)
            for match in matches:
                signed_target = _sign_jss_object(match.obj, keys_and_algorithms, args)
                if match.parent is None:
                    obj = signed_target
                else:
                    match.parent.obj[match.parts[-1]] = signed_target
            signed_obj = obj
        else:
            signed_obj = _sign_jss_object(obj, keys_and_algorithms, args)

        if args.output:
            save_json_file(args.output, signed_obj)
            print(f"Signed object saved to {args.output}")
        else:
            print(json.dumps(signed_obj, indent=2))

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_verify_jss(args) -> int:
    """Verify a JSS-signed JSON file's signature(s)."""
    try:
        signed_obj = load_json_file(args.file)

        if args.json_path:
            matches = resolve_json_path_matches(signed_obj, args.json_path)
            all_valid = True
            for match in matches:
                is_valid = JSSSignature.verify(match.obj, signatures_property=args.property)
                if is_valid:
                    print(f"✓ {match.path}: Signature is valid")
                else:
                    print(f"✗ {match.path}: Signature is invalid", file=sys.stderr)
                    all_valid = False

            return 0 if all_valid else 1

        is_valid = JSSSignature.verify(signed_obj, signatures_property=args.property)

        if is_valid:
            print("✓ Signature is valid")
            return 0
        else:
            print("✗ Signature is invalid", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_list_algorithms(args) -> int:
    """List supported algorithms."""
    algorithms = AlgorithmRegistry.list_algorithms()
    print("Supported algorithms:")
    for alg in sorted(algorithms):
        print(f"  {alg}")
    return 0


def cmd_certs(args) -> int:
    """Extract and print embedded certificate chains from a signed JSON file."""
    try:
        obj = load_json_file(args.file)

        property_name = args.property or ("signature" if args.format == "jsf" else "signatures")
        if args.format == "jsf":
            chains = JSFSignature.get_certificate_chains(obj, signature_property=property_name)
        else:
            chains = JSSSignature.get_certificate_chains(obj, signatures_property=property_name)

        lines = []
        for index, chain in enumerate(chains):
            lines.append(f"# Signature entry {index}")
            if chain is None:
                lines.append("# (no embedded certificate chain)")
                continue
            for cert in chain:
                pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
                lines.append(pem.rstrip("\n"))
        output_text = "\n".join(lines) + "\n"

        if args.output:
            Path(args.output).write_text(output_text)
            print(f"Certificate chains saved to {args.output}")
        else:
            print(output_text, end="")

        return 0
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _add_certs_parser(parent_subparsers, fmt: str):
    """Add a 'certs' subcommand to a jsf/jss sub-subparsers group for the given format."""
    certs_format = "certificatePath" if fmt == "jsf" else "public_cert_chain"
    default_property = "signature" if fmt == "jsf" else "signatures"
    certs_parser = parent_subparsers.add_parser(
        "certs",
        help="Extract embedded certificate chains from a signed JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Examples:
  # Print PEM certificate chains embedded via {fmt.upper()}'s "{certs_format}"
  pyjsign {fmt} certs signed.json

  # Write the extracted certificate chains to a file instead of stdout
  pyjsign {fmt} certs signed.json -o chains.pem

This only extracts and prints the certificates; it does NOT validate
the chain of trust, expiry, or revocation -- use a tool such as
`cryptography.x509.verification` to validate the extracted chain(s).
""",
    )
    certs_parser.add_argument(
        "file", help="Signed JSON file to read (use '-' for stdin)", type=Path
    )
    certs_parser.add_argument(
        "-p",
        "--property",
        help=f"Signature property name (default: {default_property!r})",
    )
    certs_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file for extracted PEM certificates (default: stdout)",
    )
    certs_parser.set_defaults(func=cmd_certs, format=fmt)
    return certs_parser


def main(argv=None):
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="pyjsign",
        description=(
            "JSON Signature Format (JSF) and X.590 JSON Signature Scheme (JSS) " "command-line tool"
        ),
    )

    parser.add_argument("--version", "-V", action="version", version=VERSION)

    subparsers = parser.add_subparsers(dest="command", help="Command group to run")

    # jsf command group
    jsf_parser = subparsers.add_parser("jsf", help="JSON Signature Format (JSF) commands")
    jsf_subparsers = jsf_parser.add_subparsers(
        dest="jsf_command", required=True, help="JSF command to run"
    )

    # jsf sign subcommand
    sign_parser = jsf_subparsers.add_parser(
        "sign",
        help="Sign a JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Sign with a PEM private key, embedding the public key, to stdout
  pyjsign jsf sign data.json -k priv.pem ES256 -e

  # Sign with a JWK private key, writing to a file
  pyjsign jsf sign data.json -j priv.jwk.json RS256 -o signed.json

  # Sign with a certificate chain embedded as certificatePath
  pyjsign jsf sign data.json -k priv.pem ES256 -c cert.pem -o signed.json

  # Multiple independent signatures (JSF "Multiple Signatures")
  pyjsign jsf sign data.json -k a.pem ES256 -k b.pem RS256 --multi -o signed.json

  # Signature chain (JSF "Signature Chains")
  pyjsign jsf sign data.json -k a.pem ES256 -k b.pem RS256 --chain -o signed.json

  # Read from stdin, exclude a property, add an extension
  cat data.json | pyjsign jsf sign - -k priv.pem ES256 -x timestamp \\
      --extension purpose audit -o signed.json

  # Sign only the sub-object(s) matched by a JSONPath expression
  pyjsign jsf sign data.json -k priv.pem ES256 -P '$.items[*]' -o signed.json

  # Sign with a key held in a HashiCorp Vault Transit secrets engine
  # (private key never leaves Vault); requires `pip install pyjsign[vault]`
  export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=...
  pyjsign jsf sign data.json --vault-key my-signing-key ES256 -o signed.json
""",
    )
    sign_parser.add_argument("file", help="JSON file to sign (use '-' for stdin)", type=Path)
    sign_parser.add_argument(
        "-k",
        "--key",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("KEY_FILE", "ALGORITHM"),
        help=(
            "Private key file (PEM format) and its signing algorithm, e.g. "
            "-k priv.pem ES256. Repeatable: give one -k/-j per signer for "
            "--multi/--chain (order matches the command line)."
        ),
    )
    sign_parser.add_argument(
        "-j",
        "--jwk",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("JWK_FILE", "ALGORITHM"),
        help=(
            "Private key file (JWK JSON format) and its signing algorithm, "
            "e.g. -j priv.jwk.json RS256. Repeatable: give one -k/-j per "
            "signer for --multi/--chain (order matches the command line)."
        ),
    )
    sign_parser.add_argument(
        "--vault-key",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("KEY_NAME", "ALGORITHM"),
        help=(
            "Name of a key held in a HashiCorp Vault Transit secrets engine "
            "mount and its signing algorithm, e.g. --vault-key my-key ES256. "
            "The private key never leaves Vault; only its public key is "
            "fetched locally. Requires the 'hvac' package (pip install "
            "pyjsign[vault]) and --vault-addr/--vault-token (or the "
            "VAULT_ADDR/VAULT_TOKEN environment variables). Supports "
            "ECDSA, RSA (PKCS#1 v1.5/PSS), and Ed25519 algorithms only. "
            "Repeatable: give one -k/-j/--vault-key per signer for "
            "--multi/--chain (order matches the command line)."
        ),
    )
    sign_parser.add_argument(
        "--vault-addr",
        help="HashiCorp Vault server address, e.g. https://vault.example.com:8200 "
        "(default: the VAULT_ADDR environment variable)",
    )
    sign_parser.add_argument(
        "--vault-token",
        help="HashiCorp Vault authentication token "
        "(default: the VAULT_TOKEN environment variable)",
    )
    sign_parser.add_argument(
        "--vault-mount-point",
        default="transit",
        help="Path the Vault Transit secrets engine is mounted at (default: %(default)s)",
    )
    sign_parser.add_argument(
        "--vault-key-version",
        type=int,
        help="Specific Vault key version to sign with for every --vault-key "
        "(default: each key's latest version)",
    )
    sign_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file for signed JSON (default: stdout)",
    )
    sign_parser.add_argument(
        "-p",
        "--property",
        default="signature",
        help="Signature property name (default: %(default)s)",
    )
    sign_parser.add_argument(
        "-e",
        "--embed-public-key",
        action="store_true",
        help="Embed the public key in the signature(s)",
    )
    sign_parser.add_argument(
        "-c",
        "--cert",
        dest="certs",
        action="append",
        metavar="CERT_FILE",
        help=(
            "PEM file holding a certificate chain (leaf-to-root; may "
            "contain multiple concatenated certificates) to embed as "
            "certificatePath, matched positionally with -k/-j occurrences "
            "(one -c per signer, in the same order). Use '-' to skip "
            "embedding a certificate for that signer. If given, --cert "
            "must appear once per -k/-j. Takes precedence over "
            "-e/--embed-public-key for that signer."
        ),
    )
    sign_parser.add_argument(
        "-x",
        "--exclude",
        dest="excludes",
        action="append",
        metavar="PROPERTY",
        help=(
            "Top-level property name to exclude from the signature process. "
            "Repeatable. Per the JSF spec, both the named properties and "
            "the 'excludes' property itself are left unsigned; verify "
            "requires --allow-exclude to accept them."
        ),
    )
    sign_parser.add_argument(
        "--extension",
        dest="extensions",
        action="append",
        nargs=2,
        metavar=("NAME", "VALUE"),
        help=(
            "Application-specific extension property to add to the "
            "signaturecore object (name and value). Repeatable. VALUE is "
            "parsed as JSON if possible, otherwise used as a plain string. "
            "Unlike --exclude, extension properties are covered by the "
            "signature since they are part of the signaturecore itself."
        ),
    )
    sign_parser.add_argument(
        "-P",
        "--json-path",
        metavar="EXPR",
        help=(
            "JSONPath expression selecting one or more sub-objects within "
            "the document to sign independently, in place, instead of "
            "signing the whole document. Every match must be a JSON "
            "object. Default: sign the whole document."
        ),
    )
    sign_mode_group = sign_parser.add_mutually_exclusive_group()
    sign_mode_group.add_argument(
        "--multi",
        action="store_true",
        help=(
            "Produce a JSF Multiple Signatures object (required if more " "than one -k/-j is given)"
        ),
    )
    sign_mode_group.add_argument(
        "--chain",
        action="store_true",
        help=("Produce a JSF Signature Chain object (required if more than " "one -k/-j is given)"),
    )
    sign_parser.set_defaults(func=cmd_sign)

    # jsf verify subcommand
    verify_parser = jsf_subparsers.add_parser(
        "verify",
        help="Verify a JSON signature",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Verify with a PEM public key
  pyjsign jsf verify signed.json -k priv.pem

  # Verify using the key(s) embedded in the signature
  # (via publicKey/certificatePath), instead of --key/--jwk
  pyjsign jsf verify signed.json --use-embedded-key

  # Verify a Multiple Signatures document
  pyjsign jsf verify signed.json -k a.pem -k b.pem --multi

  # Verify a Signature Chain document
  pyjsign jsf verify signed.json -k a.pem -k b.pem --chain

  # Allow a known excluded property and a known extension name
  pyjsign jsf verify signed.json -k priv.pem -x timestamp --known-extension purpose

  # Verify only the sub-object(s) matched by a JSONPath expression
  pyjsign jsf verify signed.json -k priv.pem -P '$.items[*]'
""",
    )
    verify_parser.add_argument(
        "file", help="Signed JSON file to verify (use '-' for stdin)", type=Path
    )
    verify_parser.add_argument(
        "-k",
        "--key",
        dest="keys",
        action=_OrderedKeyAction,
        metavar="KEY_FILE",
        help=(
            "Public/private key file (PEM format). Repeatable: give one "
            "-k/-j per signer for --multi/--chain (order matches the "
            "command line and the document's signer/chain order)."
        ),
    )
    verify_parser.add_argument(
        "-j",
        "--jwk",
        dest="keys",
        action=_OrderedKeyAction,
        metavar="JWK_FILE",
        help=(
            "Public/private key file (JWK JSON format). Repeatable: give "
            "one -k/-j per signer for --multi/--chain (order matches the "
            "command line and the document's signer/chain order)."
        ),
    )
    verify_parser.add_argument(
        "-p",
        "--property",
        default="signature",
        help="Signature property name (default: signature)",
    )
    verify_parser.add_argument(
        "-e",
        "--use-embedded-key",
        action="store_true",
        help=(
            "Verify using the public key(s) embedded in the signature "
            "(via publicKey/certificatePath) instead of --key/--jwk. Mode "
            "(single/--multi/--chain) is auto-detected from the document "
            "unless --multi/--chain is given explicitly."
        ),
    )
    verify_parser.add_argument(
        "-x",
        "--allow-exclude",
        dest="allowed_excludes",
        action="append",
        metavar="PROPERTY",
        help=(
            "Permit PROPERTY to appear in the signature's (unsigned) "
            "'excludes' list. Repeatable. A signature/entry carrying "
            "'excludes' is rejected unless every name it lists is allowed "
            "via this flag."
        ),
    )
    verify_parser.add_argument(
        "--known-extension",
        dest="known_extensions",
        action="append",
        metavar="NAME",
        help=(
            "Recognized/accepted extension property name. Repeatable. By "
            "default any extension is accepted (extensions are covered by "
            "the signature); pass this to reject signatures carrying "
            "extension names outside the given set."
        ),
    )
    verify_parser.add_argument(
        "-P",
        "--json-path",
        metavar="EXPR",
        help=(
            "JSONPath expression selecting one or more signed sub-objects "
            "within the document to verify independently, instead of "
            "verifying the whole document. Every match must be a JSON "
            "object. Every match is checked and reported; the overall exit "
            "code is 1 if any match fails. Default: verify the whole "
            "document."
        ),
    )
    verify_mode_group = verify_parser.add_mutually_exclusive_group()
    verify_mode_group.add_argument(
        "--multi",
        action="store_true",
        help=(
            "Verify a JSF Multiple Signatures object (required if more " "than one -k/-j is given)"
        ),
    )
    verify_mode_group.add_argument(
        "--chain",
        action="store_true",
        help=("Verify a JSF Signature Chain object (required if more than " "one -k/-j is given)"),
    )
    verify_parser.set_defaults(func=cmd_verify)

    # jsf certs subcommand
    _add_certs_parser(jsf_subparsers, "jsf")

    # jss command group
    jss_parser = subparsers.add_parser(
        "jss", help="ITU-T X.590 JSON Signature Scheme (JSS) commands"
    )
    jss_subparsers = jss_parser.add_subparsers(
        dest="jss_command", required=True, help="JSS command to run"
    )

    # jss sign subcommand
    sign_jss_parser = jss_subparsers.add_parser(
        "sign",
        help="Sign a JSON file (ITU-T X.590 JSON Signature Scheme)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Sign with a PEM private key, embedding the public key, to stdout
  pyjsign jss sign data.json -k priv.pem Ed25519 -e

  # Sign with a JWK private key, writing to a file
  pyjsign jss sign data.json -j priv.jwk.json RS256 -o signed.json

  # Sign with a certificate chain embedded as public_cert_chain
  pyjsign jss sign data.json -k priv.pem ES256 -c cert.pem -o signed.json

  # Multiple independent JSS signatures
  pyjsign jss sign data.json -k a.pem ES256 -e -k b.pem Ed25519 -e -o signed.json

  # Use a non-default hash_algorithm (applies to every signer)
  pyjsign jss sign data.json -k priv.pem ES384 -e --hash-algorithm sha-384

  # Sign with a key held in a HashiCorp Vault Transit secrets engine
  # (private key never leaves Vault); requires `pip install pyjsign[vault]`
  export VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=...
  pyjsign jss sign data.json --vault-key my-signing-key ES256 -e -o signed.json
""",
    )
    sign_jss_parser.add_argument("file", help="JSON file to sign (use '-' for stdin)", type=Path)
    sign_jss_parser.add_argument(
        "-k",
        "--key",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("KEY_FILE", "ALGORITHM"),
        help=(
            "Private key file (PEM format) and its signing algorithm, e.g. "
            "-k priv.pem ES256. Repeatable: each occurrence appends one "
            "independent JSS signature."
        ),
    )
    sign_jss_parser.add_argument(
        "-j",
        "--jwk",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("JWK_FILE", "ALGORITHM"),
        help=(
            "Private key file (JWK JSON format) and its signing algorithm, "
            "e.g. -j priv.jwk.json RS256. Repeatable: each occurrence "
            "appends one independent JSS signature."
        ),
    )
    sign_jss_parser.add_argument(
        "--vault-key",
        dest="keys",
        action=_OrderedKeyAction,
        nargs=2,
        metavar=("KEY_NAME", "ALGORITHM"),
        help=(
            "Name of a key held in a HashiCorp Vault Transit secrets engine "
            "mount and its signing algorithm, e.g. --vault-key my-key ES256. "
            "The private key never leaves Vault; only its public key is "
            "fetched locally. Requires the 'hvac' package (pip install "
            "pyjsign[vault]) and --vault-addr/--vault-token (or the "
            "VAULT_ADDR/VAULT_TOKEN environment variables). Supports "
            "ECDSA, RSA (PKCS#1 v1.5/PSS), and Ed25519 algorithms only. "
            "Repeatable: each occurrence appends one independent JSS "
            "signature."
        ),
    )
    sign_jss_parser.add_argument(
        "--vault-addr",
        help="HashiCorp Vault server address, e.g. https://vault.example.com:8200 "
        "(default: the VAULT_ADDR environment variable)",
    )
    sign_jss_parser.add_argument(
        "--vault-token",
        help="HashiCorp Vault authentication token "
        "(default: the VAULT_TOKEN environment variable)",
    )
    sign_jss_parser.add_argument(
        "--vault-mount-point",
        default="transit",
        help="Path the Vault Transit secrets engine is mounted at (default: %(default)s)",
    )
    sign_jss_parser.add_argument(
        "--vault-key-version",
        type=int,
        help="Specific Vault key version to sign with for every --vault-key "
        "(default: each key's latest version)",
    )
    sign_jss_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file for signed JSON (default: stdout)",
    )
    sign_jss_parser.add_argument(
        "-p",
        "--property",
        default="signatures",
        help="Signatures array property name (default: %(default)s)",
    )
    sign_jss_parser.add_argument(
        "--hash-algorithm",
        default="sha-256",
        help=(
            "JSS hash_algorithm used to hash the canonicalized JSON before "
            "signing, e.g. sha-256, sha-384, sha-512 (default: %(default)s). "
            "Applies to every signer given on the command line."
        ),
    )
    sign_jss_parser.add_argument(
        "-e",
        "--embed-public-key",
        action="store_true",
        help="Embed each signer's public key (as public_key) in its signature",
    )
    sign_jss_parser.add_argument(
        "-c",
        "--cert",
        dest="certs",
        action="append",
        metavar="CERT_FILE",
        help=(
            "PEM file holding a certificate chain (leaf-to-root; may "
            "contain multiple concatenated certificates) to embed as "
            "public_cert_chain, matched positionally with -k/-j "
            "occurrences (one -c per signer, in the same order). Use '-' "
            "to skip embedding a certificate for that signer. If given, "
            "--cert must appear once per -k/-j. Takes precedence over "
            "-e/--embed-public-key for that signer."
        ),
    )
    sign_jss_parser.add_argument(
        "-P",
        "--json-path",
        metavar="EXPR",
        help=(
            "JSONPath expression selecting one or more sub-objects within "
            "the document to sign independently, in place, instead of "
            "signing the whole document. Every match must be a JSON "
            "object. Default: sign the whole document."
        ),
    )
    sign_jss_parser.set_defaults(func=cmd_sign_jss)

    # jss verify subcommand
    verify_jss_parser = jss_subparsers.add_parser(
        "verify",
        help="Verify a JSON signature (ITU-T X.590 JSON Signature Scheme)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Verify using the public key(s)/certificate(s) embedded in each signature
  pyjsign jss verify signed.json

  # Verify only the sub-object(s) matched by a JSONPath expression
  pyjsign jss verify signed.json -P '$.items[*]'
""",
    )
    verify_jss_parser.add_argument(
        "file", help="Signed JSON file to verify (use '-' for stdin)", type=Path
    )
    verify_jss_parser.add_argument(
        "-p",
        "--property",
        default="signatures",
        help="Signatures array property name (default: %(default)s)",
    )
    verify_jss_parser.add_argument(
        "-P",
        "--json-path",
        metavar="EXPR",
        help=(
            "JSONPath expression selecting one or more signed sub-objects "
            "within the document to verify independently, instead of "
            "verifying the whole document. Every match must be a JSON "
            "object. Every match is checked and reported; the overall exit "
            "code is 1 if any match fails. Default: verify the whole "
            "document."
        ),
    )
    verify_jss_parser.set_defaults(func=cmd_verify_jss)

    # jss certs subcommand
    _add_certs_parser(jss_subparsers, "jss")

    # List algorithms subcommand
    list_parser = subparsers.add_parser(
        "list-algorithms",
        help="List supported algorithms",
    )
    list_parser.set_defaults(func=cmd_list_algorithms)

    # Parse arguments
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


def main_jsf(argv=None):
    """Entry point for the ``pyjsf`` command; equivalent to ``pyjsign jsf``."""
    if argv is None:
        argv = sys.argv[1:]
    return main(["jsf", *argv])


def main_jss(argv=None):
    """Entry point for the ``pyjss`` command; equivalent to ``pyjsign jss``."""
    if argv is None:
        argv = sys.argv[1:]
    return main(["jss", *argv])


if __name__ == "__main__":
    sys.exit(main())
