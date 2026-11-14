# JSON Signature Format (JSF) and JSS Python Implementation

A Python utility to sign and verify JSON document. Implements
[JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) and
[ITU-T X.590 a.k.a. JSON Signature Schema (JSS)](https://www.itu.int/epublications/zh/publication/itu-t-x-590-2023-10-json-signature-scheme-jss/en).

API Documentation is available [here](https://pyjsign.readthedocs.io/).

## Installation

Install from PyPi using:

```bash
python3 -m pip install pyjsign
```

To sign using a HashiCorp Vault server's Transit secrets engine (see
[Signing with HashiCorp Vault](#signing-with-hashicorp-vault)), install the
optional `vault` extra (adds `hvac`):

```bash
python3 -m pip install pyjsign[vault]
```

**or**

Install from a local checkout using pip using a virtual environment for
development:

```bash
python3 -m .venv
. .venv/bin/activate
pip install -e .[dev]
```

Installing the package provides a `pyjsign` CLI tool with `jsf sign`, `jsf
verify`, and `list-algorithms` subcommands.

`pyjsf` and `pyjss` are also installed as shorthand aliases for `pyjsign jsf`
and `pyjsign jss` respectively (e.g. `pyjsf sign data.json ...` is
equivalent to `pyjsign jsf sign data.json ...`).

## JSS Command-Line Interface Examples

```bash
# Sign with a PEM private key, embedding the public key, to stdout
pyjsign jss sign data.json --key private_key.pem ES256 --embed-public-key

# Sign with a JWK private key, writing to a file
pyjsign jss sign data.json --jwk rsa_key.jwk.json RS256 --embed-public-key --output signed.json

# Verify a signed JSON file; the key(s)/certificate(s) used are always
# resolved from what's embedded in each signature entry
pyjsign jss verify signed.json

# Read the document to sign/verify from stdin by passing "-" as the file
cat data.json | pyjsign jss sign - --key private_key.pem ES256 --embed-public-key > signed.json
cat signed.json | pyjsign jss verify -

# Sign with multiple independent signatures; order of -k/-j determines
# signer order
pyjsign jss sign data.json --key ec_key.pem ES256 --embed-public-key \
  --jwk rsa_key.jwk.json RS256 --embed-public-key --output signed.json
pyjsign jss verify signed.json

# Use a non-default hash_algorithm (applies to every signer)
pyjsign jss sign data.json --key ec_key.pem ES384 --embed-public-key --hash-algorithm sha-384

# Sign with a certificate instead of a raw public key (JSS "public_cert_chain").
# CERT_FILE is a PEM file, which may hold a concatenated chain (leaf-to-root).
# -c/--cert is paired positionally with -k/-j; use "-" to skip a signer.
pyjsign jss sign data.json --key private_key.pem ES256 --cert cert_chain.pem -o signed.json
pyjsign jss verify signed.json

# Use a custom signatures array property name instead of the default "signatures"
pyjsign jss sign data.json --key private_key.pem ES256 --embed-public-key --property sigs
pyjsign jss verify signed.json --property sigs

# Sign/verify only a subset of the document, selected by JSONPath, instead
# of the whole document. Each matched object is signed/verified
# independently, in place; every match must resolve to a JSON object.
pyjsign jss sign data.json --key private_key.pem ES256 --embed-public-key -P '$.documents[*]' -o signed.json
pyjsign jss verify signed.json -P '$.documents[*]'
```

## JSF Command-Line Interface Examples

```bash
# Sign a JSON file with a single PEM private key (-k/-j take FILE ALGORITHM)
pyjsign jsf sign data.json --key private_key.pem ES256 --output signed.json

# Sign with a JWK file and embed the public key
pyjsign jsf sign data.json --jwk private_key.jwk.json ES256 --embed-public-key

# Verify a signed JSON file
pyjsign jsf verify signed.json --key private_key.pem

# Verify using the public key embedded in the signature (requires the
# object to have been signed with --embed-public-key)
pyjsign jsf verify signed.json --use-embedded-key

# Read the document to sign/verify from stdin by passing "-" as the file
cat data.json | pyjsign jsf sign - --key private_key.pem ES256 > signed.json
cat signed.json | pyjsign jsf verify - --key private_key.pem

# Sign with multiple independent signatures (JSF "Multiple Signatures");
# order of -k/-j determines signer order
pyjsign jsf sign data.json --key ec_key.pem ES256 --jwk rsa_key.jwk.json RS256 \
  --multi --embed-public-key --output signed.json

# Verify a multi-signature object, either with explicit keys (in the same
# order as signing) or by resolving the embedded public keys automatically
pyjsign jsf verify signed.json --key ec_key.pem --jwk rsa_key.jwk.json --multi
pyjsign jsf verify signed.json --use-embedded-key   # mode auto-detected

# Sign a signature chain (JSF "Signature Chains") the same way, using
# --chain instead of --multi
pyjsign jsf sign data.json --key ec_key.pem ES256 --jwk rsa_key.jwk.json RS256 \
  --chain --embed-public-key --output signed.json
pyjsign jsf verify signed.json --key ec_key.pem --jwk rsa_key.jwk.json --chain

# Sign with a certificate instead of a raw public key (JSF "certificatePath").
# CERT_FILE is a PEM file, which may hold a concatenated chain (leaf-to-root).
# -c/--cert is paired positionally with -k/-j; use "-" to skip a signer.
pyjsign jsf sign data.json --key private_key.pem ES256 --cert cert_chain.pem -o signed.json
pyjsign jsf verify signed.json --use-embedded-key

pyjsign jsf sign data.json --key ec_key.pem ES256 --cert ec_cert.pem \
  --jwk rsa_key.jwk.json RS256 --cert - --multi --output signed.json

# Exclude a top-level property from the signature process (JSF "excludes").
# Both the named properties and "excludes" itself are unsigned, so verify
# requires an explicit -x/--allow-exclude per property name to accept them.
pyjsign jsf sign data.json --key private_key.pem ES256 -x myUnsignedData -o signed.json
pyjsign jsf verify signed.json --key private_key.pem -x myUnsignedData

# Add an application-specific extension property (JSF "extensions").
# Unlike "excludes", extensions are embedded in the signaturecore object
# and are therefore covered by the signature.
pyjsign jsf sign data.json --key private_key.pem ES256 --extension otherExt '"Cool Stuff"' -o signed.json
pyjsign jsf verify signed.json --key private_key.pem                       # any extensions accepted
pyjsign jsf verify signed.json --key private_key.pem --known-extension otherExt  # restrict to known names

# Sign/verify only a subset of the document, selected by JSONPath, instead
# of the whole document. Each matched object is signed/verified
# independently, in place; every match must resolve to a JSON object.
pyjsign jsf sign data.json --key private_key.pem ES256 -P '$.documents[*]' -o signed.json
pyjsign jsf verify signed.json --key private_key.pem -P '$.documents[*]'
```

### Extracting Certificate Chains

```bash
# Print PEM certificate chains embedded via JSF's "certificatePath"
pyjsign jsf certs signed.json

# Print PEM certificate chains embedded via JSS's "public_cert_chain"
pyjsign jss certs signed.json -o chains.pem
```

`pyjsign jsf certs FILE [-p/--property NAME] [-o OUTPUT]` and the equivalent
`pyjsign jss certs` read a signed JSON file and print the PEM-encoded
certificate chain embedded in each signature entry (or note entries with none).
This only extracts and prints the certificates - it does NOT validate the chain
of trust, expiry, or revocation; use a tool such as
[`cryptography.x509.verification`](https://cryptography.io/en/latest/x509/verification/)
or `openssl verify` to validate the extracted chain(s) against a trust store:

```bash
pyjsign jss certs signed.json -o chains.pem
openssl verify -CAfile root_ca.pem chains.pem
```

`-CAfile` must point to your trusted root certificate(s), not the extracted
chain itself. If the chain's root isn't present in your trust store as a CA,
add `-partial_chain` to trust the leaf's immediate issuer directly.

## Signing with HashiCorp Vault

`pyjsign` can sign with a private key that never leaves a [HashiCorp
Vault](https://www.vaultproject.io/) server, by delegating the actual
cryptographic signing operation to Vault's [Transit secrets
engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
(`/transit/sign/:name`). `pyjsign` only ever fetches the corresponding *public*
key from Vault, for JWK/`keyId`/`publicKey` embedding.

Scope of this support:

- **Signing only.** Verification is unaffected and always uses local
  public-key material (e.g. via `--use-embedded-key`, `-k`, `-j`); no Vault
  connection is needed to verify.
- **Asymmetric algorithms only**: ECDSA (`ES256`/`ES384`/`ES512`), RSA
  PKCS#1 v1.5 (`RS256`/`RS384`/`RS512`), RSA-PSS (`PS256`/`PS384`/`PS512`),
  and EdDSA (`Ed25519` - Vault Transit has no Ed448 key type). HMAC
  algorithms are not supported via Vault.
- **Token-based authentication only**, via the `VAULT_ADDR`/`VAULT_TOKEN`
  environment variables (the standard Vault CLI convention), or the
  `--vault-addr`/`--vault-token` CLI flags/`build_vault_client()`
  arguments, which take precedence over the environment variables.
- `hvac` is an **optional** dependency (the `pyjsign[vault]` extra); the core
  package imports and works without it installed, raising a clear error
  only when Vault-based signing is actually requested.

Example:

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=s.xxxxxxxx
pyjsign jsf sign data.json --vault-key my-signing-key ES256 --embed-public-key -o signed.json
pyjsign jsf verify signed.json --use-embedded-key
```

## Building the Documentation

API reference documentation is generated with [Sphinx](https://www.sphinx-doc.org/)
from the project's docstrings:

```bash
pip install -e ".[docs]"
cd docs && make html
```

Open `docs/_build/html/index.html` in a browser to view it. Run `make
clean` to remove generated output, or `make help` for other targets.

## Limitations

This implementation does not support:
- Implicit key resolution (keyId must be resolved by application)
- Advanced certificate validation (dates, revocation, etc.)

## References

- [JSON Signature Format Specification](https://cyberphone.github.io/doc/security/jsf.html)
- [ITU-T Recommendation X.590 - JSON signature scheme (JSS)](https://www.itu.int/rec/T-REC-X.590)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [RFC 7517 - JSON Web Key](https://tools.ietf.org/html/rfc7517)
- [Cryptography Library Docs](https://cryptography.io/)
