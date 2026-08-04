#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Example usage of the JSON Signature Format (JSF) implementation.
Demonstrates signing and verifying JSON objects.
"""

import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from pyjsign import JSFSignature


def example_ec_signing():
    """Example: EC key signing with embedded public key."""
    print("\n=== EC Signing with Embedded Public Key ===\n")

    # Generate an EC key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create a signer
    signer = JSFSignature(private_key, "ES256")

    # Sign a JSON object
    obj = {"timestamp": "2024-01-15T10:30:00Z", "message": "Hello, JSF!", "amount": 42}

    print(f"Original object:\n{json.dumps(obj, indent=2)}\n")

    signed = signer.sign(obj)

    print(f"Signed object:\n{json.dumps(signed, indent=2)}\n")

    # Verify the signature
    verifier = JSFSignature(private_key, "ES256")
    is_valid = verifier.verify(signed)

    print(f"Signature valid: {is_valid}\n")

    # Demonstrate tampering detection
    print("--- Tampering Detection ---\n")
    tampered = dict(signed)
    tampered["amount"] = 9999

    is_valid_tampered = verifier.verify(tampered)
    print(f"Tampered object valid: {is_valid_tampered}\n")


def example_custom_signature_property():
    """Example: Using a custom signature property name."""
    print("\n=== Custom Signature Property Name ===\n")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Use custom property name
    signer = JSFSignature(private_key, "ES256", signature_property="authorizationSignature")

    obj = {"user": "alice@example.com", "action": "approve_transfer"}

    signed = signer.sign(obj)

    print(f"Signed with custom property:\n{json.dumps(signed, indent=2)}\n")
    print(f"Has 'authorizationSignature': {'authorizationSignature' in signed}")
    print(f"Has 'signature': {'signature' in signed}\n")

    # Verify
    verifier = JSFSignature(private_key, "ES256", signature_property="authorizationSignature")
    print(f"Signature valid: {verifier.verify(signed)}\n")


def example_multiple_algorithms():
    """Example: Demonstrate different algorithms."""
    print("\n=== Multiple Algorithms ===\n")

    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    obj = {"test": "data", "value": 123}

    # ES256 (ECDSA with P-256)
    print("1. ES256 (ECDSA P-256):")
    ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ec_signer = JSFSignature(ec_key, "ES256")
    ec_signed = ec_signer.sign(obj)
    print(f"   Signature length: {len(ec_signed['signature']['value'])} chars")
    print(f"   Valid: {JSFSignature(ec_key, 'ES256').verify(ec_signed)}\n")

    # RS256 (RSA with PKCS#1)
    print("2. RS256 (RSA PKCS#1):")
    rsa_key = rsa.generate_private_key(65537, 2048, default_backend())
    rsa_signer = JSFSignature(rsa_key, "RS256")
    rsa_signed = rsa_signer.sign(obj)
    print(f"   Signature length: {len(rsa_signed['signature']['value'])} chars")
    print(f"   Valid: {JSFSignature(rsa_key, 'RS256').verify(rsa_signed)}\n")

    # PS256 (RSA-PSS)
    print("3. PS256 (RSA-PSS):")
    pss_signer = JSFSignature(rsa_key, "PS256")
    pss_signed = pss_signer.sign(obj)
    print(f"   Signature length: {len(pss_signed['signature']['value'])} chars")
    print(f"   Valid: {JSFSignature(rsa_key, 'PS256').verify(pss_signed)}\n")

    # EdDSA
    print("4. EdDSA (Ed25519):")
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_signer = JSFSignature(ed_key, "EdDSA")
    ed_signed = ed_signer.sign(obj)
    print(f"   Signature length: {len(ed_signed['signature']['value'])} chars")
    print(f"   Valid: {JSFSignature(ed_key, 'EdDSA').verify(ed_signed)}\n")


def example_complex_object():
    """Example: Signing a complex nested object."""
    print("\n=== Complex Nested Object ===\n")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Complex nested structure
    obj = {
        "transaction": {
            "id": "txn_12345",
            "amount": 1000.50,
            "currency": "USD",
            "timestamp": "2024-01-15T10:30:00Z",
        },
        "from": {"account": "alice@example.com", "type": "checking"},
        "to": {"account": "bob@example.com", "type": "savings"},
        "metadata": {"reference": "Payment for services", "tags": ["invoice", "paid"]},
    }

    print(f"Original object:\n{json.dumps(obj, indent=2)}\n")

    signer = JSFSignature(private_key, "ES256")
    signed = signer.sign(obj)

    # Show only the signature portion
    print(f"Signature object:\n{json.dumps(signed['signature'], indent=2)}\n")

    # Verify
    verifier = JSFSignature(private_key, "ES256")
    print(f"Signature valid: {verifier.verify(signed)}")
    print(f"Original object preserved: {signed['transaction']['id'] == 'txn_12345'}\n")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("JSON Signature Format (JSF) - Usage Examples")
    print("=" * 60)

    example_ec_signing()
    example_custom_signature_property()
    example_multiple_algorithms()
    example_complex_object()

    print("\n" + "=" * 60)
    print("All examples completed successfully!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
