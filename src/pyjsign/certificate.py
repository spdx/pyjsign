#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
X.509 certificate chain support, shared by both JSF (``certificatePath``) and
JSS (``public_cert_chain``).
"""

import base64
from typing import List, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class CertificateHandler:
    """Parse and validate X.509 certificates."""

    @staticmethod
    def parse_certificate_path(cert_path: List[str]) -> List[x509.Certificate]:
        """
        Parse a list of base64-encoded DER certificates.

        Args:
            cert_path: List of base64-encoded certificate strings

        Returns:
            List of Certificate objects

        Raises:
            ValueError: If certificate format is invalid
        """
        certificates = []
        for cert_data in cert_path:
            try:
                # Try base64 decoding
                der_data = base64.b64decode(cert_data)
                cert = x509.load_der_x509_certificate(der_data, default_backend())
                certificates.append(cert)
            except Exception as e:
                raise ValueError(f"Failed to parse certificate: {e}")

        return certificates

    @staticmethod
    def encode_certificate_path(certs: List[Union[x509.Certificate, bytes]]) -> List[str]:
        """
        Encode a certificate chain as a list of base64-encoded DER strings,
        suitable for embedding as a signature object's certificate chain
        (order is preserved, leaf-to-root).

        Args:
            certs: Ordered list of X.509 certificates, each either an
                ``x509.Certificate`` object or raw DER-encoded bytes

        Returns:
            List of base64-encoded DER certificate strings, same order

        Raises:
            ValueError: If an entry is neither an ``x509.Certificate`` nor
                ``bytes``
        """
        encoded = []
        for cert in certs:
            if isinstance(cert, x509.Certificate):
                der_data = cert.public_bytes(encoding=serialization.Encoding.DER)
            elif isinstance(cert, bytes):
                der_data = cert
            else:
                raise ValueError(
                    f"Certificate entries must be x509.Certificate or bytes, got {type(cert)}"
                )
            encoded.append(base64.b64encode(der_data).decode("ascii"))

        return encoded
