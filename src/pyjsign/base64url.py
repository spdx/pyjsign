#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""Base64url (RFC 4648 Section 5) encode/decode helpers used for signature values."""

import base64


def base64url_decode(data: str) -> bytes:
    """Decode a base64url string (RFC 4648), tolerating missing padding."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding

    return base64.urlsafe_b64decode(data)


def base64url_encode(data: bytes) -> str:
    """Encode bytes to an unpadded base64url string (RFC 4648)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
