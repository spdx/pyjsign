#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Abstract base class for delegating signing to a remote/external signer.

Shared by both ``pyjsign.jsf.JSFSignature`` (JSF) and
``pyjsign.jss.JSSSignature`` (JSS, ITU-T X.590).
"""

from abc import ABC, abstractmethod


class Signer(ABC):
    """
    Abstract base class for delegating the actual signing operation to
    something other than a local private key, e.g. a remote signer such
    as a HashiCorp Vault Transit key (see ``pyjsign.vault_signer``).

    Implementations receive an algorithm name and the data to sign (for
    ``JSFSignature``, the canonicalized signing input; for ``JSSSignature``,
    the digest computed per its ``hash_algorithm``), and must return the
    raw signature bytes in the same format each caller's local signing
    methods produce (e.g. concatenated fixed-width r||s for ECDSA) --
    i.e. before base64url encoding, which the caller applies uniformly
    itself.
    """

    @abstractmethod
    def sign(self, algorithm: str, data: bytes) -> bytes:
        """
        Sign ``data`` for the given ``algorithm``, and return the raw
        signature bytes.
        """
