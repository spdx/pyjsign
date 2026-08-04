#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Garmin Ltd. or its subsidiaries
#
"""
Literal test vectors from JSF specification Appendix A.

These tests use the exact keys and pre-computed signature values published in
the JSON Signature Format specification at:
https://cyberphone.github.io/doc/security/jsf.html#Test_Vectors

Unlike test_jsf_spec_vectors.py (which tests spec *behavior* using freshly
generated keys), this file verifies our implementation against the actual
byte-for-byte signatures published in the spec, proving interoperability
with the reference implementation.
"""

import binascii

import joserfc.jwk

from pyjsign import JSFSignature

# Common payload used throughout JSF spec Appendix A examples
SPEC_PAYLOAD = {
    "now": "2019-02-10T11:23:06Z",
    "name": "Joe",
    "id": 2200063,
}


def _public_key_from_jwk(jwk):
    """Parse a JWK (which may include private material) and return the public key."""
    key = joserfc.jwk.import_key(jwk)
    return joserfc.jwk.import_key(key.as_dict(private=False))


class TestAppendixAECDSAVectors:
    """EC key test vectors (P-256/ES256, P-384/ES384, P-521/ES512)."""

    P256_JWK = {
        "kid": "example.com:p256",
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
        "d": "6XxMFXhcYT5QN9w5TIg2aSKsbcj-pj4BnZkK7ZOt4B8",
    }

    def test_es256_with_keyid(self):
        """ES256 signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES256",
                "keyId": "example.com:p256",
                "value": "Il-GTiAwCgAX3X9IC7AWfVzySWA18ZLGgHgj3KDfp0-1XsjkVDdypdIFjE9vWdieI6-pHabo6UzcYGubFSVS_w",
            },
        }
        pub_key = _public_key_from_jwk(self.P256_JWK)
        verifier = JSFSignature(pub_key, "ES256")
        assert verifier.verify(signed) is True

    def test_es256_implicit_key(self):
        """ES256 signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES256",
                "value": "0nJX_Ek5PRjV0mQN19E5Hcfdjf_T-I49E0AzJD6VYFq-3PxHXlF6cn52VfOZN9brFfURXV9INiYrB--9v4Ly1Q",
            },
        }
        pub_key = _public_key_from_jwk(self.P256_JWK)
        verifier = JSFSignature(pub_key, "ES256")
        assert verifier.verify(signed) is True

    P384_JWK = {
        "kid": "example.com:p384",
        "kty": "EC",
        "crv": "P-384",
        "x": "o4lIdIXzdJro4jU9g-2q-__i5WcutpJaWwOeSgKL8x6nxKWOPD5rH-POQhJ79l6t",
        "y": "MLnyLIGdTO2feJkCW3rWWKG3elhi1Zmbp068Ejb_1LuI-2cNQsRUqb16TfK588_N",
        "d": "woqAfcmqQ5T0rD-FlnTqjXw8wLOIXACCIy4SoWwy8jiSc_BRVH5jGPwZZUyvP1vd",
    }

    def test_es384_with_embedded_public_key(self):
        """ES384 signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES384",
                "publicKey": {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": self.P384_JWK["x"],
                    "y": self.P384_JWK["y"],
                },
                "value": "OxXAQrGMw1F_PaSnsqDs2y2waf6N9UAR79XgL8lFhkVyHW2m1gyjriLRJUtH6lG3fts_zzhrCLUoLo4dQTFzRPrNilSWaMSyH6BIHldfA-DWE--Pe-o5yHKrEQ97mCcq",
            },
        }
        pub_key = _public_key_from_jwk(self.P384_JWK)
        verifier = JSFSignature(pub_key, "ES384")
        assert verifier.verify(signed) is True

    def test_es384_with_keyid(self):
        """ES384 signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES384",
                "keyId": "example.com:p384",
                "value": "GVCa3WHgNlpW39Aj9X4V2pIng9305zsDZwcv6FCpRRSgfVI3oj0a_GKEKGPHcdkg5efX1mcm9PsY5Puhbx7sDF8I0LyPXncpL2JT5LPekC1qCyGZjQKrVUnuHeCf3zdO",
            },
        }
        pub_key = _public_key_from_jwk(self.P384_JWK)
        verifier = JSFSignature(pub_key, "ES384")
        assert verifier.verify(signed) is True

    def test_es384_implicit_key(self):
        """ES384 signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES384",
                "value": "vH3otMMlnOX7TgkgF39xhJuXtYlevK0m6_Xk9ueYqO_p4jZccOGLAifXlfALnGYlrcwb4-yfptpjI0MIpqW5D4GQ9s-Lac5t9X1y5RbY8o27-M9qRx8-G-R4BuGy74nq",
            },
        }
        pub_key = _public_key_from_jwk(self.P384_JWK)
        verifier = JSFSignature(pub_key, "ES384")
        assert verifier.verify(signed) is True

    P521_JWK = {
        "kid": "example.com:p521",
        "kty": "EC",
        "crv": "P-521",
        "x": "AVb-eD8V1UAzN8GWoUypQ_8xSABA4PwUZ1O_fanjLvbwpuyoniN98ljWt3y93TCrDAqe1089tLCfpJhre8M5frBs",
        "y": "ABORvO-p61zLrGCtgqqqFcQJX_ljnoJ7iDd1IIKZSyksI8aElmtJFCRVSgCyU_P7mSmilqVVaBWhE9fqRHcQ2u_c",
        "d": "AUxbUwj3PKhK08nxKFFRToiriDJyp_bUv0puyt0qch9UwQ5qCjqBqSPAOB5RyvPKy0XwKDhXJGeAGsVqKzsUMRxA",
    }

    def test_es512_with_embedded_public_key(self):
        """ES512 (P-521) signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES512",
                "publicKey": {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": self.P521_JWK["x"],
                    "y": self.P521_JWK["y"],
                },
                "value": "AarnKZEM1hfLd4hpeDguOMV0wAX-7r3z7qRG6RR1MNy3ypliYFSrziQoV1bSYiy7B7VbULQPvtcjhtIAqjRPqaMMAOxplmbKUQNsHQcTxSfrX5jmHbxI_XZpaKv0Fagl7lNmlnHcRx9eeO7Vq8aqIlhQ1afYy34-fTjxHBwe0kNEkyqN",
            },
        }
        pub_key = _public_key_from_jwk(self.P521_JWK)
        verifier = JSFSignature(pub_key, "ES512")
        assert verifier.verify(signed) is True

    def test_es512_with_keyid(self):
        """ES512 (P-521) signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES512",
                "keyId": "example.com:p521",
                "value": "ABePs8Mek8iGGi5CX9FHoLcezTYzY1WRLi_QVgHLPN-bzKUhsGbTDEpebHlB1yv0k9kAe1TAXMJAmB0pSDTkM5wFAaY58KJkfvQAKjQHztYFn4Z4DOPiOXG_18azwKGwynzV6-9XFSd1mcH7R42KZxhIvRGQTKpSLHPxyiSxEH1ccLGh",
            },
        }
        pub_key = _public_key_from_jwk(self.P521_JWK)
        verifier = JSFSignature(pub_key, "ES512")
        assert verifier.verify(signed) is True

    def test_es512_implicit_key(self):
        """ES512 (P-521) signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES512",
                "value": "AHXuqzN7f0IPEcgyJCEJdNS18ITiyt1q7zOMzGlh7ZIDMfOsqY_tx-HMua9UrlMRIEzPJAQqjZKiAgoFwLcBP6yQAQyX_-Ver--u9lEqX566AViazxua-DVPAFpUXGG8Pe5Ju5vikkNNGFQFcQsA5l3g7NZO_OOzkgscZhgX7psl6vsN",
            },
        }
        pub_key = _public_key_from_jwk(self.P521_JWK)
        verifier = JSFSignature(pub_key, "ES512")
        assert verifier.verify(signed) is True


class TestAppendixARSAVectors:
    """RSA key test vectors (RS256, PS256)."""

    R2048_JWK = {
        "kid": "example.com:r2048",
        "kty": "RSA",
        "n": "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcrWhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0Gs4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw",
        "e": "AQAB",
        "d": "KT6KTNAEmb5rdTPxvaOC832J0wD5opDBZcQLH8lLX6go0Tv3Rgxz5bKmn-ZMyL1GegadDiXrSYqd0_MUJuMgGWB8_OnP0D3Q4soEOBIn7DcPt0o9MUxZQsF0DraZzkR02WVRvcIFJucrAEJYAaWYJkjUVbmMb2ltwQwWO21rFHGbpE73nsfr_oAWsZEvKsQZoYm4fh5jVI5-wKyRnKaN1uqAcNgj75cdywCHBVwgEefEgOPM77CDMH0-JumSirQiBfR35-HWRwHwpm09wI6Aqtvgy5bzxvLDDRgrhX4LCPtUHGrUXNJHRKYiHQX6P6bIVuBrHV6VFpyS-5weu0w6kQ",
        "p": "0KOEHi7Tu0tyh_FC95V-JYR9Su_0PfbgR5ry13Yg5B4y2wW4dCX6x4B7ZyvW7ydhr1XMISPX04jtadaOUTOY24lVEgkvdbC3Ezxb_F_N7BMQWZ675UpW_72vuMlvi876-mYg5WWLFUTbzQB1E6Ix0Qjh9j-Hl9fqpeT-BTHX70k",
        "q": "zLEOCwacYw_SnQ8yc8PWtMWy-O0HQnmQajVMujL8CxNPirBfqa76IoDWQmk3CdhX6D8aRN_6NAP28gk7g5H3Xa3f4XADtIHdUfQmCQ1yX5yG2X4XlJh1u0oW18qoaakClY8x_o5y6lY2xg-rc93TfgMDYFCw_778FzNk1qbvU0c",
        "dp": "aQ890xkPY0vNo2i4qQVtHSVHFjoYSi-LpmL_D8IbM-OFBkcuJ8aMLnOjMEOiGpFBHlJc1P9AifN0YYw54-fQfBP-c3OOo3vV5GjLhR0VC2BaJlbJFN_HSUZSOwGsGsGiHf7ZZ8onLBGdgPBPBBDzdug7KI27EJoYPWs_AoyjyIk",
        "dq": "PIePE4uc615edbtsu_cJouNjjWDqaKnyHrYsPlOdXNkVCHonj9ICffmDYpgignLLbA5dAkkJgCA8Ak7gnoOnlrg4ID4zmklc3UNJjBvB2qw65E35QyPijMPYBXAUZUppTTjPG-ub59ge0msH1Hegdv8FHJJABSDBA0tbYm5zDzk",
        "qi": "Pf9CrVihTIRd79NS-eAFxeW9eUa6AYWQH8yNVNMDzuCek8_tSqpra8B0wTyN-p8yEyIZTIXKE7DETIJ79DR88ZXEEJgMt36BQRTsh16pd4T7VmxFYgeY0LOHD-bbNaIr1YaxLa6xOdUxuFfxH3w9SSoh5ezBAmBDMgc99T7EQrs",
    }

    def test_rs256_with_embedded_public_key(self):
        """RS256 signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "RS256",
                "publicKey": {"kty": "RSA", "n": self.R2048_JWK["n"], "e": "AQAB"},
                "value": "IbTdSjKTYiFa-OP4m4wynLLHFxRgY0jwr7lonUIAG8zRpiX9d0ffR_ynGGjchtHH5CtXjfiKtWau0hqejmLqOHzx0I9xcDOLy42aOzBwITU7dElpsXSVYB76i5ekh2pD-swPJ_7E3aIfL1FPDiHjmbxWEjQseifSri4OX27iMqZVjfwIVSA-xKc-_C40r_eDwtB8tdJRaMDnI-Fsu1xf8X7mAiCjhqwRTqEWEySaXN-yGtLgi_ee0OemaBsY7fD2YnL9l9k4fq_A0JwoedRK26VLzoI1HfJ1uK-lrtud0_Ne7IXfZTeZDSKoPHY1LDVzVm0asVvkB10NrLRHO4hDYg",
            },
        }
        pub_key = _public_key_from_jwk(self.R2048_JWK)
        verifier = JSFSignature(pub_key, "RS256")
        assert verifier.verify(signed) is True

    def test_ps256_with_embedded_public_key(self):
        """PS256 (RSA-PSS) signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "PS256",
                "publicKey": {"kty": "RSA", "n": self.R2048_JWK["n"], "e": "AQAB"},
                "value": "SJnq3uAhfcDFv5MLCDhmfGE9_QQG5iDoF6urZp4uvOq-wGPDujImXHNs38XMPCQJVvDIf9Pdw1udXJAUCMkuWL0fBpMeBLriydIYNml4FOGJJ3506I3Hqk-zdjVwfBrguHshS1hniMzTqo8dzlPWxgPzU0KTDeg2xTuXOs2rbvENyqym-jHgn_iCMBQIWCwA5nQIxVmVVHNqF_wY5aUJcO1ySSWVsBk7P2_NpHNO_dOPaxdvvCvrbRne226edD4mOb6adtHoIdXVIhpsulkGEefBnqXQYvmjq_62rnCTZCfXTfM2ylp98NNgT_hyj1IN4yA5Wxwq86UP9of9yOxQ4w",
            },
        }
        pub_key = _public_key_from_jwk(self.R2048_JWK)
        verifier = JSFSignature(pub_key, "PS256")
        assert verifier.verify(signed) is True

    def test_rs256_with_keyid(self):
        """RS256 signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "RS256",
                "keyId": "example.com:r2048",
                "value": "Ra3r-1ZGBh-UkMzjyS70mRuw3LmC7E8TmG5y0V7EIZrnvz5lfqXl0DL20ftSpbwzFPAlkH_iywKH9g85e5TYQUlMsI7ptsjNURQv-2dRbOq4UhCjbxA8T33424tfraHMutKhJ4vhHhvDgYLqDg9Pwh2RrgcXrBc5VgCAFSR2mhzkjzyJlrOekByf6q9MyPpMjok6wBDkEoWQ8c2vEdEbck6kARYEr3AeOTsnsUptkgbsJ2xQ4ZK4Al93LMW6xiuIa1ATuYwNUilWDhJqYUnAEA54uYRNEFULYqLRjBIGipnFtz7-802K1DfjUtHSL7unwZRNg5CtFHlWAeJ8rhv-mA",
            },
        }
        pub_key = _public_key_from_jwk(self.R2048_JWK)
        verifier = JSFSignature(pub_key, "RS256")
        assert verifier.verify(signed) is True

    def test_rs256_implicit_key(self):
        """RS256 signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "RS256",
                "value": "X6k3LmtM2UT4N13yu-vUBdM84hfYZDbxRdt49WacS3OAbYzHE33XZK5i8J7enIzvZEggxeIhQ1Wu2LpTqxNgZEjAo7qYNl4W3rilme0KNH-NnB-4BHQawqCv9_uzKnFt3MwK_nyc-Wl-7ngKrL2LvbLgY4i1GM8u0vBB_92QDMYrqVC3S6nRh9IUaQcLShyAiSMa6BwbEg0mAZgGZxMsu2tEXvNyyrYV0Z4Fsl_SMVon_kXCAFuJB-WpdpIan6GGQ1wrSkHXu4OZjvabO0qIqkE3aP2WWUPCfHbtI-Z0Iq4N3U5D56-Y8Q6OUWBWkd4kt3dAD1Q2OBbA42sKUGROnw",
            },
        }
        pub_key = _public_key_from_jwk(self.R2048_JWK)
        verifier = JSFSignature(pub_key, "RS256")
        assert verifier.verify(signed) is True


class TestAppendixAEdDSAVectors:
    """OKP key test vectors (Ed25519, Ed448)."""

    ED25519_JWK = {
        "kid": "example.com:ed25519",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "_kms9bkrbpI1lPLoM2j2gKySS-k89TOuyvgC43dX-Mk",
        "d": "0flr-6bXs459f9qwAq20Zs3NizTGIEH5_rTDFoumFV4",
    }

    def test_ed25519_with_embedded_public_key(self):
        """Ed25519 signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed25519",
                "publicKey": {"kty": "OKP", "crv": "Ed25519", "x": self.ED25519_JWK["x"]},
                "value": "UtN9-gMgTkfAdBJRX4gi0s6iKYiilO5EmXRD4KRSEnPKo5Og1ltbGYZecdJqKphCXkboIE_pecfszHEQXeqqDA",
            },
        }
        pub_key = _public_key_from_jwk(self.ED25519_JWK)
        verifier = JSFSignature(pub_key, "Ed25519")
        assert verifier.verify(signed) is True

    def test_ed25519_with_keyid(self):
        """Ed25519 signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed25519",
                "keyId": "example.com:ed25519",
                "value": "Z5GCvK_W6s1aiEVHlLlqlc2Q-Hq07lOkSIjKVdhjwBHnATwevYfZ8GbooHjjbN8Eb0JN-E4zT40dbGi6TnjPCA",
            },
        }
        pub_key = _public_key_from_jwk(self.ED25519_JWK)
        verifier = JSFSignature(pub_key, "Ed25519")
        assert verifier.verify(signed) is True

    def test_ed25519_implicit_key(self):
        """Ed25519 signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed25519",
                "value": "VIjBJ-x4A7wPf0QiPBEvLEcPLfuMPJzaxooHPk3I65Vst2j1YYZvfc7T83oiujkUyCRbJrY5qX4rCk-OVFEmCw",
            },
        }
        pub_key = _public_key_from_jwk(self.ED25519_JWK)
        verifier = JSFSignature(pub_key, "Ed25519")
        assert verifier.verify(signed) is True

    ED448_JWK = {
        "kid": "example.com:ed448",
        "kty": "OKP",
        "crv": "Ed448",
        "x": "IUkRrGrNQFnHA-pIcgwzTxyL4BlWyHqC6LkZbgyHMsM14mC2NfpW9QV_Ao7mkQXIZM2OCgCimEQA",
        "d": "EzABSeOFsw-6ydqO3YW4ZPONZqEOQ-0DARQ1U-v_jOCyXPI6FkGS1x1a5CAVY2HNTcfNYGKBriKC",
    }

    def test_ed448_with_embedded_public_key(self):
        """Ed448 signature with an embedded "publicKey" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed448",
                "publicKey": {"kty": "OKP", "crv": "Ed448", "x": self.ED448_JWK["x"]},
                "value": "7etBe_-_lSMU1OXH38PRmT3MHvnf0IQcvX2GX-l16Ax7_-V7l0TDH31-ioXo0B8PV75PspWEm3-AVHmKpIUAbb8FU1k7KJcCc1m0HQOvbiDlIh3j_G10wrv5edpjDWBQ8Xjek94vGpKM7kA9Y--EkS4A",
            },
        }
        pub_key = _public_key_from_jwk(self.ED448_JWK)
        verifier = JSFSignature(pub_key, "Ed448")
        assert verifier.verify(signed) is True

    def test_ed448_with_keyid(self):
        """Ed448 signature referencing the key by "keyId" verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed448",
                "keyId": "example.com:ed448",
                "value": "OCU7mH_M9lf1hOKMhQBTqOOhSQRiKg9GyIGk-D1c1T5bnon7v0Mfi879N4vtA4KSuExxfUUldnQAaEWNLdTgVp8ojm2WVieRAwgAlxddJ9KMqdcXoi-SJxLByySUG-UJj3MiJmW7hhRzergMTj31-y4A",
            },
        }
        pub_key = _public_key_from_jwk(self.ED448_JWK)
        verifier = JSFSignature(pub_key, "Ed448")
        assert verifier.verify(signed) is True

    def test_ed448_implicit_key(self):
        """Ed448 signature with no key info (implicit key) verifies correctly."""
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "Ed448",
                "value": "SUjAWwmGUVzFkjUBs4FPCgrikPWyivcqLIlzADGgT8m4LwAvmLDSTdn8URgML5egnUDqLzBHeGqA_H_t6z-ziw6EkgSdj88Uf_q2psWsQdltfe4EXuGjCgK5VTGgO1leN952xO9gjJD2KvofANdKsRsA",
            },
        }
        pub_key = _public_key_from_jwk(self.ED448_JWK)
        verifier = JSFSignature(pub_key, "Ed448")
        assert verifier.verify(signed) is True


class TestAppendixAHMACVectors:
    """Symmetric (oct) key test vectors (HS256, HS384, HS512).

    Per the spec, HMAC keys are raw secret bytes referenced by an arbitrary
    "keyId" (e.g. "a256bitkey"); the hex strings below are the actual secret
    key material published alongside the test vectors.
    """

    def test_hs256(self):
        """HS256 signature verifies with the published 256-bit key."""
        key = binascii.unhexlify("7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a")
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "HS256",
                "keyId": "a256bitkey",
                "value": "GJ6Jhb-PfHpN6KPcjHBNxbO9j56ShgUh13JfmZ3ORkI",
            },
        }
        verifier = JSFSignature(key, "HS256")
        assert verifier.verify(signed) is True

    def test_hs384(self):
        """HS384 signature verifies with the published 384-bit key."""
        key = binascii.unhexlify(
            "37b7daeedc3403eb865a506c19597a37582ad5059e08438ada8bf544ee44bb3"
            "024a15f8fa191bbe7a533a56c9fc1db1d"
        )
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "HS384",
                "keyId": "a384bitkey",
                "value": "FjkRAZS-HsGsC_WPKsF2fmaNO7CPp90asbgXfOPQjolyK_qQaOuJH_u7PgonjzN9",
            },
        }
        verifier = JSFSignature(key, "HS384")
        assert verifier.verify(signed) is True

    def test_hs512(self):
        """HS512 signature verifies with the published 512-bit key."""
        key = binascii.unhexlify(
            "83d26e96b71a5dd767c215f201ef5884fb03dfe5a8ee9612d4e3c942e84d45d"
            "fdc5801cb8379958f3af600d68eba1a14e945c90f1655671f042cea7b34d53236"
        )
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "HS512",
                "keyId": "a512bitkey",
                "value": "VJHJXrZhVMMWTKTJktmdE5J4xBjKwtdf25eItui4fIGuyYsiZD5M9n573WZ0XgM9q48gG1KpTee4q8LCW4a7qQ",
            },
        }
        verifier = JSFSignature(key, "HS512")
        assert verifier.verify(signed) is True


class TestAppendixAMultiSignature:
    """Literal "Multiple Signatures" test vector (p256#es256,r2048#rs256@mult-jwk.json)."""

    SIGNED = {
        **SPEC_PAYLOAD,
        "signature": {
            "signers": [
                {
                    "algorithm": "ES256",
                    "publicKey": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
                        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
                    },
                    "value": (
                        "Nmkfbz5AfQbLW7m3uZrc12yrXoP-skILw58Z9KRPFW0OYyrnuagJTVvKAfpaZ6SznQ69"
                        "IGM_J8bBnsuois6JAg"
                    ),
                },
                {
                    "algorithm": "RS256",
                    "publicKey": {
                        "kty": "RSA",
                        "n": TestAppendixARSAVectors.R2048_JWK["n"],
                        "e": "AQAB",
                    },
                    "value": (
                        "JqJPRtttK-_whpZthVGZne1MONlMh5co7s8IWsI1-HAlqyYQTqmIIaIVBUc00MKxGZk"
                        "le99d7GuF2GGKb_7aJtdsA5ZNUYHzYReaX0xg6TKcM9ppWqeFQx_DXR6GlGv3NNhNqBy"
                        "2uCT_vnwErlWlNe_KQd3KJeQDrqHVQHmvCrUnx2ShXQp6MhLkZ6mrAN_J2I9z-i6NWFR"
                        "G91aXfnupKvmrUZ8834ASbo5i2uEXbT8VeG9Ihuwi9iP7hhLmGd3ocUTsdtB4jTU2js7"
                        "Q-F24_99SbIXW50Tfrp_TZWIjF9CqW8278OE4kGsf9Qub4VkR0b7MXYFRsE0fxTw4rdP"
                        "V7A"
                    ),
                },
            ]
        },
    }

    def test_verify_multi_with_embedded_public_keys(self):
        """The literal spec multisignature vector verifies using get_public_keys()."""
        keys = JSFSignature.get_public_keys(self.SIGNED)
        assert JSFSignature.verify_multi(self.SIGNED, keys=keys) is True

    def test_verify_multi_tampered_payload_fails(self):
        """Tampering with the shared payload invalidates every signer."""
        keys = JSFSignature.get_public_keys(self.SIGNED)
        tampered = dict(self.SIGNED)
        tampered["id"] = 9999999
        assert JSFSignature.verify_multi(tampered, keys=keys) is False


class TestAppendixASignatureChain:
    """Literal "Signature Chains" test vector (p256#es256,r2048#rs256@chai-jwk.json)."""

    SIGNED = {
        **SPEC_PAYLOAD,
        "signature": {
            "chain": [
                {
                    "algorithm": "ES256",
                    "publicKey": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
                        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg",
                    },
                    "value": (
                        "VJKH2mR8qwq5vPLbwA9i-IYoSdI8lLQ9Orz9vANsOCMw0FQB4KjEuBfdKJ1D2JSFoX7K"
                        "caMvCz24sT5cbeN8TA"
                    ),
                },
                {
                    "algorithm": "RS256",
                    "publicKey": {
                        "kty": "RSA",
                        "n": TestAppendixARSAVectors.R2048_JWK["n"],
                        "e": "AQAB",
                    },
                    "value": (
                        "YhGrlUD-wwoMLxTgZcDLlRq_dlUV300yffV6ejjbxhszocSI1qGu8Yn0p1vVTfgxPfR1"
                        "VErQ_ME-XFAfck1_1vrrrWdv9Vg5SzHrhu5YnJAhT7QUq3gR1s3iH9nS9xcA7HB3nuYc9"
                        "4z_vfDY2s3u-q-858Q6jnIGy0ejpOeEK7jSqwTbDkwRo5tguXmArMQHY92NB8Pt2hI_11"
                        "ZJH1CuShKixTtKP6DOu8Q8f8wgjC2AHcTjogeW7bMcH6k4kjdQGkwWWHSCjLVTxqxkpMc"
                        "dkn2gaFBtaxzWd7kXAxMF8MyjoXV_J-cQn5fU6uImR8MbMVYUmpPMVbvToEfXSZBiuw"
                    ),
                },
            ]
        },
    }

    def test_verify_chain_with_embedded_public_keys(self):
        """The literal spec signature chain vector verifies using get_public_keys()."""
        keys = JSFSignature.get_public_keys(self.SIGNED)
        assert JSFSignature.verify_chain(self.SIGNED, keys=keys) is True

    def test_verify_chain_tampered_payload_fails(self):
        """Tampering with the shared payload invalidates the whole chain."""
        keys = JSFSignature.get_public_keys(self.SIGNED)
        tampered = dict(self.SIGNED)
        tampered["id"] = 9999999
        assert JSFSignature.verify_chain(tampered, keys=keys) is False


class TestAppendixATamperDetection:
    """Sanity checks that literal spec vectors correctly reject tampered payloads."""

    def test_es256_tampered_payload_fails(self):
        """Modifying a payload field after copying a real spec signature must fail verification."""
        p256_jwk = TestAppendixAECDSAVectors.P256_JWK
        signed = {
            **SPEC_PAYLOAD,
            "signature": {
                "algorithm": "ES256",
                "value": "0nJX_Ek5PRjV0mQN19E5Hcfdjf_T-I49E0AzJD6VYFq-3PxHXlF6cn52VfOZN9brFfURXV9INiYrB--9v4Ly1Q",
            },
        }
        signed["id"] = 9999999  # tamper with signed payload
        pub_key = _public_key_from_jwk(p256_jwk)
        verifier = JSFSignature(pub_key, "ES256")
        assert verifier.verify(signed) is False
