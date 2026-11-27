#
#  SelfTest/PublicKey/test_import_openssh_cert.py: import of OpenSSH certificates
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import binascii
import struct

import pytest

from Crypto.PublicKey import DSA, ECC, RSA
from Crypto.SelfTest.PublicKey.test_import_DSA import TestImportKey as _DSAVectors

# Certificates created with OpenSSH 10.2 (ssh-keygen -s ca -I test-<name> -n alice,bob
# -V 20260101:20360101 -z 42, with -h for host256), and the certified public keys.
# Each item: (certificate, public key)
VECTORS = {
    "rsa1024": (
        b"ssh-rsa-cert-v01@openssh.com "
        b"AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgiqPgDPzeVxo80uVLhauDKWOlXyd+"
        b"SBXSaxOURxziVJ0AAAADAQABAAAAgQDbqwHIejsbDcprrqzsZsDv0trB+PJRQYT0CHwe/UNDUAYT"
        b"jw4tFJb9xplAJSN6wInG35E2d9uLo9IQ4JZQnpxQoXomh8I4o8s15SWTnJ+FJlEp4FilwOhrXWZo"
        b"ypLp5xGKFyW98G1p28DCgvWGghi1klqRsIX5/gIRt6EaIx+cawAAAAAAAAAqAAAAAQAAAAx0ZXN0"
        b"LXJzYTEwMjQAAAAQAAAABWFsaWNlAAAAA2JvYgAAAABpVbkAAAAAAHwkXwAAAAAAAAAAggAAABVw"
        b"ZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAA"
        b"ABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQt"
        b"dXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACC+D1qKV2X/S09WQ79Umv4fNETS"
        b"txSRC1MdIAE7TMjRjAAAAFMAAAALc3NoLWVkMjU1MTkAAABAIrVH9h9rw6aBaV2X5WPjjNvJcmIr"
        b"n6anV26wzS06xRf8SyVcXVbc/j2NrmO+5vFxhcJfcejfku9+S+YjPpz2Bw=="
        b" user@example",
        b"ssh-rsa "
        b"AAAAB3NzaC1yc2EAAAADAQABAAAAgQDbqwHIejsbDcprrqzsZsDv0trB+PJRQYT0CHwe/UNDUAYT"
        b"jw4tFJb9xplAJSN6wInG35E2d9uLo9IQ4JZQnpxQoXomh8I4o8s15SWTnJ+FJlEp4FilwOhrXWZo"
        b"ypLp5xGKFyW98G1p28DCgvWGghi1klqRsIX5/gIRt6EaIx+caw=="
        b" user@example",
    ),
    "ecdsa256": (
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com "
        b"AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAglQSjxYfass2W"
        b"JD0Ecp8LDfc+KIqm7hJ/mB4Jz4w0hIAAAAAIbmlzdHAyNTYAAABBBMA4Rn75QS2q7Jec+0QhjUI8"
        b"UTwZT7iqxiG7OWQH4fddj/jlqkIXvPMzcT0yeOTi1I40VUPm9uLT9uReJXcz9z0AAAAAAAAAKgAA"
        b"AAEAAAANdGVzdC1lY2RzYTI1NgAAABAAAAAFYWxpY2UAAAADYm9iAAAAAGlVuQAAAAAAfCRfAAAA"
        b"AAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndh"
        b"cmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAA"
        b"AAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL4PWopXZf9L"
        b"T1ZDv1Sa/h80RNK3FJELUx0gATtMyNGMAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBjJevdeJReKO6C"
        b"RetZtahWRV5RTksNT9XhAU3wes4Wl5+BuJFr1eG1Ce6t/xTpLYvVXLYqINZ56uc0J153XacA"
        b" user@example",
        b"ecdsa-sha2-nistp256 "
        b"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMA4Rn75QS2q7Jec+0QhjUI8"
        b"UTwZT7iqxiG7OWQH4fddj/jlqkIXvPMzcT0yeOTi1I40VUPm9uLT9uReJXcz9z0="
        b" user@example",
    ),
    "ecdsa384": (
        b"ecdsa-sha2-nistp384-cert-v01@openssh.com "
        b"AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgvJJVw3TIJwpM"
        b"ALY6BfJav2yLgU1tNtlNyGGhM3M1EBIAAAAIbmlzdHAzODQAAABhBJkWEzzMfPs095ULi8MGlH2c"
        b"9lb5x/lFCRhkIUbh2DbZKG7qbieYNJ+B9KlNPqmZVzzDiAheGxRe48fKjhmTtTGEv1XOC4nxEH8+"
        b"8fgm4LVlbtqp63W1qb1PtAl9f375PwAAAAAAAAAqAAAAAQAAAA10ZXN0LWVjZHNhMzg0AAAAEAAA"
        b"AAVhbGljZQAAAANib2IAAAAAaVW5AAAAAAB8JF8AAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3"
        b"YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQt"
        b"Zm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAA"
        b"AAAAADMAAAALc3NoLWVkMjU1MTkAAAAgvg9aildl/0tPVkO/VJr+HzRE0rcUkQtTHSABO0zI0YwA"
        b"AABTAAAAC3NzaC1lZDI1NTE5AAAAQLJxOzmbMxdZVDvN5e0dSHfbkHdZbJJt63Nx8/pDEYa4p2yh"
        b"H8KFc9PjrM5vRHVvWapWb8AfDTGrFL2vYVTkEgA="
        b" user@example",
        b"ecdsa-sha2-nistp384 "
        b"AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJkWEzzMfPs095ULi8MGlH2c"
        b"9lb5x/lFCRhkIUbh2DbZKG7qbieYNJ+B9KlNPqmZVzzDiAheGxRe48fKjhmTtTGEv1XOC4nxEH8+"
        b"8fgm4LVlbtqp63W1qb1PtAl9f375Pw=="
        b" user@example",
    ),
    "ecdsa521": (
        b"ecdsa-sha2-nistp521-cert-v01@openssh.com "
        b"AAAAKGVjZHNhLXNoYTItbmlzdHA1MjEtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgTwqucUNInCNd"
        b"5dNT6UMSXzArwKLCgXDaf3c1/QEMWy8AAAAIbmlzdHA1MjEAAACFBACL+/8VyapJsiatAypN5uVM"
        b"ju4W/kUfOrlWVjApv3P0jIh3HwTiW3ePdfvVQUdB8uf6VzEi4MEJxLpRSrhmHIabAwCo8fqBWtoJ"
        b"I4SePM4F5yH7Pjp/E78F1MOI3yIU0ov1BKVcMrS0mLSstDEEa9aqROOH2Y9NPFTMBqhryfbOHc0j"
        b"cwAAAAAAAAAqAAAAAQAAAA10ZXN0LWVjZHNhNTIxAAAAEAAAAAVhbGljZQAAAANib2IAAAAAaVW5"
        b"AAAAAAB8JF8AAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQt"
        b"YWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVy"
        b"bWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkA"
        b"AAAgvg9aildl/0tPVkO/VJr+HzRE0rcUkQtTHSABO0zI0YwAAABTAAAAC3NzaC1lZDI1NTE5AAAA"
        b"QB0WmL5Umgn64GIYLIjV2uoRnUfmfIijSe4nvG01dR3HjfFj0Cn7QmBklwf94TYo6zNPO6CVTGDl"
        b"+eo6kKQiFAw="
        b" user@example",
        b"ecdsa-sha2-nistp521 "
        b"AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACL+/8VyapJsiatAypN5uVM"
        b"ju4W/kUfOrlWVjApv3P0jIh3HwTiW3ePdfvVQUdB8uf6VzEi4MEJxLpRSrhmHIabAwCo8fqBWtoJ"
        b"I4SePM4F5yH7Pjp/E78F1MOI3yIU0ov1BKVcMrS0mLSstDEEa9aqROOH2Y9NPFTMBqhryfbOHc0j"
        b"cw=="
        b" user@example",
    ),
    "ed25519": (
        b"ssh-ed25519-cert-v01@openssh.com "
        b"AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHUQQKTb4D6IgNEJS6csImA8"
        b"HX+blTbUatrrEXHBQw4KAAAAIOb5aX/gS5PRbVnLGk1rnOSEHpurkSwNuo97pCIpJ0eHAAAAAAAA"
        b"ACoAAAABAAAADHRlc3QtZWQyNTUxOQAAABAAAAAFYWxpY2UAAAADYm9iAAAAAGlVuQAAAAAAfCRf"
        b"AAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZv"
        b"cndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkA"
        b"AAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL4PWopX"
        b"Zf9LT1ZDv1Sa/h80RNK3FJELUx0gATtMyNGMAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBg5OWJ9hWS"
        b"A0pZS4atU9qkmucnt8p/sm4XNxZ0CDQO0CjnaDwGgojsV3mUNx2CuvmclNDVt6qBibGIQpFBeRcF"
        b" user@example",
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOb5aX/gS5PRbVnLGk1rnOSEHpurkSwNuo97pCIpJ0eH user@example",
    ),
    "host256": (
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com "
        b"AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgof//w0tZdeWj"
        b"nGMZpK8iVG+427uvO4asNqwXnvMeHeQAAAAIbmlzdHAyNTYAAABBBMA4Rn75QS2q7Jec+0QhjUI8"
        b"UTwZT7iqxiG7OWQH4fddj/jlqkIXvPMzcT0yeOTi1I40VUPm9uLT9uReJXcz9z0AAAAAAAAAAAAA"
        b"AAIAAAAJaG9zdC10ZXN0AAAAEAAAAAxob3N0LmV4YW1wbGUAAAAAaVW5AAAAAAB8JF8AAAAAAAAA"
        b"AAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACC+D1qKV2X/S09WQ79Umv4fNETStxSRC1MdIAE7"
        b"TMjRjAAAAFMAAAALc3NoLWVkMjU1MTkAAABAEL3hTK/UwTE1cNO0Kjifx3FRm5FqRGNM5gP+XpCP"
        b"V/hVty6jijSFWxI1usTqseMqj4TevjnxnUgl1KOmb7CBDw=="
        b" user@example",
        b"ecdsa-sha2-nistp256 "
        b"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMA4Rn75QS2q7Jec+0QhjUI8"
        b"UTwZT7iqxiG7OWQH4fddj/jlqkIXvPMzcT0yeOTi1I40VUPm9uLT9uReJXcz9z0="
        b" user@example",
    ),
}

MODULES = {
    "rsa1024": RSA,
    "ecdsa256": ECC,
    "ecdsa384": ECC,
    "ecdsa521": ECC,
    "ed25519": ECC,
    "host256": ECC,
}


def _string(data):
    return struct.pack(">I", len(data)) + data


def _fields(ssh_line):
    """The fields of the blob of an OpenSSH public key line (type first)"""
    blob = binascii.a2b_base64(ssh_line.split(b" ")[1])
    fields = []
    while blob:
        length = struct.unpack(">I", blob[:4])[0]
        fields.append(blob[4 : 4 + length])
        blob = blob[4 + length :]
    return fields


def _make_cert(cert_type, key_fields, kind=1, inner_type=None, trailing=b""):
    """Build an OpenSSH certificate (with a fake signature) for the given key fields"""
    blob = _string(inner_type or cert_type) + _string(b"\x01" * 32)
    blob += b"".join(_string(f) for f in key_fields)
    blob += struct.pack(">QI", 42, kind) + _string(b"key-id") + _string(_string(b"alice"))
    blob += struct.pack(">QQ", 0, 2**64 - 1) + _string(b"") + _string(b"") + _string(b"")
    blob += _string(_string(b"ssh-ed25519") + _string(bytes(32))) + _string(b"fake signature")
    return cert_type + b" " + binascii.b2a_base64(blob + trailing, newline=False) + b" comment"


@pytest.mark.parametrize("name", list(VECTORS))
def test_import_certificate(name):
    cert, pub = VECTORS[name]
    module = MODULES[name]
    key = module.import_key(cert)
    assert not key.has_private()
    assert key == module.import_key(pub)
    # Also as str, and with a final newline
    assert key == module.import_key(cert.decode("latin-1") + "\n")


def test_import_dsa_certificate():
    # OpenSSH 10 no longer supports DSA: the certificate is built here
    pub = _DSAVectors.ssh_pub.encode()
    fields = _fields(pub)
    assert fields[0] == b"ssh-dss"
    cert = _make_cert(b"ssh-dss-cert-v01@openssh.com", fields[1:])
    assert DSA.import_key(cert) == DSA.import_key(pub)


def test_import_synthetic_matches_real():
    # The test builder creates certificates that are parsed as the real ones
    cert, pub = VECTORS["ed25519"]
    fields = _fields(pub)
    synthetic = _make_cert(b"ssh-ed25519-cert-v01@openssh.com", fields[1:])
    assert ECC.import_key(synthetic) == ECC.import_key(cert)


def test_host_certificate():
    fields = _fields(VECTORS["ed25519"][1])
    cert = _make_cert(b"ssh-ed25519-cert-v01@openssh.com", fields[1:], kind=2)
    assert ECC.import_key(cert) == ECC.import_key(VECTORS["ed25519"][1])


def test_wrong_module():
    with pytest.raises(ValueError):
        RSA.import_key(VECTORS["ed25519"][0])
    with pytest.raises(ValueError):
        ECC.import_key(VECTORS["rsa1024"][0])
    with pytest.raises(ValueError):
        DSA.import_key(VECTORS["rsa1024"][0])


class TestInvalidCertificates:
    fields = _fields(VECTORS["rsa1024"][1])[1:]
    cert_type = b"ssh-rsa-cert-v01@openssh.com"

    def test_truncated(self):
        cert, _ = VECTORS["rsa1024"]
        cert_type, b64, _ = cert.split(b" ")
        blob = binascii.a2b_base64(b64)
        for length in (0, 10, 60, len(blob) // 2, len(blob) - 1):
            truncated = cert_type + b" " + binascii.b2a_base64(blob[:length], newline=False)
            with pytest.raises(ValueError):
                RSA.import_key(truncated)

    def test_trailing_data(self):
        with pytest.raises(ValueError):
            RSA.import_key(_make_cert(self.cert_type, self.fields, trailing=b"\x00"))

    def test_type_mismatch(self):
        cert = _make_cert(self.cert_type, self.fields, inner_type=b"ssh-dss-cert-v01@openssh.com")
        with pytest.raises(ValueError):
            RSA.import_key(cert)

    @pytest.mark.parametrize("kind", [0, 3])
    def test_wrong_kind(self, kind):
        with pytest.raises(ValueError):
            RSA.import_key(_make_cert(self.cert_type, self.fields, kind=kind))

    def test_bad_base64(self):
        with pytest.raises(ValueError):
            RSA.import_key(self.cert_type + b" !!!! comment")

    def test_unknown_version(self):
        cert = _make_cert(b"ssh-rsa-cert-v02@openssh.com", self.fields)
        with pytest.raises(ValueError):
            RSA.import_key(cert)


class TestEcdsaKeyType:
    """The curve comes from the key type in the line: an unknown certificate
    version used to be parsed as a key, with its random nonce shown as the curve"""

    def test_unknown_certificate_version(self):
        fields = _fields(VECTORS["ecdsa256"][1])[1:]
        cert = _make_cert(b"ecdsa-sha2-nistp256-cert-v02@openssh.com", fields)
        with pytest.raises(
            ValueError, match=r"Unsupported ECC curve: b'ecdsa-sha2-nistp256-cert-v02@openssh\.com'"
        ):
            ECC.import_key(cert)
