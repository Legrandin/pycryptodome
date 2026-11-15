#
#  SelfTest/IO/test_PEM.py: Self-test for the PEM encoding
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from binascii import a2b_base64, b2a_base64

import pytest

from Crypto import PassphraseRequiredError
from Crypto.IO import PEM
from Crypto.IO.PEM import _decode_base64
from Crypto.Util.asn1 import DerSequence

DATA = bytes(range(256)) * 3


def test_round_trip():
    for length in range(100):
        data = DATA[:length]
        pem = PEM.encode(data, "TEST")
        assert PEM.decode(pem) == (data, "TEST", False)


def test_round_trip_encrypted():
    # An encrypted PEM block must hold DER
    der = DerSequence([1, 2**200, 3]).encode()
    pem = PEM.encode(der, "RSA PRIVATE KEY", passphrase=b"secret")
    assert "Proc-Type: 4,ENCRYPTED" in pem
    with pytest.raises(PassphraseRequiredError):
        PEM.decode(pem)
    assert PEM.decode(pem, b"secret") == (der, "RSA PRIVATE KEY", True)


def test_layout():
    body = b2a_base64(DATA, newline=False).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]

    # CRLF, blank lines and spaces around the boundaries, indented body
    pem = "\r\n\n  -----BEGIN TEST-----  \r\n"
    pem += "".join("  " + x + " \r\n" for x in lines)
    pem += "-----END TEST-----\r\n \n\n"
    assert PEM.decode(pem) == (DATA, "TEST", False)

    # The body is a single line, with spaces inside
    pem = "-----BEGIN TEST-----\n" + " ".join(lines) + "\n-----END TEST-----"
    assert PEM.decode(pem)[0] == DATA

    # Unknown headers are ignored
    pem = "-----BEGIN TEST-----\nComment: hello\n\n" + body + "\n-----END TEST-----\n"
    assert PEM.decode(pem)[0] == DATA

    # An empty body
    assert PEM.decode("-----BEGIN TEST-----\n-----END TEST-----\n") == (b"", "TEST", False)


def test_invalid_boundaries():
    body = "SGVsbG8=\n"
    for pem in (
        "",
        "\n\n",
        "-----BEGIN TEST-----\n",
        "-----BEGIN TEST-----",
        "x-----BEGIN TEST-----\n" + body + "-----END TEST-----\n",
        "-----BEGIN TEST-----\n" + body,
        "-----BEGIN TEST-----\n" + body + "-----END OTHER-----\n",
        "-----BEGIN TEST-----\n" + body + "-----END TEST-----\nx\n",
        "-----BEGIN TEST-----\n" + "SGVsbG8=-----END TEST-----\n",
    ):
        with pytest.raises(ValueError):
            PEM.decode(pem)


def test_invalid_body():
    for body in (
        "SGVsbG8",  # No padding
        "SGVsbG8==",  # Excess padding
        "SGVsbG8=SGVs",  # Data after padding
        "SGVs*G8=",  # Not in the alphabet
        "SGVséG8=",  # Not ASCII
        "SGVs€G8=",  # Not Latin-1
        "SGVsbG8=\n" + "-----BEGIN TEST-----",
    ):
        pem = "-----BEGIN TEST-----\n" + body + "\n-----END TEST-----\n"
        with pytest.raises(ValueError):
            PEM.decode(pem)


def test_decode_base64_like_binascii():
    for length in range(70):
        text = b2a_base64(DATA[:length]).decode()
        assert _decode_base64(text) == a2b_base64(text)

    # The 64 characters of the alphabet, in every position of a group of 4
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for pos in range(4):
        for c in alphabet:
            text = "AAAA"[:pos] + c + "AAAA"[pos + 1 :]
            assert _decode_base64(text) == a2b_base64(text)

    # All other non-whitespace characters are rejected
    for i in range(256):
        c = chr(i)
        if c in alphabet or c in " \t\n\v\f\r=":
            continue
        with pytest.raises(ValueError):
            _decode_base64("AA" + c + "A")
