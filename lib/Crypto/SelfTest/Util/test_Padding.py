#
#  SelfTest/Util/test_Padding.py: Self-test for padding functions
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from binascii import unhexlify as uh

import pytest

from Crypto.Util.Padding import pad, unpad


class TestPKCS7:
    def test1(self):
        padded = pad(b"", 4)
        assert padded == uh(b"04040404")
        padded = pad(b"", 4, "pkcs7")
        assert padded == uh(b"04040404")
        back = unpad(padded, 4)
        assert back == b""

    def test2(self):
        padded = pad(uh(b"12345678"), 4)
        assert padded == uh(b"1234567804040404")
        back = unpad(padded, 4)
        assert back == uh(b"12345678")

    def test3(self):
        padded = pad(uh(b"123456"), 4)
        assert padded == uh(b"12345601")
        back = unpad(padded, 4)
        assert back == uh(b"123456")

    def test4(self):
        padded = pad(uh(b"1234567890"), 4)
        assert padded == uh(b"1234567890030303")
        back = unpad(padded, 4)
        assert back == uh(b"1234567890")

    def testn1(self):
        with pytest.raises(ValueError):
            pad(uh(b"12"), 4, "pkcs8")

    def testn2(self):
        with pytest.raises(ValueError):
            unpad(b"\0\0\0", 4)
        with pytest.raises(ValueError):
            unpad(b"", 4)

    def testn3(self):
        with pytest.raises(ValueError):
            unpad(b"123456\x02", 4)
        with pytest.raises(ValueError):
            unpad(b"123456\x00", 4)
        with pytest.raises(ValueError):
            unpad(b"123456\x05\x05\x05\x05\x05", 4)


class TestX923:
    def test1(self):
        padded = pad(b"", 4, "x923")
        assert padded == uh(b"00000004")
        back = unpad(padded, 4, "x923")
        assert back == b""

    def test2(self):
        padded = pad(uh(b"12345678"), 4, "x923")
        assert padded == uh(b"1234567800000004")
        back = unpad(padded, 4, "x923")
        assert back == uh(b"12345678")

    def test3(self):
        padded = pad(uh(b"123456"), 4, "x923")
        assert padded == uh(b"12345601")
        back = unpad(padded, 4, "x923")
        assert back == uh(b"123456")

    def test4(self):
        padded = pad(uh(b"1234567890"), 4, "x923")
        assert padded == uh(b"1234567890000003")
        back = unpad(padded, 4, "x923")
        assert back == uh(b"1234567890")

    def testn1(self):
        with pytest.raises(ValueError):
            unpad(b"123456\x02", 4, "x923")
        with pytest.raises(ValueError):
            unpad(b"123456\x00", 4, "x923")
        with pytest.raises(ValueError):
            unpad(b"123456\x00\x00\x00\x00\x05", 4, "x923")
        with pytest.raises(ValueError):
            unpad(b"", 4, "x923")


class TestISO7816:
    def test1(self):
        padded = pad(b"", 4, "iso7816")
        assert padded == uh(b"80000000")
        back = unpad(padded, 4, "iso7816")
        assert back == b""

    def test2(self):
        padded = pad(uh(b"12345678"), 4, "iso7816")
        assert padded == uh(b"1234567880000000")
        back = unpad(padded, 4, "iso7816")
        assert back == uh(b"12345678")

    def test3(self):
        padded = pad(uh(b"123456"), 4, "iso7816")
        assert padded == uh(b"12345680")
        back = unpad(padded, 4, "iso7816")
        assert back == uh(b"123456")

    def test4(self):
        padded = pad(uh(b"1234567890"), 4, "iso7816")
        assert padded == uh(b"1234567890800000")
        back = unpad(padded, 4, "iso7816")
        assert back == uh(b"1234567890")

    def testn1(self):
        with pytest.raises(ValueError):
            unpad(b"123456\x81", 4, "iso7816")
        with pytest.raises(ValueError):
            unpad(b"", 4, "iso7816")
