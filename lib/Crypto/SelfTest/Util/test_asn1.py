#
#  SelfTest/Util/test_asn.py: Self-test for the Crypto.Util.asn1 module
#
# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

"""Self-tests for Crypto.Util.asn1"""

import pytest

from Crypto.Util.asn1 import (
    DerBitString,
    DerBoolean,
    DerInteger,
    DerNull,
    DerObject,
    DerObjectId,
    DerOctetString,
    DerSequence,
    DerSetOf,
)


class TestDerObject:
    def testObjInit1(self):
        # Fail with invalid tag format (must be 1 byte)
        with pytest.raises(ValueError):
            DerObject(b"\x00\x99")
        # Fail with invalid implicit tag (must be <0x1F)
        with pytest.raises(ValueError):
            DerObject(0x1F)

    # ------

    def testObjEncode1(self):
        # No payload
        der = DerObject(b"\x02")
        assert der.encode() == b"\x02\x00"
        # Small payload (primitive)
        der.payload = b"\x45"
        assert der.encode() == b"\x02\x01\x45"
        # Invariant
        assert der.encode() == b"\x02\x01\x45"
        # Initialize with numerical tag
        der = DerObject(0x04)
        der.payload = b"\x45"
        assert der.encode() == b"\x04\x01\x45"
        # Initialize with constructed type
        der = DerObject(b"\x10", constructed=True)
        assert der.encode() == b"\x30\x00"

    def testObjEncode2(self):
        # Initialize with payload
        der = DerObject(0x03, b"\x12\x12")
        assert der.encode() == b"\x03\x02\x12\x12"

    def testObjEncode3(self):
        # Long payload
        der = DerObject(b"\x10")
        der.payload = b"0" * 128
        assert der.encode() == ("\x10\x81\x80" + "0" * 128).encode("latin-1")

    def testObjEncode4(self):
        # Implicit tags (constructed)
        der = DerObject(0x10, implicit=1, constructed=True)
        der.payload = b"ppll"
        assert der.encode() == b"\xa1\x04ppll"
        # Implicit tags (primitive)
        der = DerObject(0x02, implicit=0x1E, constructed=False)
        der.payload = b"ppll"
        assert der.encode() == b"\x9e\x04ppll"

    def testObjEncode5(self):
        # Encode type with explicit tag
        der = DerObject(0x10, explicit=5)
        der.payload = b"xxll"
        assert der.encode() == b"\xa5\x06\x10\x04xxll"

    # -----

    def testObjDecode1(self):
        # Decode short payload
        der = DerObject(0x02)
        der.decode(b"\x02\x02\x01\x02")
        assert der.payload == b"\x01\x02"
        assert der._tag_octet == 0x02

    def testObjDecode2(self):
        # Decode long payload
        der = DerObject(0x02)
        der.decode(("\x02\x81\x80" + "1" * 128).encode("latin-1"))
        assert der.payload == b"1" * 128
        assert der._tag_octet == 0x02

    def testObjDecode3(self):
        # Decode payload with too much data gives error
        der = DerObject(0x02)
        with pytest.raises(ValueError):
            der.decode(b"\x02\x02\x01\x02\xff")
        # Decode payload with too little data gives error
        der = DerObject(0x02)
        with pytest.raises(ValueError):
            der.decode(b"\x02\x02\x01")

    def testObjDecode4(self):
        # Decode implicit tag (primitive)
        der = DerObject(0x02, constructed=False, implicit=0xF)
        with pytest.raises(ValueError):
            der.decode(b"\x02\x02\x01\x02")
        der.decode(b"\x8f\x01\x00")
        assert der.payload == b"\x00"
        # Decode implicit tag (constructed)
        der = DerObject(0x02, constructed=True, implicit=0xF)
        with pytest.raises(ValueError):
            der.decode(b"\x02\x02\x01\x02")
        der.decode(b"\xaf\x01\x00")
        assert der.payload == b"\x00"

    def testObjDecode5(self):
        # Decode payload with unexpected tag gives error
        der = DerObject(0x02)
        with pytest.raises(ValueError):
            der.decode(b"\x03\x02\x01\x02")

    def testObjDecode6(self):
        # Arbitrary DER object
        der = DerObject()
        der.decode(b"\x65\x01\x88")
        assert der._tag_octet == 0x65
        assert der.payload == b"\x88"

    def testObjDecode7(self):
        # Decode explicit tag
        der = DerObject(0x10, explicit=5)
        der.decode(b"\xa5\x06\x10\x04xxll")
        assert der._inner_tag_octet == 0x10
        assert der.payload == b"xxll"

        # Explicit tag may be 0
        der = DerObject(0x10, explicit=0)
        der.decode(b"\xa0\x06\x10\x04xxll")
        assert der._inner_tag_octet == 0x10
        assert der.payload == b"xxll"

    def testObjDecode8(self):
        # Verify that decode returns the object
        der = DerObject(0x02)
        assert der == der.decode(b"\x02\x02\x01\x02")


class TestDerInteger:
    def testInit1(self):
        der = DerInteger(1)
        assert der.encode() == b"\x02\x01\x01"

    def testEncode1(self):
        # Single-byte integers
        # Value 0
        der = DerInteger(0)
        assert der.encode() == b"\x02\x01\x00"
        # Value 1
        der = DerInteger(1)
        assert der.encode() == b"\x02\x01\x01"
        # Value 127
        der = DerInteger(127)
        assert der.encode() == b"\x02\x01\x7f"

    def testEncode2(self):
        # Multi-byte integers
        # Value 128
        der = DerInteger(128)
        assert der.encode() == b"\x02\x02\x00\x80"
        # Value 0x180
        der = DerInteger(0x180)
        assert der.encode() == b"\x02\x02\x01\x80"
        # One very long integer
        der = DerInteger(2**2048)
        assert (
            der.encode()
            == b"\x02\x82\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    def testEncode3(self):
        # Negative integers
        # Value -1
        der = DerInteger(-1)
        assert der.encode() == b"\x02\x01\xff"
        # Value -128
        der = DerInteger(-128)
        assert der.encode() == b"\x02\x01\x80"
        # Value
        der = DerInteger(-87873)
        assert der.encode() == b"\x02\x03\xfe\xa8\xbf"

    def testEncode4(self):
        # Explicit encoding
        number = DerInteger(0x34, explicit=3)
        assert number.encode() == b"\xa3\x03\x02\x01\x34"

    # -----

    def testDecode1(self):
        # Single-byte integer
        der = DerInteger()
        # Value 0
        der.decode(b"\x02\x01\x00")
        assert der.value == 0
        # Value 1
        der.decode(b"\x02\x01\x01")
        assert der.value == 1
        # Value 127
        der.decode(b"\x02\x01\x7f")
        assert der.value == 127

    def testDecode2(self):
        # Multi-byte integer
        der = DerInteger()
        # Value 0x180L
        der.decode(b"\x02\x02\x01\x80")
        assert der.value == 0x180
        # One very long integer
        der.decode(
            b"\x02\x82\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        assert der.value == 2**2048

    def testDecode3(self):
        # Negative integer
        der = DerInteger()
        # Value -1
        der.decode(b"\x02\x01\xff")
        assert der.value == -1
        # Value -32768
        der.decode(b"\x02\x02\x80\x00")
        assert der.value == -32768

    def testDecode5(self):
        # We still accept BER integer format
        der = DerInteger()
        # Redundant leading zeroes
        der.decode(b"\x02\x02\x00\x01")
        assert der.value == 1
        # Redundant leading 0xFF
        der.decode(b"\x02\x02\xff\xff")
        assert der.value == -1
        # Empty payload
        der.decode(b"\x02\x00")
        assert der.value == 0

    def testDecode6(self):
        # Explicit encoding
        number = DerInteger(explicit=3)
        number.decode(b"\xa3\x03\x02\x01\x34")
        assert number.value == 0x34

    def testDecode7(self):
        # Verify decode returns the DerInteger
        der = DerInteger()
        assert der == der.decode(b"\x02\x01\x7f")

    ###

    def testStrict1(self):
        number = DerInteger()

        number.decode(b"\x02\x02\x00\x01")
        number.decode(b"\x02\x02\x00\x7f")
        with pytest.raises(ValueError):
            number.decode(b"\x02\x02\x00\x01", strict=True)
        with pytest.raises(ValueError):
            number.decode(b"\x02\x02\x00\x7f", strict=True)

    ###

    def testErrDecode1(self):
        # Wide length field
        der = DerInteger()
        with pytest.raises(ValueError):
            der.decode(b"\x02\x81\x01\x01")


class TestDerSequence:
    def testInit1(self):
        der = DerSequence([1, DerInteger(2), b"0\x00"])
        assert der.encode() == b"0\x08\x02\x01\x01\x02\x01\x020\x00"

    def testEncode1(self):
        # Empty sequence
        der = DerSequence()
        assert der.encode() == b"0\x00"
        assert not der.hasOnlyInts()
        # One single-byte integer (zero)
        der.append(0)
        assert der.encode() == b"0\x03\x02\x01\x00"
        assert der.hasInts() == 1
        assert der.hasInts(False) == 1
        assert der.hasOnlyInts()
        assert der.hasOnlyInts(False)
        # Invariant
        assert der.encode() == b"0\x03\x02\x01\x00"

    def testEncode2(self):
        # Indexing
        der = DerSequence()
        der.append(0)
        der[0] = 1
        assert len(der) == 1
        assert der[0] == 1
        assert der[-1] == 1
        assert der.encode() == b"0\x03\x02\x01\x01"
        #
        der[:] = [1]
        assert len(der) == 1
        assert der[0] == 1
        assert der.encode() == b"0\x03\x02\x01\x01"

    def testEncode3(self):
        # One multi-byte integer (non-zero)
        der = DerSequence()
        der.append(0x180)
        assert der.encode() == b"0\x04\x02\x02\x01\x80"

    def testEncode4(self):
        # One very long integer
        der = DerSequence()
        der.append(2**2048)
        assert (
            der.encode()
            == b"0\x82\x01\x05"
            + b"\x02\x82\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    def testEncode5(self):
        der = DerSequence()
        der += 1
        der += b"\x30\x00"
        assert der.encode() == b"\x30\x05\x02\x01\x01\x30\x00"

    def testEncode6(self):
        # Two positive integers
        der = DerSequence()
        der.append(0x180)
        der.append(0xFF)
        assert der.encode() == b"0\x08\x02\x02\x01\x80\x02\x02\x00\xff"
        assert der.hasOnlyInts()
        assert der.hasOnlyInts(False)
        # Two mixed integers
        der = DerSequence()
        der.append(2)
        der.append(-2)
        assert der.encode() == b"0\x06\x02\x01\x02\x02\x01\xfe"
        assert der.hasInts() == 1
        assert der.hasInts(False) == 2
        assert not der.hasOnlyInts()
        assert der.hasOnlyInts(False)
        #
        der.append(0x01)
        der[1:] = [9, 8]
        assert len(der) == 3
        assert der[1:] == [9, 8]
        assert der[1:-1] == [9]
        assert der.encode() == b"0\x09\x02\x01\x02\x02\x01\x09\x02\x01\x08"

    def testEncode7(self):
        # One integer and another type (already encoded)
        der = DerSequence()
        der.append(0x180)
        der.append(b"0\x03\x02\x01\x05")
        assert der.encode() == b"0\x09\x02\x02\x01\x800\x03\x02\x01\x05"
        assert not der.hasOnlyInts()

    def testEncode8(self):
        # One integer and another type (yet to encode)
        der = DerSequence()
        der.append(0x180)
        der.append(DerSequence([5]))
        assert der.encode() == b"0\x09\x02\x02\x01\x800\x03\x02\x01\x05"
        assert not der.hasOnlyInts()

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerSequence()
        der.decode(b"0\x00")
        assert len(der) == 0
        # One single-byte integer (zero)
        der.decode(b"0\x03\x02\x01\x00")
        assert len(der) == 1
        assert der[0] == 0
        # Invariant
        der.decode(b"0\x03\x02\x01\x00")
        assert len(der) == 1
        assert der[0] == 0

    def testDecode2(self):
        # One single-byte integer (non-zero)
        der = DerSequence()
        der.decode(b"0\x03\x02\x01\x7f")
        assert len(der) == 1
        assert der[0] == 127

    def testDecode4(self):
        # One very long integer
        der = DerSequence()
        der.decode(
            b"0\x82\x01\x05"
            + b"\x02\x82\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        assert len(der) == 1
        assert der[0] == 2**2048

    def testDecode6(self):
        # Two integers
        der = DerSequence()
        der.decode(b"0\x08\x02\x02\x01\x80\x02\x02\x00\xff")
        assert len(der) == 2
        assert der[0] == 0x180
        assert der[1] == 0xFF

    def testDecode7(self):
        # One integer and 2 other types
        der = DerSequence()
        der.decode(b"0\x0a\x02\x02\x01\x80\x24\x02\xb6\x63\x12\x00")
        assert len(der) == 3
        assert der[0] == 0x180
        assert der[1] == b"\x24\x02\xb6\x63"
        assert der[2] == b"\x12\x00"

    def testDecode8(self):
        # Only 2 other types
        der = DerSequence()
        der.decode(b"0\x06\x24\x02\xb6\x63\x12\x00")
        assert len(der) == 2
        assert der[0] == b"\x24\x02\xb6\x63"
        assert der[1] == b"\x12\x00"
        assert der.hasInts() == 0
        assert der.hasInts(False) == 0
        assert not der.hasOnlyInts()
        assert not der.hasOnlyInts(False)

    def testDecode9(self):
        # Verify that decode returns itself
        der = DerSequence()
        assert der == der.decode(b"0\x06\x24\x02\xb6\x63\x12\x00")

    ###

    def testErrDecode1(self):
        # Not a sequence
        der = DerSequence()
        with pytest.raises(ValueError):
            der.decode(b"")
        with pytest.raises(ValueError):
            der.decode(b"\x00")
        with pytest.raises(ValueError):
            der.decode(b"\x30")

    def testErrDecode2(self):
        der = DerSequence()
        # Too much data
        with pytest.raises(ValueError):
            der.decode(b"\x30\x00\x00")

    def testErrDecode3(self):
        # Wrong length format
        der = DerSequence()
        # Missing length in sub-item
        with pytest.raises(ValueError):
            der.decode(b"\x30\x04\x02\x01\x01\x00")
        # Valid BER, but invalid DER length
        with pytest.raises(ValueError):
            der.decode(b"\x30\x81\x03\x02\x01\x01")
        with pytest.raises(ValueError):
            der.decode(b"\x30\x04\x02\x81\x01\x01")

    def test_expected_nr_elements(self):
        der_bin = DerSequence([1, 2, 3]).encode()

        DerSequence().decode(der_bin, nr_elements=3)
        DerSequence().decode(der_bin, nr_elements=(2, 3))
        with pytest.raises(ValueError):
            DerSequence().decode(der_bin, nr_elements=1)
        with pytest.raises(ValueError):
            DerSequence().decode(der_bin, nr_elements=(4, 5))

    def test_expected_only_integers(self):

        der_bin1 = DerSequence([1, 2, 3]).encode()
        der_bin2 = DerSequence([1, 2, DerSequence([3, 4])]).encode()

        DerSequence().decode(der_bin1, only_ints_expected=True)
        DerSequence().decode(der_bin1, only_ints_expected=False)
        DerSequence().decode(der_bin2, only_ints_expected=False)
        with pytest.raises(ValueError):
            DerSequence().decode(der_bin2, only_ints_expected=True)


class TestDerOctetString:
    def testInit1(self):
        der = DerOctetString(b"\xff")
        assert der.encode() == b"\x04\x01\xff"

    def testEncode1(self):
        # Empty sequence
        der = DerOctetString()
        assert der.encode() == b"\x04\x00"
        # Small payload
        der.payload = b"\x01\x02"
        assert der.encode() == b"\x04\x02\x01\x02"

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerOctetString()
        der.decode(b"\x04\x00")
        assert der.payload == b""
        # Small payload
        der.decode(b"\x04\x02\x01\x02")
        assert der.payload == b"\x01\x02"

    def testDecode2(self):
        # Verify that decode returns the object
        der = DerOctetString()
        assert der == der.decode(b"\x04\x00")

    def testErrDecode1(self):
        # No leftovers allowed
        der = DerOctetString()
        with pytest.raises(ValueError):
            der.decode(b"\x04\x01\x01\xff")


class TestDerNull:
    def testEncode1(self):
        der = DerNull()
        assert der.encode() == b"\x05\x00"

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerNull()
        assert der == der.decode(b"\x05\x00")


class TestDerObjectId:
    def testInit1(self):
        der = DerObjectId("1.1")
        assert der.encode() == b"\x06\x01)"

    def testEncode1(self):
        der = DerObjectId("1.2.840.113549.1.1.1")
        assert der.encode() == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

        der = DerObjectId()
        der.value = "1.2.840.113549.1.1.1"
        assert der.encode() == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

        der = DerObjectId("2.999.1234")
        assert der.encode() == b"\x06\x04\x88\x37\x89\x52"

    def testEncode2(self):
        der = DerObjectId("3.4")
        with pytest.raises(ValueError):
            der.encode()

        der = DerObjectId("1.40")
        with pytest.raises(ValueError):
            der.encode()

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerObjectId()
        der.decode(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
        assert der.value == "1.2.840.113549.1.1.1"

    def testDecode2(self):
        # Verify that decode returns the object
        der = DerObjectId()
        assert der == der.decode(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")

    def testDecode3(self):
        der = DerObjectId()
        der.decode(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x00\x01")
        assert der.value == "1.2.840.113549.1.0.1"

    def testDecode4(self):
        der = DerObjectId()
        der.decode(b"\x06\x04\x88\x37\x89\x52")
        assert der.value == "2.999.1234"


class TestDerBitString:
    def testInit1(self):
        der = DerBitString(b"\xff")
        assert der.encode() == b"\x03\x02\x00\xff"

    def testInit2(self):
        der = DerBitString(DerInteger(1))
        assert der.encode() == b"\x03\x04\x00\x02\x01\x01"

    def testEncode1(self):
        # Empty sequence
        der = DerBitString()
        assert der.encode() == b"\x03\x01\x00"
        # Small payload
        der = DerBitString(b"\x01\x02")
        assert der.encode() == b"\x03\x03\x00\x01\x02"
        # Small payload
        der = DerBitString()
        der.value = b"\x01\x02"
        assert der.encode() == b"\x03\x03\x00\x01\x02"

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerBitString()
        der.decode(b"\x03\x00")
        assert der.value == b""
        # Small payload
        der.decode(b"\x03\x03\x00\x01\x02")
        assert der.value == b"\x01\x02"

    def testDecode2(self):
        # Verify that decode returns the object
        der = DerBitString()
        assert der == der.decode(b"\x03\x00")


class TestDerSetOf:
    def testInit1(self):
        der = DerSetOf([DerInteger(1), DerInteger(2)])
        assert der.encode() == b"1\x06\x02\x01\x01\x02\x01\x02"

    def testEncode1(self):
        # Empty set
        der = DerSetOf()
        assert der.encode() == b"1\x00"
        # One single-byte integer (zero)
        der.add(0)
        assert der.encode() == b"1\x03\x02\x01\x00"
        # Invariant
        assert der.encode() == b"1\x03\x02\x01\x00"

    def testEncode2(self):
        # Two integers
        der = DerSetOf()
        der.add(0x180)
        der.add(0xFF)
        assert der.encode() == b"1\x08\x02\x02\x00\xff\x02\x02\x01\x80"
        # Initialize with integers
        der = DerSetOf([0x180, 0xFF])
        assert der.encode() == b"1\x08\x02\x02\x00\xff\x02\x02\x01\x80"

    def testEncode3(self):
        # One integer and another type (no matter what it is)
        der = DerSetOf()
        der.add(0x180)
        with pytest.raises(ValueError):
            der.add(b"\x00\x02\x00\x00")

    def testEncode4(self):
        # Only non integers
        der = DerSetOf()
        der.add(b"\x01\x00")
        der.add(b"\x01\x01\x01")
        assert der.encode() == b"1\x05\x01\x00\x01\x01\x01"

    ####

    def testDecode1(self):
        # Empty sequence
        der = DerSetOf()
        der.decode(b"1\x00")
        assert len(der) == 0
        # One single-byte integer (zero)
        der.decode(b"1\x03\x02\x01\x00")
        assert len(der) == 1
        assert list(der) == [0]

    def testDecode2(self):
        # Two integers
        der = DerSetOf()
        der.decode(b"1\x08\x02\x02\x01\x80\x02\x02\x00\xff")
        assert len(der) == 2
        members = list(der)
        assert 0x180 in members
        assert 0xFF in members

    def testDecode3(self):
        # One integer and 2 other types
        der = DerSetOf()
        # import pdb; pdb.set_trace()
        with pytest.raises(ValueError):
            der.decode(b"0\x0a\x02\x02\x01\x80\x24\x02\xb6\x63\x12\x00")

    def testDecode4(self):
        # Verify that decode returns the object
        der = DerSetOf()
        assert der == der.decode(b"1\x08\x02\x02\x01\x80\x02\x02\x00\xff")

    ###

    def testErrDecode1(self):
        # No leftovers allowed
        der = DerSetOf()
        with pytest.raises(ValueError):
            der.decode(b"1\x08\x02\x02\x01\x80\x02\x02\x00\xff\xaa")


class TestDerBoolean:
    def testEncode1(self):
        der = DerBoolean(False)
        assert der.encode() == b"\x01\x01\x00"

    def testEncode2(self):
        der = DerBoolean(True)
        assert der.encode() == b"\x01\x01\xff"

    def testEncode3(self):
        der = DerBoolean(False, implicit=0x12)
        assert der.encode() == b"\x92\x01\x00"

    def testEncode4(self):
        der = DerBoolean(False, explicit=0x05)
        assert der.encode() == b"\xa5\x03\x01\x01\x00"

    ####

    def testDecode1(self):
        der = DerBoolean()
        der.decode(b"\x01\x01\x00")
        assert der.value is False

    def testDecode2(self):
        der = DerBoolean()
        der.decode(b"\x01\x01\xff")
        assert der.value is True

    def testDecode3(self):
        der = DerBoolean(implicit=0x12)
        der.decode(b"\x92\x01\x00")
        assert der.value is False

    def testDecode4(self):
        der = DerBoolean(explicit=0x05)
        der.decode(b"\xa5\x03\x01\x01\x00")
        assert der.value is False

    def testErrorDecode1(self):
        der = DerBoolean()
        # Wrong tag
        with pytest.raises(ValueError):
            der.decode(b"\x02\x01\x00")

    def testErrorDecode2(self):
        der = DerBoolean()
        # Payload too long
        with pytest.raises(ValueError):
            der.decode(b"\x01\x01\x00\xff")
