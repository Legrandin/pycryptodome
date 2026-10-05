#
#  SelfTest/Util/test_strxor.py: Self-test for XORing
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

from binascii import unhexlify

import pytest

from Crypto.Util.strxor import strxor, strxor_c


class TestStrxor:
    def test1(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"383d4ba020573314395b")
        result = unhexlify(b"c70ed123c59a7fcb6f12")
        assert strxor(term1, term2) == result
        assert strxor(term2, term1) == result

    def test2(self):
        es = b""
        assert strxor(es, es) == es

    def test3(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        all_zeros = b"\x00" * len(term1)
        assert strxor(term1, term1) == all_zeros

    def test_wrong_length(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"ff339a83e5cd4cdf564990")
        with pytest.raises(ValueError):
            strxor(term1, term2)

    def test_bytearray(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term1_ba = bytearray(term1)
        term2 = unhexlify(b"383d4ba020573314395b")
        result = unhexlify(b"c70ed123c59a7fcb6f12")

        assert strxor(term1_ba, term2) == result

    def test_memoryview(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term1_mv = memoryview(term1)
        term2 = unhexlify(b"383d4ba020573314395b")
        result = unhexlify(b"c70ed123c59a7fcb6f12")

        assert strxor(term1_mv, term2) == result

    def test_output_bytearray(self):
        """Verify result can be stored in pre-allocated memory"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"383d4ba020573314395b")
        original_term1 = term1[:]
        original_term2 = term2[:]
        expected_xor = unhexlify(b"c70ed123c59a7fcb6f12")
        output = bytearray(len(term1))

        result = strxor(term1, term2, output=output)

        assert result is None
        assert output == expected_xor
        assert term1 == original_term1
        assert term2 == original_term2

    def test_output_memoryview(self):
        """Verify result can be stored in pre-allocated memory"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"383d4ba020573314395b")
        original_term1 = term1[:]
        original_term2 = term2[:]
        expected_xor = unhexlify(b"c70ed123c59a7fcb6f12")
        output = memoryview(bytearray(len(term1)))

        result = strxor(term1, term2, output=output)

        assert result is None
        assert output == expected_xor
        assert term1 == original_term1
        assert term2 == original_term2

    def test_output_overlapping_bytearray(self):
        """Verify result can be stored in overlapping memory"""

        term1 = bytearray(unhexlify(b"ff339a83e5cd4cdf5649"))
        term2 = unhexlify(b"383d4ba020573314395b")
        original_term2 = term2[:]
        expected_xor = unhexlify(b"c70ed123c59a7fcb6f12")

        result = strxor(term1, term2, output=term1)

        assert result is None
        assert term1 == expected_xor
        assert term2 == original_term2

    def test_output_overlapping_memoryview(self):
        """Verify result can be stored in overlapping memory"""

        term1 = memoryview(bytearray(unhexlify(b"ff339a83e5cd4cdf5649")))
        term2 = unhexlify(b"383d4ba020573314395b")
        original_term2 = term2[:]
        expected_xor = unhexlify(b"c70ed123c59a7fcb6f12")

        result = strxor(term1, term2, output=term1)

        assert result is None
        assert term1 == expected_xor
        assert term2 == original_term2

    def test_output_ro_bytes(self):
        """Verify result cannot be stored in read-only memory"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"383d4ba020573314395b")

        with pytest.raises(TypeError):
            strxor(term1, term2, output=term1)

    def test_output_ro_memoryview(self):
        """Verify result cannot be stored in read-only memory"""

        term1 = memoryview(unhexlify(b"ff339a83e5cd4cdf5649"))
        term2 = unhexlify(b"383d4ba020573314395b")

        with pytest.raises(TypeError):
            strxor(term1, term2, output=term1)

    def test_output_incorrect_length(self):
        """Verify result cannot be stored in memory of incorrect length"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term2 = unhexlify(b"383d4ba020573314395b")
        output = bytearray(len(term1) - 1)

        with pytest.raises(ValueError):
            strxor(term1, term2, output=output)


class TestStrxor_c:
    def test1(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        result = unhexlify(b"be72dbc2a48c0d9e1708")
        assert strxor_c(term1, 65) == result

    def test2(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        assert strxor_c(term1, 0) == term1

    def test3(self):
        assert strxor_c(b"", 90) == b""

    def test_wrong_range(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        with pytest.raises(ValueError):
            strxor_c(term1, -1)
        with pytest.raises(ValueError):
            strxor_c(term1, 256)

    def test_bytearray(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term1_ba = bytearray(term1)
        result = unhexlify(b"be72dbc2a48c0d9e1708")

        assert strxor_c(term1_ba, 65) == result

    def test_memoryview(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        term1_mv = memoryview(term1)
        result = unhexlify(b"be72dbc2a48c0d9e1708")

        assert strxor_c(term1_mv, 65) == result

    def test_output_bytearray(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        original_term1 = term1[:]
        expected_result = unhexlify(b"be72dbc2a48c0d9e1708")
        output = bytearray(len(term1))

        result = strxor_c(term1, 65, output=output)

        assert result is None
        assert output == expected_result
        assert term1 == original_term1

    def test_output_memoryview(self):
        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        original_term1 = term1[:]
        expected_result = unhexlify(b"be72dbc2a48c0d9e1708")
        output = memoryview(bytearray(len(term1)))

        result = strxor_c(term1, 65, output=output)

        assert result is None
        assert output == expected_result
        assert term1 == original_term1

    def test_output_overlapping_bytearray(self):
        """Verify result can be stored in overlapping memory"""

        term1 = bytearray(unhexlify(b"ff339a83e5cd4cdf5649"))
        expected_xor = unhexlify(b"be72dbc2a48c0d9e1708")

        result = strxor_c(term1, 65, output=term1)

        assert result is None
        assert term1 == expected_xor

    def test_output_overlapping_memoryview(self):
        """Verify result can be stored in overlapping memory"""

        term1 = memoryview(bytearray(unhexlify(b"ff339a83e5cd4cdf5649")))
        expected_xor = unhexlify(b"be72dbc2a48c0d9e1708")

        result = strxor_c(term1, 65, output=term1)

        assert result is None
        assert term1 == expected_xor

    def test_output_ro_bytes(self):
        """Verify result cannot be stored in read-only memory"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")

        with pytest.raises(TypeError):
            strxor_c(term1, 65, output=term1)

    def test_output_ro_memoryview(self):
        """Verify result cannot be stored in read-only memory"""

        term1 = memoryview(unhexlify(b"ff339a83e5cd4cdf5649"))
        unhexlify(b"383d4ba020573314395b")

        with pytest.raises(TypeError):
            strxor_c(term1, 65, output=term1)

    def test_output_incorrect_length(self):
        """Verify result cannot be stored in memory of incorrect length"""

        term1 = unhexlify(b"ff339a83e5cd4cdf5649")
        output = bytearray(len(term1) - 1)

        with pytest.raises(ValueError):
            strxor_c(term1, 65, output=output)
