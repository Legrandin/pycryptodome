# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
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

"""Self-test suite for Crypto.Hash.SHAKE128 and SHAKE256"""

import pytest

from Crypto.Hash import SHAKE128, SHAKE256
from Crypto.SelfTest.loader import load_test_vectors
from Crypto.Util._bytes import tobytes


class SHAKETest:
    def test_new_positive(self):

        xof1 = self.shake.new()
        xof2 = self.shake.new(data=b"90")
        xof3 = self.shake.new().update(b"90")

        assert xof1.read(10) != xof2.read(10)
        xof3.read(10)
        assert xof2.read(10) == xof3.read(10)

    def test_update(self):
        pieces = [bytes([10]) * 200, bytes([20]) * 300]
        h = self.shake.new()
        h.update(pieces[0]).update(pieces[1])
        digest = h.read(10)
        h = self.shake.new()
        h.update(pieces[0] + pieces[1])
        assert h.read(10) == digest

    def test_update_negative(self):
        h = self.shake.new()
        with pytest.raises(TypeError):
            h.update("string")

    def test_digest(self):
        h = self.shake.new()
        digest = h.read(90)

        # read returns a byte string of the right length
        assert isinstance(digest, bytes)
        assert len(digest) == 90

    def test_update_after_read(self):
        mac = self.shake.new()
        mac.update(b"rrrr")
        mac.read(90)
        with pytest.raises(TypeError):
            mac.update(b"ttt")

    def test_copy(self):
        mac = self.shake.new()
        mac.update(b"rrrr")
        mac2 = mac.copy()
        x1 = mac.read(90)
        x2 = mac2.read(90)
        assert x1 == x2


class TestSHAKE128(SHAKETest):
    shake = SHAKE128


class TestSHAKE256(SHAKETest):
    shake = SHAKE256


test_vectors_128 = (
    load_test_vectors(
        ("Hash", "SHA3"), "ShortMsgKAT_SHAKE128.txt", "Short Messages KAT SHAKE128", {"len": lambda x: int(x)}
    )
    or []
)


test_vectors_256 = (
    load_test_vectors(
        ("Hash", "SHA3"), "ShortMsgKAT_SHAKE256.txt", "Short Messages KAT SHAKE256", {"len": lambda x: int(x)}
    )
    or []
)


def _vectors(test_vectors):
    return [
        pytest.param(b"" if tv.len == 0 else tobytes(tv.msg), tv.md, id=str(idx))
        for idx, tv in enumerate(test_vectors)
    ]


class TestSHAKEVectors:
    @pytest.mark.parametrize("data, result", _vectors(test_vectors_128))
    def test_128(self, data, result):
        hobj = SHAKE128.new(data=data)
        digest = hobj.read(len(result))
        assert digest == result

    @pytest.mark.parametrize("data, result", _vectors(test_vectors_256))
    def test_256(self, data, result):
        hobj = SHAKE256.new(data=data)
        digest = hobj.read(len(result))
        assert digest == result
