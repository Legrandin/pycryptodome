# ===================================================================
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

"""Self-test suite for Crypto.Hash.cSHAKE128 and cSHAKE256"""

import pytest

from Crypto.Hash import SHAKE128, SHAKE256, cSHAKE128, cSHAKE256
from Crypto.SelfTest.loader import load_test_vectors
from Crypto.Util._bytes import tobytes


class cSHAKETest:
    def test_left_encode(self):
        from Crypto.Hash.cSHAKE128 import _left_encode

        assert _left_encode(0) == b"\x01\x00"
        assert _left_encode(1) == b"\x01\x01"
        assert _left_encode(256) == b"\x02\x01\x00"

    def test_bytepad(self):
        from Crypto.Hash.cSHAKE128 import _bytepad

        assert _bytepad(b"", 4) == b"\x01\x04\x00\x00"
        assert _bytepad(b"A", 4) == b"\x01\x04A\x00"
        assert _bytepad(b"AA", 4) == b"\x01\x04AA"
        assert _bytepad(b"AAA", 4) == b"\x01\x04AAA\x00\x00\x00"
        assert _bytepad(b"AAAA", 4) == b"\x01\x04AAAA\x00\x00"
        assert _bytepad(b"AAAAA", 4) == b"\x01\x04AAAAA\x00"
        assert _bytepad(b"AAAAAA", 4) == b"\x01\x04AAAAAA"
        assert _bytepad(b"AAAAAAA", 4) == b"\x01\x04AAAAAAA\x00\x00\x00"

    def test_new_positive(self):

        xof1 = self.cshake.new()
        xof2 = self.cshake.new(data=b"90")
        xof3 = self.cshake.new().update(b"90")

        assert xof1.read(10) != xof2.read(10)
        xof3.read(10)
        assert xof2.read(10) == xof3.read(10)

        xof1 = self.cshake.new()
        ref = xof1.read(10)
        xof2 = self.cshake.new(custom=b"")
        xof3 = self.cshake.new(custom=b"foo")

        assert ref == xof2.read(10)
        assert ref != xof3.read(10)

        xof1 = self.cshake.new(custom=b"foo")
        xof2 = self.cshake.new(custom=b"foo", data=b"90")
        xof3 = self.cshake.new(custom=b"foo").update(b"90")

        assert xof1.read(10) != xof2.read(10)
        xof3.read(10)
        assert xof2.read(10) == xof3.read(10)

    def test_update(self):
        pieces = [bytes([10]) * 200, bytes([20]) * 300]
        h = self.cshake.new()
        h.update(pieces[0]).update(pieces[1])
        digest = h.read(10)
        h = self.cshake.new()
        h.update(pieces[0] + pieces[1])
        assert h.read(10) == digest

    def test_update_negative(self):
        h = self.cshake.new()
        with pytest.raises(TypeError):
            h.update("string")

    def test_digest(self):
        h = self.cshake.new()
        digest = h.read(90)

        # read returns a byte string of the right length
        assert isinstance(digest, bytes)
        assert len(digest) == 90

    def test_update_after_read(self):
        mac = self.cshake.new()
        mac.update(b"rrrr")
        mac.read(90)
        with pytest.raises(TypeError):
            mac.update(b"ttt")

    def test_read_negative(self):
        xof = self.cshake.new()
        for bad in (True, False, 1.0, "1", None):
            with pytest.raises(TypeError):
                xof.read(bad)
        with pytest.raises(ValueError):
            xof.read(-1)

        # A rejected read() does not start squeezing
        xof.update(b"abc")
        assert xof.read(10) == self.cshake.new(data=b"abc").read(10)

    def test_shake(self):
        # When no customization string is passed, results must match SHAKE
        for digest_len in range(64):
            xof1 = self.cshake.new(b"TEST")
            xof2 = self.shake.new(b"TEST")
            assert xof1.read(digest_len) == xof2.read(digest_len)


class TestCSHAKE128(cSHAKETest):
    cshake = cSHAKE128
    shake = SHAKE128


class TestCSHAKE256(cSHAKETest):
    cshake = cSHAKE256
    shake = SHAKE256


vector_files = [
    ("ShortMsgSamples_cSHAKE128.txt", "Short Message Samples cSHAKE128", "128_cshake", cSHAKE128),
    ("ShortMsgSamples_cSHAKE256.txt", "Short Message Samples cSHAKE256", "256_cshake", cSHAKE256),
    ("CustomMsgSamples_cSHAKE128.txt", "Custom Message Samples cSHAKE128", "custom_128_cshake", cSHAKE128),
    ("CustomMsgSamples_cSHAKE256.txt", "Custom Message Samples cSHAKE256", "custom_256_cshake", cSHAKE256),
]


def _load_vectors():
    params = []
    for file, descr, tag, test_class in vector_files:
        test_vectors = (
            load_test_vectors(
                ("Hash", "SHA3"),
                file,
                descr,
                {"len": lambda x: int(x), "nlen": lambda x: int(x), "slen": lambda x: int(x)},
            )
            or []
        )

        for idx, tv in enumerate(test_vectors):
            if getattr(tv, "len", 0) == 0:
                data = b""
            else:
                data = tobytes(tv.msg)
                assert tv.len == len(tv.msg) * 8
            if getattr(tv, "nlen", 0) != 0:
                raise ValueError("Unsupported cSHAKE test vector")
            if getattr(tv, "slen", 0) == 0:
                custom = b""
            else:
                custom = tobytes(tv.s)
                assert tv.slen == len(tv.s) * 8

            params.append(pytest.param(test_class, data, custom, tv.md, id="%s_%d" % (tag, idx)))
    return params


class TestCSHAKEVectors:
    @pytest.mark.parametrize("test_class, data, custom, result", _load_vectors())
    def test(self, test_class, data, custom, result):
        hobj = test_class.new(data=data, custom=custom)
        digest = hobj.read(len(result))
        assert digest == result
