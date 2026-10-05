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

"""Self-test suite for Crypto.Hash.keccak"""

import random
from binascii import hexlify

import pytest

from Crypto.Hash import keccak
from Crypto.SelfTest.loader import load_test_vectors
from Crypto.Util._bytes import tobytes
from Crypto.Util._raw_api import (
    VoidPointer,
    c_size_t,
    c_ubyte,
    c_uint8_ptr,
    create_string_buffer,
    get_raw_buffer,
)


class TestKeccak:
    def test_new_positive(self):

        for digest_bits in (224, 256, 384, 512):
            hobj = keccak.new(digest_bits=digest_bits)
            assert hobj.digest_size == digest_bits // 8

            hobj2 = hobj.new()
            assert hobj2.digest_size == digest_bits // 8

        for digest_bytes in (28, 32, 48, 64):
            hobj = keccak.new(digest_bytes=digest_bytes)
            assert hobj.digest_size == digest_bytes

            hobj2 = hobj.new()
            assert hobj2.digest_size == digest_bytes

    def test_new_positive2(self):

        digest1 = keccak.new(data=b"\x90", digest_bytes=64).digest()
        digest2 = keccak.new(digest_bytes=64).update(b"\x90").digest()
        assert digest1 == digest2

    def test_new_negative(self):

        # keccak.new needs digest size
        with pytest.raises(TypeError):
            keccak.new()

        keccak.new(digest_bits=512)

        # Either bits or bytes can be specified
        with pytest.raises(TypeError):
            keccak.new(digest_bytes=64, digest_bits=512)

        # Range
        with pytest.raises(ValueError):
            keccak.new(digest_bytes=0)
        with pytest.raises(ValueError):
            keccak.new(digest_bytes=1)
        with pytest.raises(ValueError):
            keccak.new(digest_bytes=65)
        with pytest.raises(ValueError):
            keccak.new(digest_bits=0)
        with pytest.raises(ValueError):
            keccak.new(digest_bits=1)
        with pytest.raises(ValueError):
            keccak.new(digest_bits=513)

    def test_update(self):
        pieces = [bytes([10]) * 200, bytes([20]) * 300]
        h = keccak.new(digest_bytes=64)
        h.update(pieces[0]).update(pieces[1])
        digest = h.digest()
        h = keccak.new(digest_bytes=64)
        h.update(pieces[0] + pieces[1])
        assert h.digest() == digest

    def test_update_negative(self):
        h = keccak.new(digest_bytes=64)
        with pytest.raises(TypeError):
            h.update("string")

    def test_digest(self):
        h = keccak.new(digest_bytes=64)
        digest = h.digest()

        # hexdigest does not change the state
        assert h.digest() == digest
        # digest returns a byte string
        assert isinstance(digest, bytes)

    def test_hex_digest(self):
        mac = keccak.new(digest_bits=512)
        digest = mac.digest()
        hexdigest = mac.hexdigest()

        # hexdigest is equivalent to digest
        assert hexlify(digest) == tobytes(hexdigest)
        # hexdigest does not change the state
        assert mac.hexdigest() == hexdigest
        # hexdigest returns a string
        assert isinstance(hexdigest, str)

    def test_update_after_digest(self):
        msg = b"rrrrttt"

        # Normally, update() cannot be done after digest()
        h = keccak.new(digest_bits=512, data=msg[:4])
        dig1 = h.digest()
        with pytest.raises(TypeError):
            h.update(msg[4:])
        dig2 = keccak.new(digest_bits=512, data=msg).digest()

        # With the proper flag, it is allowed
        h = keccak.new(digest_bits=512, data=msg[:4], update_after_digest=True)
        assert h.digest() == dig1
        # ... and the subsequent digest applies to the entire message
        # up to that point
        h.update(msg[4:])
        assert h.digest() == dig2


test_vectors_224 = (
    load_test_vectors(
        ("Hash", "keccak"), "ShortMsgKAT_224.txt", "Short Messages KAT 224", {"len": lambda x: int(x)}
    )
    or []
)

test_vectors_224 += (
    load_test_vectors(
        ("Hash", "keccak"), "LongMsgKAT_224.txt", "Long Messages KAT 224", {"len": lambda x: int(x)}
    )
    or []
)


test_vectors_256 = (
    load_test_vectors(
        ("Hash", "keccak"), "ShortMsgKAT_256.txt", "Short Messages KAT 256", {"len": lambda x: int(x)}
    )
    or []
)

test_vectors_256 += (
    load_test_vectors(
        ("Hash", "keccak"), "LongMsgKAT_256.txt", "Long Messages KAT 256", {"len": lambda x: int(x)}
    )
    or []
)


test_vectors_384 = (
    load_test_vectors(
        ("Hash", "keccak"), "ShortMsgKAT_384.txt", "Short Messages KAT 384", {"len": lambda x: int(x)}
    )
    or []
)

test_vectors_384 += (
    load_test_vectors(
        ("Hash", "keccak"), "LongMsgKAT_384.txt", "Long Messages KAT 384", {"len": lambda x: int(x)}
    )
    or []
)


test_vectors_512 = (
    load_test_vectors(
        ("Hash", "keccak"), "ShortMsgKAT_512.txt", "Short Messages KAT 512", {"len": lambda x: int(x)}
    )
    or []
)

test_vectors_512 += (
    load_test_vectors(
        ("Hash", "keccak"), "LongMsgKAT_512.txt", "Long Messages KAT 512", {"len": lambda x: int(x)}
    )
    or []
)


def _vectors(test_vectors):
    return [
        pytest.param(b"" if tv.len == 0 else tobytes(tv.msg), tv.md, id=str(idx))
        for idx, tv in enumerate(test_vectors)
    ]


class TestKeccakVectors:
    # TODO: add ExtremelyLong tests

    @pytest.mark.parametrize(
        "digest_bits, data, result",
        [
            pytest.param(bits, *p.values, id="%d-%s" % (bits, p.id))
            for bits, tvs in (
                (224, test_vectors_224),
                (256, test_vectors_256),
                (384, test_vectors_384),
                (512, test_vectors_512),
            )
            for p in _vectors(tvs)
        ],
    )
    def test(self, digest_bits, data, result):
        hobj = keccak.new(digest_bits=digest_bits, data=data)
        assert hobj.digest() == result


@pytest.mark.skipif(keccak._raw_keccak_avx2_bmi2_lib is None, reason="AVX2 and BMI2 not available")
class TestKeccakImplementations:
    """The test vectors only exercise the implementation in use.
    Check that the other one (portable C) returns the same output."""

    def _sponge(self, lib, capacity, rounds, chunks, out_len):
        state = VoidPointer()
        assert lib.keccak_init(state.address_of(), c_size_t(capacity), c_ubyte(rounds)) == 0
        for chunk in chunks:
            assert lib.keccak_absorb(state.get(), c_uint8_ptr(chunk), c_size_t(len(chunk))) == 0
        out = create_string_buffer(out_len)
        assert lib.keccak_squeeze(state.get(), out, c_size_t(out_len), c_ubyte(0x1F)) == 0
        lib.keccak_destroy(state.get())
        return get_raw_buffer(out)

    @pytest.mark.parametrize("capacity", [32, 48, 64, 96, 128])
    @pytest.mark.parametrize("rounds", [12, 24])
    def test_same_output(self, capacity, rounds):
        rng = random.Random(capacity * rounds)
        for length in (0, 1, 71, 72, 135, 136, 168, 169, 1000, 5000):
            data = bytes(rng.getrandbits(8) for _ in range(length))
            cut = rng.randint(0, length)
            chunks = (data[:cut], data[cut:])
            results = [
                self._sponge(lib, capacity, rounds, chunks, 500)
                for lib in (keccak._raw_keccak_portable_lib, keccak._raw_keccak_avx2_bmi2_lib)
            ]
            assert results[0] == results[1]
