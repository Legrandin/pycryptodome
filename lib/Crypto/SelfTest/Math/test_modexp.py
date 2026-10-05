#
#  SelfTest/Math/test_modexp.py: Self-test for module exponentiation
#
# ===================================================================
#
# Copyright (c) 2017, Helder Eijs <helderijs@gmail.com>
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

"""Self-test for the custom module exponentiation"""

import unittest

from Crypto.Hash import SHAKE128
from Crypto.Math._IntegerCustom import _raw_montgomery
from Crypto.Math.Numbers import Integer
from Crypto.Random.random import StrongRandom
from Crypto.Util._raw_api import (
    c_size_t,
    c_ulonglong,
    create_string_buffer,
    get_raw_buffer,
)
from Crypto.Util.number import bytes_to_long, long_to_bytes


def create_rng(tag):
    rng = StrongRandom(SHAKE128.new(data=tag))
    return rng


class ExceptionModulus(ValueError):
    pass


def monty_pow(base, exp, modulus):
    max_len = len(long_to_bytes(max(base, exp, modulus)))

    base_b, exp_b, modulus_b = (long_to_bytes(x, max_len) for x in (base, exp, modulus))

    out = create_string_buffer(max_len)
    error = _raw_montgomery.monty_pow(out, base_b, exp_b, modulus_b, c_size_t(max_len), c_ulonglong(32))

    if error == 17:
        raise ExceptionModulus()
    if error:
        raise ValueError("monty_pow failed with error: %d" % error)

    result = bytes_to_long(get_raw_buffer(out))
    return result


exponent1 = 0x2CE0AF628901460A419A08EF950D498B9FD6F271A1A52AC293B86FE5C60EFE8E8BA93FA1EBE1EB3D614D2E7B328CB60A2591440E163441A190ECF101CEEC245F600FFFDCF3F5B3A17A7BAEACB96A424DB1D7EC985E8EC998BB479FECFFFED6A75F9A90FC97062FD973303BCE855AD7B8D8272A94025E8532BE9AABD54A183F303538D2A7E621B4131D59E823A4625F39BD7D518D7784F7C3A8F19061DA74974FF42FA1C063DEC2DB97D461E291A7D6E721708A5229DE166C1246363372854E27F3F08AE274BC16BFD205B028A4D81386494433D516DFBB35F495ACBA5E4E1D1843CB3C3129B6642A85FC7244CE5845FAC071C7F622E4EE12AC43FABEEAA0CD01
modulus1 = 0xD66691B20071BE4D66D4B71032B37FA007CFABF579FCB91E50BFC2753B3F0CE7BE74E216AEF7E26D4AE180BC20D7BD3EA88A6CBF6F87380E613C8979B5B043B200A8FF8856A3B12875E36E98A7569F3852D028E967551000B02C19E9FA52E83115B89309AABB1E1CF1E2CB6369D637D46775CE4523EA31F64AD2794CBC365DD8A35E007ED3B57695877FBF102DBEB8B3212491398E494314E93726926E1383F8ABB5889BEA954EB8C0CA1C62C8E9D83F41888095C5E645ED6D32515FE0C58C1368CAD84694E18DA43668C6F43E61D7C9BCA633DDCDA7AEF5B79BC396D4A9F48E2A9ABE0836CC455E435305357228E93D25AAED46B952DEFAE0F57339BF26F5A9


class TestModExp(unittest.TestCase):
    def test_small(self):
        self.assertEqual(1, monty_pow(11, 12, 19))

    def test_large_1(self):
        base = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        expected = pow(base, exponent1, modulus1)
        result = monty_pow(base, exponent1, modulus1)
        self.assertEqual(result, expected)

    def test_zero_exp(self):
        base = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        result = monty_pow(base, 0, modulus1)
        self.assertEqual(result, 1)

    def test_zero_base(self):
        result = monty_pow(0, exponent1, modulus1)
        self.assertEqual(result, 0)

    def test_zero_modulus(self):
        base = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        self.assertRaises(ExceptionModulus, monty_pow, base, exponent1, 0)
        self.assertRaises(ExceptionModulus, monty_pow, 0, 0, 0)

    def test_larger_exponent(self):
        base = modulus1 - 0xFFFFFFF
        expected = pow(base, modulus1 << 64, modulus1)
        result = monty_pow(base, modulus1 << 64, modulus1)
        self.assertEqual(result, expected)

    def test_even_modulus(self):
        base = modulus1 >> 4
        self.assertRaises(ExceptionModulus, monty_pow, base, exponent1, modulus1 - 1)

    def test_several_lengths(self):
        prng = SHAKE128.new().update(b"Test")
        for length in range(1, 100):
            modulus2 = Integer.from_bytes(prng.read(length)) | 1
            base = Integer.from_bytes(prng.read(length)) % modulus2
            exponent2 = Integer.from_bytes(prng.read(length))

            expected = pow(base, exponent2, modulus2)
            result = monty_pow(base, exponent2, modulus2)
            self.assertEqual(result, expected)

    def test_variable_exponent(self):
        prng = create_rng(b"Test variable exponent")
        for i in range(20):
            for j in range(7):
                modulus = prng.getrandbits(8 * 30) | 1
                base = prng.getrandbits(8 * 30) % modulus
                exponent = prng.getrandbits(i * 8 + j)

                expected = pow(base, exponent, modulus)
                result = monty_pow(base, exponent, modulus)
                self.assertEqual(result, expected)

                exponent ^= (1 << (i * 8 + j)) - 1

                expected = pow(base, exponent, modulus)
                result = monty_pow(base, exponent, modulus)
                self.assertEqual(result, expected)

    def test_stress_63(self):
        prng = create_rng(b"Test 63")
        length = 63
        for _ in range(2000):
            modulus = prng.getrandbits(8 * length) | 1
            base = prng.getrandbits(8 * length) % modulus
            exponent = prng.getrandbits(8 * length)

            expected = pow(base, exponent, modulus)
            result = monty_pow(base, exponent, modulus)
            self.assertEqual(result, expected)

    def test_stress_64(self):
        prng = create_rng(b"Test 64")
        length = 64
        for _ in range(2000):
            modulus = prng.getrandbits(8 * length) | 1
            base = prng.getrandbits(8 * length) % modulus
            exponent = prng.getrandbits(8 * length)

            expected = pow(base, exponent, modulus)
            result = monty_pow(base, exponent, modulus)
            self.assertEqual(result, expected)

    def test_stress_65(self):
        prng = create_rng(b"Test 65")
        length = 65
        for _ in range(2000):
            modulus = prng.getrandbits(8 * length) | 1
            base = prng.getrandbits(8 * length) % modulus
            exponent = prng.getrandbits(8 * length)

            expected = pow(base, exponent, modulus)
            result = monty_pow(base, exponent, modulus)
            self.assertEqual(result, expected)
