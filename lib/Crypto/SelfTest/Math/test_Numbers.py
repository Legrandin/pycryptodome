#
#  SelfTest/Math/test_Numbers.py: Self-test for Numbers module
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

"""Self-test for Math.Numbers"""

import pytest

from Crypto.Math._IntegerNative import IntegerNative

try:
    from Crypto.Math._IntegerGMP import IntegerGMP

    _gmp_error = None
except (ImportError, OSError) as e:
    _gmp_error = e

try:
    from Crypto.Math._IntegerCustom import IntegerCustom

    _custom_error = None
except (ImportError, OSError) as e:
    _custom_error = e


class IntegerTests:
    def setup_method(self):
        raise NotImplementedError("To be implemented")

    def Integers(self, *arg):
        return map(self.Integer, arg)

    def test_init_and_equality(self):
        Integer = self.Integer

        v1 = Integer(23)
        v2 = Integer(v1)
        v3 = Integer(-9)
        with pytest.raises(ValueError):
            Integer(1.0)

        v4 = Integer(10**10)
        v5 = Integer(-(10**10))

        v6 = Integer(0xFFFF)
        v7 = Integer(0xFFFFFFFF)
        v8 = Integer(0xFFFFFFFFFFFFFFFF)

        assert v1 == v1
        assert v1 == 23
        assert v1 == v2
        assert v3 == -9
        assert v4 == 10**10
        assert v5 == -(10**10)
        assert v6 == 0xFFFF
        assert v7 == 0xFFFFFFFF
        assert v8 == 0xFFFFFFFFFFFFFFFF

        assert not (v1 == v4)  # noqa: SIM201 (tests __eq__)

        # Init and comparison between Integer's
        v6 = Integer(v1)
        assert v1 == v6

        assert not (Integer(0) == None)  # noqa: E711, SIM201 (tests __eq__)

    def test_conversion_to_int(self):
        v1, v2 = self.Integers(-23, 2**1000)
        assert int(v1) == -23
        assert int(v2) == 2**1000

    def test_equality_with_ints(self):
        v1, v2, v3 = self.Integers(23, -89, 2**1000)
        assert v1 == 23
        assert v2 == -89
        assert not (v1 == 24)  # noqa: SIM201 (tests __eq__)
        assert v3 == 2**1000

    def test_conversion_to_str(self):
        v1, v2, v3, v4 = self.Integers(20, 0, -20, 2**1000)
        assert str(v1) == "20"
        assert str(v2) == "0"
        assert str(v3) == "-20"
        assert (
            str(v4)
            == "10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046474983581941267398767559165543946077062914571196477686542167660429831652624386837205668069376"
        )

    def test_repr(self):
        v1, v2 = self.Integers(-1, 2**80)
        assert repr(v1) == "Integer(-1)"
        assert repr(v2) == "Integer(1208925819614629174706176)"

    def test_conversion_to_bytes(self):
        Integer = self.Integer

        v0 = Integer(0)
        assert v0.to_bytes() == b"\x00"

        v1 = Integer(0x17)
        assert v1.to_bytes() == b"\x17"

        v2 = Integer(0xFFFE)
        assert v2.to_bytes() == b"\xff\xfe"
        assert v2.to_bytes(3) == b"\x00\xff\xfe"
        with pytest.raises(ValueError):
            v2.to_bytes(1)

        assert v2.to_bytes(byteorder="little") == b"\xfe\xff"
        assert v2.to_bytes(3, byteorder="little") == b"\xfe\xff\x00"

        v3 = Integer(0xFF00AABBCCDDEE1122)
        assert v3.to_bytes() == b"\xff\x00\xaa\xbb\xcc\xdd\xee\x11\x22"
        assert v3.to_bytes(byteorder="little") == b"\x22\x11\xee\xdd\xcc\xbb\xaa\x00\xff"
        assert v3.to_bytes(10) == b"\x00\xff\x00\xaa\xbb\xcc\xdd\xee\x11\x22"
        assert v3.to_bytes(10, byteorder="little") == b"\x22\x11\xee\xdd\xcc\xbb\xaa\x00\xff\x00"
        with pytest.raises(ValueError):
            v3.to_bytes(8)

        v4 = Integer(-90)
        with pytest.raises(ValueError):
            v4.to_bytes()
        with pytest.raises(ValueError):
            v4.to_bytes(byteorder="bittle")

    def test_conversion_from_bytes(self):
        Integer = self.Integer

        v1 = Integer.from_bytes(b"\x00")
        assert isinstance(v1, Integer)
        assert v1 == 0

        v2 = Integer.from_bytes(b"\x00\x01")
        assert v2 == 1

        v3 = Integer.from_bytes(b"\xff\xff")
        assert v3 == 0xFFFF

        v4 = Integer.from_bytes(b"\x00\x01", "big")
        assert v4 == 1

        v5 = Integer.from_bytes(b"\x00\x01", byteorder="big")
        assert v5 == 1

        v6 = Integer.from_bytes(b"\x00\x01", byteorder="little")
        assert v6 == 0x0100

        with pytest.raises(ValueError):
            Integer.from_bytes(b"\x09", "bittle")

    def test_inequality(self):
        # Test Integer!=Integer and Integer!=int
        v1, v2, v3, v4 = self.Integers(89, 89, 90, -8)
        assert v1 != v3
        assert v1 != 90
        assert not (v1 != v2)  # noqa: SIM202 (tests __ne__)
        assert not (v1 != 89)  # noqa: SIM202 (tests __ne__)
        assert v1 != v4
        assert v4 != v1
        assert self.Integer(0) != None  # noqa: E711 (tests __ne__)

    def test_less_than(self):
        # Test Integer<Integer and Integer<int
        v1, v2, v3, v4, v5 = self.Integers(13, 13, 14, -8, 2**10)
        assert v1 < v3
        assert v1 < 14
        assert not (v1 < v2)
        assert not (v1 < 13)
        assert v4 < v1
        assert not (v1 < v4)
        assert v1 < v5
        assert not (v5 < v1)

    def test_less_than_or_equal(self):
        # Test Integer<=Integer and Integer<=int
        v1, v2, v3, v4, v5 = self.Integers(13, 13, 14, -4, 2**10)
        assert v1 <= v1
        assert v1 <= 13
        assert v1 <= v2
        assert v1 <= 14
        assert v1 <= v3
        assert not (v1 <= v4)
        assert v1 <= v5
        assert not (v5 <= v1)

    def test_more_than(self):
        # Test Integer>Integer and Integer>int
        v1, v2, v3, v4, v5 = self.Integers(13, 13, 14, -8, 2**10)
        assert v3 > v1
        assert v3 > 13
        assert not (v1 > v1)
        assert not (v1 > v2)
        assert not (v1 > 13)
        assert v1 > v4
        assert not (v4 > v1)
        assert v5 > v1
        assert not (v1 > v5)

    def test_more_than_or_equal(self):
        # Test Integer>=Integer and Integer>=int
        v1, v2, v3, v4 = self.Integers(13, 13, 14, -4)
        assert v3 >= v1
        assert v3 >= 13
        assert v1 >= v2
        assert v1 >= v1
        assert v1 >= 13
        assert not (v4 >= v1)

    def test_bool(self):
        v1, v2, v3, v4 = self.Integers(0, 10, -9, 2**10)
        assert not v1
        assert not bool(v1)
        assert v2
        assert bool(v2)
        assert v3
        assert v4

    def test_is_negative(self):
        v1, v2, _v3, v4, v5 = self.Integers(-(3**100), -3, 0, 3, 3**100)
        assert v1.is_negative()
        assert v2.is_negative()
        assert not v4.is_negative()
        assert not v5.is_negative()

    def test_addition(self):
        # Test Integer+Integer and Integer+int
        v1, v2, v3 = self.Integers(7, 90, -7)
        assert isinstance(v1 + v2, self.Integer)
        assert v1 + v2 == 97
        assert v1 + 90 == 97
        assert v1 + v3 == 0
        assert v1 + (-7) == 0
        assert v1 + 2**10 == 2**10 + 7

    def test_subtraction(self):
        # Test Integer-Integer and Integer-int
        v1, v2, v3 = self.Integers(7, 90, -7)
        assert isinstance(v1 - v2, self.Integer)
        assert v2 - v1 == 83
        assert v2 - 7 == 83
        assert v2 - v3 == 97
        assert v1 - (-7) == 14
        assert v1 - 2**10 == 7 - 2**10

    def test_multiplication(self):
        # Test Integer-Integer and Integer-int
        v1, v2, _v3, _v4 = self.Integers(4, 5, -2, 2**10)
        assert isinstance(v1 * v2, self.Integer)
        assert v1 * v2 == 20
        assert v1 * 5 == 20
        assert v1 * -2 == -8
        assert v1 * 2**10 == 4 * (2**10)

    def test_floor_div(self):
        v1, v2, v3 = self.Integers(3, 8, 2**80)
        assert isinstance(v1 // v2, self.Integer)
        assert v2 // v1 == 2
        assert v2 // 3 == 2
        assert v2 // -3 == -3
        assert v3 // 2**79 == 2
        with pytest.raises(ZeroDivisionError):
            v1 // 0

    def test_remainder(self):
        # Test Integer%Integer and Integer%int
        v1, v2, v3 = self.Integers(23, 5, -4)
        assert isinstance(v1 % v2, self.Integer)
        assert v1 % v2 == 3
        assert v1 % 5 == 3
        assert v3 % 5 == 1
        assert v1 % 2**10 == 23
        with pytest.raises(ZeroDivisionError):
            v1 % 0
        with pytest.raises(ValueError):
            v1 % -6

    def test_simple_exponentiation(self):
        v1, v2, v3 = self.Integers(4, 3, -2)
        assert isinstance(v1**v2, self.Integer)
        assert v1**v2 == 64
        assert pow(v1, v2) == 64
        assert v1**3 == 64
        assert pow(v1, 3) == 64
        assert v3**2 == 4
        assert v3**3 == -8

        with pytest.raises(ValueError):
            pow(v1, -3)

    def test_modular_exponentiation(self):
        v1, v2, v3 = self.Integers(23, 5, 17)

        assert isinstance(pow(v1, v2, v3), self.Integer)
        assert pow(v1, v2, v3) == 7
        assert pow(v1, 5, v3) == 7
        assert pow(v1, v2, 17) == 7
        assert pow(v1, 5, 17) == 7
        assert pow(v1, 0, 17) == 1
        assert pow(v1, 1, 2**80) == 23
        assert pow(v1, 2**80, 89298) == 17689

        with pytest.raises(ZeroDivisionError):
            pow(v1, 5, 0)
        with pytest.raises(ValueError):
            pow(v1, 5, -4)
        with pytest.raises(ValueError):
            pow(v1, -3, 8)

    def test_inplace_exponentiation(self):
        v1 = self.Integer(4)
        v1.inplace_pow(2)
        assert v1 == 16

        v1 = self.Integer(4)
        v1.inplace_pow(2, 15)
        assert v1 == 1

    def test_abs(self):
        v1, v2, v3, v4, v5 = self.Integers(-(2**100), -2, 0, 2, 2**100)
        assert abs(v1) == 2**100
        assert abs(v2) == 2
        assert abs(v3) == 0
        assert abs(v4) == 2
        assert abs(v5) == 2**100

    def test_sqrt(self):
        v1, v2, v3, v4 = self.Integers(-2, 0, 49, 10**100)

        with pytest.raises(ValueError):
            v1.sqrt()
        assert v2.sqrt() == 0
        assert v3.sqrt() == 7
        assert v4.sqrt() == 10**50

    def test_sqrt_module(self):

        # Invalid modulus (non positive)
        with pytest.raises(ValueError):
            self.Integer(5).sqrt(0)
        with pytest.raises(ValueError):
            self.Integer(5).sqrt(-1)

        # Simple cases
        assert self.Integer(0).sqrt(5) == 0
        assert self.Integer(1).sqrt(5) in (1, 4)

        # Test with all quadratic residues in several fields
        for p in (11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
            for i in range(p):
                square = i**2 % p
                res = self.Integer(square).sqrt(p)
                assert res in (i, p - i)

        # 2 is a non-quadratic reside in Z_11
        with pytest.raises(ValueError):
            self.Integer(2).sqrt(11)

        # 10 is not a prime
        with pytest.raises(ValueError):
            self.Integer(4).sqrt(10)

        # 5 is square residue of 4 and 7
        assert self.Integer(5 - 11).sqrt(11) in (4, 7)
        assert self.Integer(5 + 11).sqrt(11) in (4, 7)

    def test_in_place_add(self):
        v1, v2 = self.Integers(10, 20)

        v1 += v2
        assert v1 == 30
        v1 += 10
        assert v1 == 40
        v1 += -1
        assert v1 == 39
        v1 += 2**1000
        assert v1 == 39 + 2**1000

    def test_in_place_sub(self):
        v1, v2 = self.Integers(10, 20)

        v1 -= v2
        assert v1 == -10
        v1 -= -100
        assert v1 == 90
        v1 -= 90000
        assert v1 == -89910
        v1 -= -100000
        assert v1 == 10090

    def test_in_place_mul(self):
        v1, v2 = self.Integers(3, 5)

        v1 *= v2
        assert v1 == 15
        v1 *= 2
        assert v1 == 30
        v1 *= -2
        assert v1 == -60
        v1 *= 2**1000
        assert v1 == -60 * (2**1000)

    def test_in_place_modulus(self):
        v1, v2 = self.Integers(20, 7)

        v1 %= v2
        assert v1 == 6
        v1 %= 2**1000
        assert v1 == 6
        v1 %= 2
        assert v1 == 0

        def t():
            v3 = self.Integer(9)
            v3 %= 0

        with pytest.raises(ZeroDivisionError):
            t()

    def test_and(self):
        v1, v2, v3 = self.Integers(0xF4, 0x31, -0xF)
        assert isinstance(v1 & v2, self.Integer)
        assert v1 & v2 == 0x30
        assert v1 & 0x31 == 0x30
        assert v1 & v3 == 0xF0
        assert v1 & -0xF == 0xF0
        assert v3 & -0xF == -0xF
        assert v2 & (2**1000 + 0x31) == 0x31

    def test_or(self):
        v1, v2, v3 = self.Integers(0x40, 0x82, -0xF)
        assert isinstance(v1 | v2, self.Integer)
        assert v1 | v2 == 0xC2
        assert v1 | 0x82 == 0xC2
        assert v2 | v3 == -0xD
        assert v2 | 2**1000 == 2**1000 + 0x82

    def test_right_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        assert v1 >> 0 == v1
        assert isinstance(v1 >> v2, self.Integer)
        assert v1 >> v2 == 0x08
        assert v1 >> 1 == 0x08
        with pytest.raises(ValueError):
            v1 >> -1
        assert v1 >> (2**1000) == 0

        assert v3 >> 1 == -0x08
        assert v3 >> (2**1000) == -1

    def test_in_place_right_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        v1 >>= 0
        assert v1 == 0x10
        v1 >>= 1
        assert v1 == 0x08
        v1 >>= v2
        assert v1 == 0x04
        v3 >>= 1
        assert v3 == -0x08

        def shift_by_negative():
            v4 = self.Integer(0x90)
            v4 >>= -1

        with pytest.raises(ValueError):
            shift_by_negative()

        def m1():
            v4 = self.Integer(0x90)
            v4 >>= 2**1000
            return v4

        assert m1() == 0

        def m2():
            v4 = self.Integer(-1)
            v4 >>= 2**1000
            return v4

        assert m2() == -1

    def _test_left_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        assert v1 << 0 == v1
        assert isinstance(v1 << v2, self.Integer)
        assert v1 << v2 == 0x20
        assert v1 << 1 == 0x20
        assert v3 << 1 == -0x20
        with pytest.raises(ValueError):
            v1 << -1
        with pytest.raises(ValueError):
            v1 << (2**1000)

    def test_in_place_left_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        v1 <<= 0
        assert v1 == 0x10
        v1 <<= 1
        assert v1 == 0x20
        v1 <<= v2
        assert v1 == 0x40
        v3 <<= 1
        assert v3 == -0x20

        def shift_by_negative():
            v4 = self.Integer(0x90)
            v4 <<= -1

        with pytest.raises(ValueError):
            shift_by_negative()

        def m():
            v4 = self.Integer(0x90)
            v4 <<= 2**1000

        with pytest.raises(ValueError):
            m()

    def test_get_bit(self):
        v1, v2, v3 = self.Integers(0x102, -3, 1)
        assert v1.get_bit(0) == 0
        assert v1.get_bit(1) == 1
        assert v1.get_bit(v3) == 1
        assert v1.get_bit(8) == 1
        assert v1.get_bit(9) == 0

        with pytest.raises(ValueError):
            v1.get_bit(-1)
        assert v1.get_bit(2**1000) == 0

        with pytest.raises(ValueError):
            v2.get_bit(-1)
        with pytest.raises(ValueError):
            v2.get_bit(0)
        with pytest.raises(ValueError):
            v2.get_bit(1)
        with pytest.raises(ValueError):
            v2.get_bit(2 * 1000)

    def test_odd_even(self):
        v1, v2, v3, v4, v5 = self.Integers(0, 4, 17, -4, -17)

        assert v1.is_even()
        assert v2.is_even()
        assert not v3.is_even()
        assert v4.is_even()
        assert not v5.is_even()

        assert not v1.is_odd()
        assert not v2.is_odd()
        assert v3.is_odd()
        assert not v4.is_odd()
        assert v5.is_odd()

    def test_size_in_bits(self):
        v1, v2, v3, v4 = self.Integers(0, 1, 0x100, -90)
        assert v1.size_in_bits() == 1
        assert v2.size_in_bits() == 1
        assert v3.size_in_bits() == 9
        with pytest.raises(ValueError):
            v4.size_in_bits()

    def test_size_in_bytes(self):
        v1, v2, v3, v4, v5, v6 = self.Integers(0, 1, 0xFF, 0x1FF, 0x10000, -9)
        assert v1.size_in_bytes() == 1
        assert v2.size_in_bytes() == 1
        assert v3.size_in_bytes() == 1
        assert v4.size_in_bytes() == 2
        assert v5.size_in_bytes() == 3
        with pytest.raises(ValueError):
            v6.size_in_bits()

    def test_perfect_square(self):

        assert not self.Integer(-9).is_perfect_square()
        assert self.Integer(0).is_perfect_square()
        assert self.Integer(1).is_perfect_square()
        assert not self.Integer(2).is_perfect_square()
        assert not self.Integer(3).is_perfect_square()
        assert self.Integer(4).is_perfect_square()
        assert self.Integer(39 * 39).is_perfect_square()
        assert not self.Integer(39 * 39 + 1).is_perfect_square()

        for x in range(100, 1000):
            assert not self.Integer(x**2 + 1).is_perfect_square()
            assert self.Integer(x**2).is_perfect_square()

    def test_fail_if_divisible_by(self):
        v1, v2, v3 = self.Integers(12, -12, 4)

        # No failure expected
        v1.fail_if_divisible_by(7)
        v2.fail_if_divisible_by(7)
        v2.fail_if_divisible_by(2**80)

        # Failure expected
        with pytest.raises(ValueError):
            v1.fail_if_divisible_by(4)
        with pytest.raises(ValueError):
            v1.fail_if_divisible_by(v3)

    def test_multiply_accumulate(self):
        v1, v2, v3 = self.Integers(4, 3, 2)
        v1.multiply_accumulate(v2, v3)
        assert v1 == 10
        v1.multiply_accumulate(v2, 2)
        assert v1 == 16
        v1.multiply_accumulate(3, v3)
        assert v1 == 22
        v1.multiply_accumulate(1, -2)
        assert v1 == 20
        v1.multiply_accumulate(-2, 1)
        assert v1 == 18
        v1.multiply_accumulate(1, 2**1000)
        assert v1 == 18 + 2**1000
        v1.multiply_accumulate(2**1000, 1)
        assert v1 == 18 + 2**1001

    def test_set(self):
        v1, v2 = self.Integers(3, 6)
        v1.set(v2)
        assert v1 == 6
        v1.set(9)
        assert v1 == 9
        v1.set(-2)
        assert v1 == -2
        v1.set(2**1000)
        assert v1 == 2**1000

    def test_inverse(self):
        v1, v2, v3, v4, v5, v6 = self.Integers(2, 5, -3, 0, 723872, 3433)

        assert isinstance(v1.inverse(v2), self.Integer)
        assert v1.inverse(v2) == 3
        assert v1.inverse(5) == 3
        assert v3.inverse(5) == 3
        assert v5.inverse(92929921) == 58610507
        assert v6.inverse(9912) == 5353

        with pytest.raises(ValueError):
            v2.inverse(10)
        with pytest.raises(ValueError):
            v1.inverse(-3)
        with pytest.raises(ValueError):
            v4.inverse(10)
        with pytest.raises(ZeroDivisionError):
            v2.inverse(0)

    def test_inplace_inverse(self):
        v1, v2 = self.Integers(2, 5)

        v1.inplace_inverse(v2)
        assert v1 == 3

    def test_gcd(self):
        v1, v2, v3, v4 = self.Integers(6, 10, 17, -2)
        assert isinstance(v1.gcd(v2), self.Integer)
        assert v1.gcd(v2) == 2
        assert v1.gcd(10) == 2
        assert v1.gcd(v3) == 1
        assert v1.gcd(-2) == 2
        assert v4.gcd(6) == 2

    def test_lcm(self):
        v1, v2, v3, v4, v5 = self.Integers(6, 10, 17, -2, 0)
        assert isinstance(v1.lcm(v2), self.Integer)
        assert v1.lcm(v2) == 30
        assert v1.lcm(10) == 30
        assert v1.lcm(v3) == 102
        assert v1.lcm(-2) == 6
        assert v4.lcm(6) == 6
        assert v1.lcm(0) == 0
        assert v5.lcm(0) == 0

    def test_jacobi_symbol(self):

        data = (
            (1001, 1, 1),
            (19, 45, 1),
            (8, 21, -1),
            (5, 21, 1),
            (610, 987, -1),
            (1001, 9907, -1),
            (5, 3439601197, -1),
        )

        js = self.Integer.jacobi_symbol

        # Jacobi symbol is always 1 for k==1 or n==1
        for k in range(1, 30):
            assert js(k, 1) == 1
        for n in range(1, 30, 2):
            assert js(1, n) == 1

        # Fail if n is not positive odd
        with pytest.raises(ValueError):
            js(6, -2)
        with pytest.raises(ValueError):
            js(6, -1)
        with pytest.raises(ValueError):
            js(6, 0)
        with pytest.raises(ValueError):
            js(0, 0)
        with pytest.raises(ValueError):
            js(6, 2)
        with pytest.raises(ValueError):
            js(6, 4)
        with pytest.raises(ValueError):
            js(6, 6)
        with pytest.raises(ValueError):
            js(6, 8)

        for tv in data:
            assert js(tv[0], tv[1]) == tv[2]
            assert js(self.Integer(tv[0]), tv[1]) == tv[2]
            assert js(tv[0], self.Integer(tv[1])) == tv[2]

    def test_jacobi_symbol_wikipedia(self):
        # Test vectors from https://en.wikipedia.org/wiki/Jacobi_symbol
        # fmt: off
        tv = [
            (3, [(1, 1), (2, -1), (3, 0), (4, 1), (5, -1), (6, 0), (7, 1), (8, -1), (9, 0), (10, 1), (11, -1), (12, 0), (13, 1), (14, -1), (15, 0), (16, 1), (17, -1), (18, 0), (19, 1), (20, -1), (21, 0), (22, 1), (23, -1), (24, 0), (25, 1), (26, -1), (27, 0), (28, 1), (29, -1), (30, 0)]),
            (5, [(1, 1), (2, -1), (3, -1), (4, 1), (5, 0), (6, 1), (7, -1), (8, -1), (9, 1), (10, 0), (11, 1), (12, -1), (13, -1), (14, 1), (15, 0), (16, 1), (17, -1), (18, -1), (19, 1), (20, 0), (21, 1), (22, -1), (23, -1), (24, 1), (25, 0), (26, 1), (27, -1), (28, -1), (29, 1), (30, 0)]),
            (7, [(1, 1), (2, 1), (3, -1), (4, 1), (5, -1), (6, -1), (7, 0), (8, 1), (9, 1), (10, -1), (11, 1), (12, -1), (13, -1), (14, 0), (15, 1), (16, 1), (17, -1), (18, 1), (19, -1), (20, -1), (21, 0), (22, 1), (23, 1), (24, -1), (25, 1), (26, -1), (27, -1), (28, 0), (29, 1), (30, 1)]),
            (9, [(1, 1), (2, 1), (3, 0), (4, 1), (5, 1), (6, 0), (7, 1), (8, 1), (9, 0), (10, 1), (11, 1), (12, 0), (13, 1), (14, 1), (15, 0), (16, 1), (17, 1), (18, 0), (19, 1), (20, 1), (21, 0), (22, 1), (23, 1), (24, 0), (25, 1), (26, 1), (27, 0), (28, 1), (29, 1), (30, 0)]),
            (11, [(1, 1), (2, -1), (3, 1), (4, 1), (5, 1), (6, -1), (7, -1), (8, -1), (9, 1), (10, -1), (11, 0), (12, 1), (13, -1), (14, 1), (15, 1), (16, 1), (17, -1), (18, -1), (19, -1), (20, 1), (21, -1), (22, 0), (23, 1), (24, -1), (25, 1), (26, 1), (27, 1), (28, -1), (29, -1), (30, -1)]),
            (13, [(1, 1), (2, -1), (3, 1), (4, 1), (5, -1), (6, -1), (7, -1), (8, -1), (9, 1), (10, 1), (11, -1), (12, 1), (13, 0), (14, 1), (15, -1), (16, 1), (17, 1), (18, -1), (19, -1), (20, -1), (21, -1), (22, 1), (23, 1), (24, -1), (25, 1), (26, 0), (27, 1), (28, -1), (29, 1), (30, 1)]),
            (15, [(1, 1), (2, 1), (3, 0), (4, 1), (5, 0), (6, 0), (7, -1), (8, 1), (9, 0), (10, 0), (11, -1), (12, 0), (13, -1), (14, -1), (15, 0), (16, 1), (17, 1), (18, 0), (19, 1), (20, 0), (21, 0), (22, -1), (23, 1), (24, 0), (25, 0), (26, -1), (27, 0), (28, -1), (29, -1), (30, 0)]),
            (17, [(1, 1), (2, 1), (3, -1), (4, 1), (5, -1), (6, -1), (7, -1), (8, 1), (9, 1), (10, -1), (11, -1), (12, -1), (13, 1), (14, -1), (15, 1), (16, 1), (17, 0), (18, 1), (19, 1), (20, -1), (21, 1), (22, -1), (23, -1), (24, -1), (25, 1), (26, 1), (27, -1), (28, -1), (29, -1), (30, 1)]),
            (19, [(1, 1), (2, -1), (3, -1), (4, 1), (5, 1), (6, 1), (7, 1), (8, -1), (9, 1), (10, -1), (11, 1), (12, -1), (13, -1), (14, -1), (15, -1), (16, 1), (17, 1), (18, -1), (19, 0), (20, 1), (21, -1), (22, -1), (23, 1), (24, 1), (25, 1), (26, 1), (27, -1), (28, 1), (29, -1), (30, 1)]),
            (21, [(1, 1), (2, -1), (3, 0), (4, 1), (5, 1), (6, 0), (7, 0), (8, -1), (9, 0), (10, -1), (11, -1), (12, 0), (13, -1), (14, 0), (15, 0), (16, 1), (17, 1), (18, 0), (19, -1), (20, 1), (21, 0), (22, 1), (23, -1), (24, 0), (25, 1), (26, 1), (27, 0), (28, 0), (29, -1), (30, 0)]),
            (23, [(1, 1), (2, 1), (3, 1), (4, 1), (5, -1), (6, 1), (7, -1), (8, 1), (9, 1), (10, -1), (11, -1), (12, 1), (13, 1), (14, -1), (15, -1), (16, 1), (17, -1), (18, 1), (19, -1), (20, -1), (21, -1), (22, -1), (23, 0), (24, 1), (25, 1), (26, 1), (27, 1), (28, -1), (29, 1), (30, -1)]),
            (25, [(1, 1), (2, 1), (3, 1), (4, 1), (5, 0), (6, 1), (7, 1), (8, 1), (9, 1), (10, 0), (11, 1), (12, 1), (13, 1), (14, 1), (15, 0), (16, 1), (17, 1), (18, 1), (19, 1), (20, 0), (21, 1), (22, 1), (23, 1), (24, 1), (25, 0), (26, 1), (27, 1), (28, 1), (29, 1), (30, 0)]),
            (27, [(1, 1), (2, -1), (3, 0), (4, 1), (5, -1), (6, 0), (7, 1), (8, -1), (9, 0), (10, 1), (11, -1), (12, 0), (13, 1), (14, -1), (15, 0), (16, 1), (17, -1), (18, 0), (19, 1), (20, -1), (21, 0), (22, 1), (23, -1), (24, 0), (25, 1), (26, -1), (27, 0), (28, 1), (29, -1), (30, 0)]),
            (29, [(1, 1), (2, -1), (3, -1), (4, 1), (5, 1), (6, 1), (7, 1), (8, -1), (9, 1), (10, -1), (11, -1), (12, -1), (13, 1), (14, -1), (15, -1), (16, 1), (17, -1), (18, -1), (19, -1), (20, 1), (21, -1), (22, 1), (23, 1), (24, 1), (25, 1), (26, -1), (27, -1), (28, 1), (29, 0), (30, 1)]),
            ]
        # fmt: on

        js = self.Integer.jacobi_symbol

        for n, kj in tv:
            for k, j in kj:
                assert js(k, n) == j

    def test_hex(self):
        (v1,) = self.Integers(0x10)
        assert hex(v1) == "0x10"

    def test_mult_modulo_bytes(self):
        modmult = self.Integer._mult_modulo_bytes

        res = modmult(4, 5, 19)
        assert res == b"\x01"

        res = modmult(4 - 19, 5, 19)
        assert res == b"\x01"

        res = modmult(4, 5 - 19, 19)
        assert res == b"\x01"

        res = modmult(4 + 19, 5, 19)
        assert res == b"\x01"

        res = modmult(4, 5 + 19, 19)
        assert res == b"\x01"

        modulus = 2**512 - 1  # 64 bytes
        t1 = 13**100
        t2 = 17**100
        expect = b"\xfa\xb2\x11\x87\xc3(y\x07\xf8\xf1n\xdepq\x0b\xca\xf3\xd3B,\xef\xf2\xfbf\xcc)\x8dZ*\x95\x98r\x96\xa8\xd5\xc3}\xe2q:\xa2'z\xf48\xde%\xef\t\x07\xbc\xc4[C\x8bUE2\x90\xef\x81\xaa:\x08"
        assert expect == modmult(t1, t2, modulus)

        with pytest.raises(ZeroDivisionError):
            modmult(4, 5, 0)
        with pytest.raises(ValueError):
            modmult(4, 5, -1)
        with pytest.raises(ValueError):
            modmult(4, 5, 4)


class TestIntegerInt(IntegerTests):
    def setup_method(self):
        self.Integer = IntegerNative


@pytest.mark.skipif(_gmp_error is not None, reason="GMP not available (%s)" % _gmp_error)
class TestIntegerGMP(IntegerTests):
    def setup_method(self):
        self.Integer = IntegerGMP


@pytest.mark.skipif(_custom_error is not None, reason="custom modexp not available (%s)" % _custom_error)
class TestIntegerCustomModexp(IntegerTests):
    def setup_method(self):
        self.Integer = IntegerCustom


class TestIntegerRandom:
    def test_random_exact_bits(self):

        for _ in range(1000):
            a = IntegerNative.random(exact_bits=8)
            assert not (a < 128)
            assert not (a >= 256)

        for bits_value in range(1024, 1024 + 8):
            a = IntegerNative.random(exact_bits=bits_value)
            assert not (a < 2 ** (bits_value - 1))
            assert not (a >= 2**bits_value)

    def test_random_max_bits(self):

        flag = False
        for _ in range(1000):
            a = IntegerNative.random(max_bits=8)
            flag = flag or a < 128
            assert not (a >= 256)
        assert flag

        for bits_value in range(1024, 1024 + 8):
            a = IntegerNative.random(max_bits=bits_value)
            assert not (a >= 2**bits_value)

    def test_random_bits_custom_rng(self):

        class CustomRNG:
            def __init__(self):
                self.counter = 0

            def __call__(self, size):
                self.counter += size
                return bytes([0]) * size

        custom_rng = CustomRNG()
        IntegerNative.random(exact_bits=32, randfunc=custom_rng)
        assert custom_rng.counter == 4

    def test_random_range(self):

        func = IntegerNative.random_range

        for _x in range(200):
            a = func(min_inclusive=1, max_inclusive=15)
            assert 1 <= a <= 15

        for _x in range(200):
            a = func(min_inclusive=1, max_exclusive=15)
            assert 1 <= a < 15

        with pytest.raises(ValueError):
            func(min_inclusive=1, max_inclusive=2, max_exclusive=3)
        with pytest.raises(ValueError):
            func(max_inclusive=2, max_exclusive=3)
