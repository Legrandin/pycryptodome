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

import unittest

from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Util.py3compat import *

from Crypto.Math.Numbers import Integer as IntegerGeneric
from Crypto.Math import _Numbers_int as NumbersInt
from Crypto.Math import _Numbers_gmp as NumbersGMP


class TestIntegerBase(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, "Integer"):
            from Crypto.Math.Numbers import Integer as IntegerDefault
            self.Integer = IntegerDefault

    def Integers(self, *arg):
        return map(self.Integer, arg)

    def test_init_and_equality(self):
        Integer = self.Integer

        v1 = Integer(23)
        v2 = Integer(v1)
        v3 = Integer(-9)
        self.assertRaises(ValueError, Integer, 1.0)

        v4 = Integer(10**10)
        self.failUnless(v1 == v1)
        self.failUnless(v1 == v2)
        self.failIf(v1 == v4)

    def test_conversion_to_int(self):
        v1, v2 = self.Integers(-23, 2 ** 1000)
        self.assertEqual(int(v1), -23)
        self.assertEqual(int(v2), 2 ** 1000)

    def test_equality_with_ints(self):
        v1, v2 = self.Integers(23, -89)
        self.failUnless(v1 == 23)
        self.failUnless(v2 == -89)
        self.failIf(v1 == 24)

    def test_conversion_to_str(self):
        v1, v2, v3 = self.Integers(20, 0, -20)
        self.failUnless(str(v1) == "20")
        self.failUnless(str(v2) == "0")
        self.failUnless(str(v3) == "-20")

    def test_conversion_to_bytes(self):
        Integer = self.Integer

        v1 = Integer(0x17)
        self.assertEqual(b("\x17"), v1.to_bytes())

        v2 = Integer(0xFFFF)
        self.assertEqual(b("\xFF\xFF"), v2.to_bytes())
        self.assertEqual(b("\x00\xFF\xFF"), v2.to_bytes(3))
        self.assertRaises(ValueError, v2.to_bytes, 1)

        v3 = Integer(-90)
        self.assertRaises(ValueError, v3.to_bytes)

    def test_conversion_from_bytes(self):
        Integer = self.Integer

        v1 = Integer.from_bytes(b("\x00"))
        self.assertEqual(0, v1)

        v2 = Integer.from_bytes(b("\x00\x00"))
        self.assertEqual(0, v2)

        v3 = Integer.from_bytes(b("\xFF\xFF"))
        self.assertEqual(0xFFFF, v3)

    def test_inequality(self):
        # Test Integer!=Integer and Integer!=int
        v1, v2, v3 = self.Integers(89, 89, 90)
        self.failUnless(v1 != v3)
        self.failUnless(v1 != 90)
        self.failIf(v1 != v2)
        self.failIf(v1 != 89)

    def test_less_than(self):
        # Test Integer<Integer and Integer<int
        v1, v2, v3 = self.Integers(13, 13, 14)
        self.failUnless(v1 < v3)
        self.failUnless(v1 < 14)
        self.failIf(v1 < v2)
        self.failIf(v1 < 13)

    def test_less_than_or_equal(self):
        # Test Integer<=Integer and Integer<=int
        v1, v2, v3, v4 = self.Integers(13, 13, 14, -4)
        self.failUnless(v1 <= v1)
        self.failUnless(v1 <= 13)
        self.failUnless(v1 <= v2)
        self.failUnless(v1 <= 14)
        self.failUnless(v1 <= v3)
        self.failIf(v1 <= v4)

    def test_more_than(self):
        # Test Integer>Integer and Integer>int
        v1, v2, v3 = self.Integers(13, 13, 14)
        self.failUnless(v3 > v1)
        self.failUnless(v3 > 13)
        self.failIf(v1 > v1)
        self.failIf(v1 > v2)
        self.failIf(v1 > 13)

    def test_more_than_or_equal(self):
        # Test Integer>=Integer and Integer>=int
        v1, v2, v3, v4 = self.Integers(13, 13, 14, -4)
        self.failUnless(v3 >= v1)
        self.failUnless(v3 >= 13)
        self.failUnless(v1 >= v2)
        self.failUnless(v1 >= v1)
        self.failUnless(v1 >= 13)
        self.failIf(v4 >= v1)

    def test_bool(self):
        v1, v2 = self.Integers(0, 10)
        self.failIf(v1)
        self.failIf(bool(v1))
        self.failUnless(v2)
        self.failUnless(bool(v2))

    def test_addition(self):
        # Test Integer+Integer and Integer+int
        v1, v2, v3 = self.Integers(7, 90, -7)
        self.assertEqual(v1 + v2, 97)
        self.assertEqual(v1 + 90, 97)
        self.assertEqual(v1 + v3, 0)

    def test_subtraction(self):
        # Test Integer-Integer and Integer-int
        v1, v2, v3 = self.Integers(7, 90, -7)
        self.assertEqual(v2 - v1, 83)
        self.assertEqual(v2 - 7, 83)
        self.assertEqual(v2 - v3, 97)

    def test_multiplication(self):
        # Test Integer-Integer and Integer-int
        v1, v2 = self.Integers(4, 5)
        self.assertEqual(v1 * v2, 20)
        self.assertEqual(v1 * 5, 20)

    def test_remainder(self):
        # Test Integer%Integer and Integer%int
        v1, v2, v3 = self.Integers(23, 5, -4)
        self.assertEqual(v1 % v2, 3)
        self.assertEqual(v1 % 5, 3)
        self.assertEqual(v3 % 5, 1)
        self.assertRaises(ZeroDivisionError, lambda: v1 % 0)
        self.assertRaises(ValueError, lambda: v1 % -6)

    def test_simple_exponentiation(self):
        v1, v2, v3 = self.Integers(4, 3, -2)

        self.assertEqual(v1 ** v2, 64)
        self.assertEqual(pow(v1, v2), 64)
        self.assertEqual(v1 ** 3, 64)
        self.assertEqual(pow(v1, 3), 64)
        self.assertEqual(v3 ** 2, 4)
        self.assertEqual(v3 ** 3, -8)

        self.assertRaises(ValueError, pow, v1, -3)

    def test_modular_exponentiation(self):
        v1, v2, v3 = self.Integers(23, 5, 17)

        self.assertEqual(pow(v1, v2, v3), 7)
        self.assertEqual(pow(v1, 5,  v3), 7)
        self.assertEqual(pow(v1, v2, 17), 7)
        self.assertEqual(pow(v1, 5,  17), 7)
        self.assertEqual(pow(v1, 0,  17), 1)

        self.assertRaises(ZeroDivisionError, pow, v1, 5, 0)
        self.assertRaises(ValueError, pow, v1, 5, -4)
        self.assertRaises(ValueError, pow, v1, -3, 8)

    def test_and(self):
        v1, v2, v3 = self.Integers(0xF4, 0x31, -0xF)
        self.assertEqual(v1 & v2, 0x30)
        self.assertEqual(v1 & 0x31, 0x30)
        self.assertEqual(v1 & v3, 0xF0)
        self.assertEqual(v1 & -0xF, 0xF0)
        self.assertEqual(v3 & -0xF, -0xF)

    def test_or(self):
        v1, v2, v3 = self.Integers(0x40, 0x82, -0xF)
        self.assertEqual(v1 | v2, 0xC2)
        self.assertEqual(v1 | 0x82, 0xC2)
        self.assertEqual(v2 | v3, -0xD)

    def test_right_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        self.assertEqual(v1 >> 0, v1)
        self.assertEqual(v1 >> v2, 0x08)
        self.assertEqual(v1 >> 1, 0x08)
        self.assertEqual(v3 >> 1, -0x08)
        self.assertRaises(ValueError, lambda: v1 >> -1)

    def test_in_place_right_shift(self):
        v1, v2, v3 = self.Integers(0x10, 1, -0x10)
        v1 >>= 0
        self.assertEqual(v1, 0x10)
        v1 >>= 1
        self.assertEqual(v1, 0x08)
        v1 >>= v2
        self.assertEqual(v1, 0x04)
        v3 >>= 1
        self.assertEqual(v3, -0x08)
        def l():
            v4 = self.Integer(0x90)
            v4 >>= -1
        self.assertRaises(ValueError, l)

    def test_odd_even(self):
        v1, v2, v3, v4, v5 = self.Integers(0, 4, 17, -4, -17)

        self.failUnless(v1.is_even())
        self.failUnless(v2.is_even())
        self.failIf(v3.is_even())
        self.failUnless(v4.is_even())
        self.failIf(v5.is_even())

        self.failIf(v1.is_odd())
        self.failIf(v2.is_odd())
        self.failUnless(v3.is_odd())
        self.failIf(v4.is_odd())
        self.failUnless(v5.is_odd())

    def test_size_in_bits(self):
        v1, v2, v3, v4 = self.Integers(0, 1, 0x100, -90)
        self.assertEqual(v1.size_in_bits(), 1)
        self.assertEqual(v2.size_in_bits(), 1)
        self.assertEqual(v3.size_in_bits(), 9)
        self.assertRaises(ValueError, v4.size_in_bits)

    def test_perfect_square(self):

        self.failIf(self.Integer(-9).is_perfect_square())
        self.failUnless(self.Integer(0).is_perfect_square())
        self.failUnless(self.Integer(1).is_perfect_square())
        self.failIf(self.Integer(2).is_perfect_square())
        self.failIf(self.Integer(3).is_perfect_square())
        self.failUnless(self.Integer(4).is_perfect_square())
        self.failUnless(self.Integer(39*39).is_perfect_square())
        self.failIf(self.Integer(39*39+1).is_perfect_square())

        for x in xrange(100, 1000):
            self.failIf(self.Integer(x**2+1).is_perfect_square())
            self.failUnless(self.Integer(x**2).is_perfect_square())

    def test_is_divisible_by_ulong(self):
        v1, v2 = self.Integers(12, -12)
        self.failUnless(v1.is_divisible_by_ulong(3))
        self.failIf(v1.is_divisible_by_ulong(5))
        self.failUnless(v2.is_divisible_by_ulong(3))
        self.failIf(v2.is_divisible_by_ulong(5))

        self.assertRaises(ValueError, v1.is_divisible_by_ulong, 2**80)
        self.assertRaises(ValueError, v1.is_divisible_by_ulong, -4)

    def test_jacobi_symbol(self):

        data = (
            (1001, 1, 1),
            (19, 45, 1),
            (8, 21, -1),
            (5, 21, 1),
            (610, 987, -1),
            (1001, 9907, -1),
            (5, 3439601197, -1)
            )

        js = self.Integer.jacobi_symbol

        for tv in data:
            self.assertEqual(js(tv[0], tv[1]), tv[2])
            self.assertEqual(js(self.Integer(tv[0]), tv[1]), tv[2])
            self.assertEqual(js(tv[0], self.Integer(tv[1])), tv[2])

        self.assertRaises(ValueError, js, 6, 8)

class TestIntegerInt(TestIntegerBase):

    def setUp(self):
        self.Numbers = NumbersInt
        self.Integer = NumbersInt.Integer
        TestIntegerBase.setUp(self)


class TestIntegerGMP(TestIntegerBase):

    def setUp(self):
        self.Numbers = NumbersGMP
        self.Integer = NumbersGMP.Integer
        TestIntegerBase.setUp(self)


class TestIntegerGeneric(unittest.TestCase):

    def test_random_exact_bits(self):

        for _ in xrange(1000):
            a = IntegerGeneric.random(exact_bits=8)
            self.failIf(a < 128)
            self.failIf(a >= 256)

        for bits_value in xrange(1024, 1024 + 8):
            a = IntegerGeneric.random(exact_bits=bits_value)
            self.failIf(a < 2**(bits_value - 1))
            self.failIf(a >= 2**bits_value)

    def test_random_max_bits(self):

        flag = False
        for _ in xrange(1000):
            a = IntegerGeneric.random(max_bits=8)
            flag = flag or a < 128
            self.failIf(a>=256)
        self.failUnless(flag)

        for bits_value in xrange(1024, 1024 + 8):
            a = IntegerGeneric.random(max_bits=bits_value)
            self.failIf(a >= 2**bits_value)

    def test_random_bits_custom_rng(self):

        class CustomRNG(object):
            def __init__(self):
                self.counter = 0

            def __call__(self, size):
                self.counter += size
                return bchr(0) * size

        custom_rng = CustomRNG()
        a = IntegerGeneric.random(exact_bits=32, randfunc=custom_rng)
        self.assertEqual(custom_rng.counter, 4)

    def test_random_range(self):

        for x in xrange(2, 20):
            a = IntegerGeneric.random_range(1, x)
            self.failUnless(1 <= a <= x)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestIntegerInt)
    try:
        from Crypto.Math._Numbers_gmp import Integer as IntegerGMP
        tests += list_test_cases(TestIntegerGMP)
    except ImportError:
        print "Skipping GMP tests"
    tests += list_test_cases(TestIntegerGeneric)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
