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

from Crypto.Math.Numbers import Natural as NaturalGeneric
from Crypto.Math._Numbers_int import Natural as NaturalInt
from Crypto.Math._Numbers_gmp import Natural as NaturalGMP


class TestNaturalBase(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, "Natural"):
            from Crypto.Math.Numbers import Natural as NaturalDefault
            self.Natural = NaturalDefault

    def Naturals(self, *arg):
        return map(self.Natural, arg)

    def test_init_and_equality(self):
        Natural = self.Natural

        a = Natural(23)
        d = Natural(a)
        self.assertRaises(ValueError, Natural, 1.0)
        self.assertRaises(ValueError, Natural, -1)

        c = Natural(10)
        self.failUnless(a == a)
        self.failUnless(a == d)
        self.failIf(a == c)

    def test_conversion_to_bytes(self):
        Natural = self.Natural

        a = Natural(0x17)
        self.assertEqual(b("\x17"), a.to_bytes())

        c = Natural(0xFFFF)
        self.assertEqual(b("\xFF\xFF"), c.to_bytes())
        self.assertEqual(b("\x00\xFF\xFF"), c.to_bytes(3))
        self.assertRaises(ValueError, c.to_bytes, 1)

    def test_conversion_to_int(self):
        Natural = self.Natural

        a = Natural(23)
        self.assertEqual(int(a), 23)

        f = Natural(2 ** 1000)
        self.assertEqual(int(f), 2 ** 1000)

    def test_equality_with_ints(self):
        a = self.Natural(23)
        self.failUnless(a == 23)
        self.failIf(a == 24)

    def test_conversion_from_bytes(self):
        Natural = self.Natural

        a = Natural.from_bytes(b("\x00"))
        self.assertEqual(0, a)

        a = Natural.from_bytes(b("\x00\x00"))
        self.assertEqual(0, a)

        c = Natural.from_bytes(b("\xFF\xFF"))
        self.assertEqual(0xFFFF, c)

    def test_inequality(self):
        # Test Natural!=Natural and Natural!=int
        a, d, c = self.Naturals(89, 89, 90)
        self.failUnless(a != c)
        self.failUnless(a != 90)
        self.failIf(a != d)
        self.failIf(a != 89)

    def test_less_than(self):
        # Test Natural<Natural and Natural<int
        a, d, c = self.Naturals(13, 13, 14)
        self.failUnless(a < c)
        self.failUnless(a < 14)
        self.failIf(a < d)
        self.failIf(a < 13)

    def test_less_than_or_equal(self):
        # Test Natural<=Natural and Natural<=int
        a, d, c, e = self.Naturals(13, 13, 14, 4)
        self.failUnless(a <= c)
        self.failUnless(a <= 14)
        self.failUnless(a <= d)
        self.failUnless(a <= a)
        self.failUnless(a <= 13)
        self.failIf(a <= e)

    def test_more_than(self):
        # Test Natural>Natural and Natural>int
        a, d, c = self.Naturals(13, 13, 14)
        self.failUnless(c > a)
        self.failUnless(c > 13)
        self.failIf(d > a)
        self.failIf(d < 13)

    def test_more_than_or_equal(self):
        # Test Natural>=Natural and Natural>=int
        a, d, c, e = self.Naturals(13, 13, 14, 4)
        self.failUnless(c >= a)
        self.failUnless(c >= 13)
        self.failUnless(a >= d)
        self.failUnless(a >= a)
        self.failUnless(a >= 13)
        self.failIf(e >= a)

    def test_addition(self):
        # Test Natural+Natural and Natural+int
        a, d = self.Naturals(7, 90)
        self.assertEqual(a + d, 97)
        self.assertEqual(a + 90, 97)
        self.assertEqual(a + (-7), 0)
        self.assertRaises(ValueError, lambda: a + (-8))

    def test_subtraction(self):
        # Test Natural-Natural and Natural-int
        a, d = self.Naturals(7, 90)
        self.assertEqual(d - a, 83)
        self.assertEqual(d - 7, 83)
        self.assertEqual(d - (-7), 97)
        self.assertRaises(ValueError, lambda: a - d)
        self.assertRaises(ValueError, lambda: a - 90)

    def test_multiplication(self):
        # Test Natural-Natural and Natural-int
        a, d = self.Naturals(4, 5)
        self.assertEqual(a * d, 20)
        self.assertEqual(a * 5, 20)
        self.assertRaises(ValueError, lambda: a * (-3))

    def test_remainder(self):
        # Test Natural%Natural and Natural%int
        a, d = self.Naturals(23, 5)
        self.assertEqual(a % d, 3)
        self.assertEqual(a % 5, 3)
        self.assertRaises(ZeroDivisionError, lambda: a % 0)

    def test_simple_exponentiation(self):
        a, d = self.Naturals(4, 3)

        self.assertEqual(a ** d, 64)
        self.assertEqual(pow(a, d), 64)
        self.assertEqual(a ** 3, 64)
        self.assertEqual(pow(a, 3), 64)

        self.assertRaises(ValueError, pow, a, -3)

    def test_modular_exponentiation(self):
        a, d, e = self.Naturals(23, 5, 17)

        self.assertEqual(pow(a, d, e), 7)
        self.assertEqual(pow(a, 5, e), 7)
        self.assertEqual(pow(a, d, 17), 7)
        self.assertEqual(pow(a, 5, 17), 7)
        self.assertEqual(pow(a, 0, 17), 1)

        self.assertRaises(ValueError, pow, a, 5, 0)
        self.assertRaises(ValueError, pow, a, 5, -4)
        self.assertRaises(ValueError, pow, a, -3, 8)

    def test_and(self):
        a, d = self.Naturals(0xF4, 0x31)
        self.assertEqual(a & d, 0x30)
        self.assertEqual(a & 0x31, 0x30)

    def test_bool(self):
        a, d = self.Naturals(0, 1)
        self.failIf(a)
        self.failUnless(d)

    def test_right_shift(self):
        a, one = self.Naturals(0x10, 1)
        self.assertEqual(a >> 0, a)
        self.assertEqual(a >> one, 0x08)
        self.assertEqual(a >> 1, 0x08)

    def test_in_place_right_shift(self):
        a, one = self.Naturals(0x10, 1)
        a >>= 0
        self.assertEqual(a, 0x10)
        a >>= 1
        self.assertEqual(a, 0x08)
        a >>= one
        self.assertEqual(a, 0x04)

    def test_size_in_bits(self):
        a, c, d = self.Naturals(0, 1, 0x100)
        self.assertEqual(a.size_in_bits(), 1)
        self.assertEqual(c.size_in_bits(), 1)
        self.assertEqual(d.size_in_bits(), 9)

    def test_odd_even(self):
        a, c, d = self.Naturals(0, 4, 17)

        self.failUnless(a.is_even())
        self.failUnless(c.is_even())
        self.failIf(d.is_even())

        self.failIf(a.is_odd())
        self.failIf(c.is_odd())
        self.failUnless(d.is_odd())

    def test_perfect_square(self):

        self.failUnless(self.Natural(0).is_perfect_square())
        self.failUnless(self.Natural(1).is_perfect_square())
        self.failIf(self.Natural(2).is_perfect_square())
        self.failIf(self.Natural(3).is_perfect_square())
        self.failUnless(self.Natural(4).is_perfect_square())

        for x in xrange(100, 1000):
            self.failIf(self.Natural(x**2+1).is_perfect_square())
            self.failUnless(self.Natural(x**2).is_perfect_square())

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

        for tv in data:
            self.assertEqual(self.Natural.jacobi_symbol(tv[0], tv[1]), tv[2])
            self.assertEqual(self.Natural.jacobi_symbol(self.Natural(tv[0]), tv[1]), tv[2])
            self.assertEqual(self.Natural.jacobi_symbol(tv[0], self.Natural(tv[1])), tv[2])

        self.assertRaises(ValueError, self.Natural.jacobi_symbol, 6, 8)

class TestNaturalInt(TestNaturalBase):

    def setUp(self):
        self.Natural = NaturalInt
        TestNaturalBase.setUp(self)


class TestNaturalGMP(TestNaturalBase):

    def setUp(self):
        self.Natural = NaturalGMP
        TestNaturalBase.setUp(self)


class TestNaturalGeneric(unittest.TestCase):

    def test_random_exact_bits(self):

        for _ in xrange(1000):
            a = NaturalGeneric.random(exact_bits=8)
            self.failIf(a < 128)
            self.failIf(a >= 256)

        for bits_value in xrange(1024, 1024 + 8):
            a = NaturalGeneric.random(exact_bits=bits_value)
            self.failIf(a < 2**(bits_value - 1))
            self.failIf(a >= 2**bits_value)

    def test_random_max_bits(self):

        flag = False
        for _ in xrange(1000):
            a = NaturalGeneric.random(max_bits=8)
            flag = flag or a < 128
            self.failIf(a>=256)
        self.failUnless(flag)

        for bits_value in xrange(1024, 1024 + 8):
            a = NaturalGeneric.random(max_bits=bits_value)
            self.failIf(a >= 2**bits_value)

    def test_random_bits_custom_rng(self):

        class CustomRNG(object):
            def __init__(self):
                self.counter = 0

            def __call__(self, size):
                self.counter += size
                return bchr(0) * size

        custom_rng = CustomRNG()
        a = NaturalGeneric.random(exact_bits=32, randfunc=custom_rng)
        self.assertEqual(custom_rng.counter, 4)

    def test_random_range(self):

        for x in xrange(2, 20):
            a = NaturalGeneric.random_range(1, x)
            self.failUnless(1 <= a <= x)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestNaturalInt)
    try:
        from Crypto.Math._Numbers_gmp import Natural as NaturalGMP
        tests += list_test_cases(TestNaturalGMP)
    except ImportError:
        print "Skipping GMP tests"
    tests += list_test_cases(TestNaturalGeneric)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
