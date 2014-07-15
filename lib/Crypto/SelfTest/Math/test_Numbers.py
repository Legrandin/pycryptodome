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

from Crypto.Math.Numbers import Natural

def Naturals(*arg):
    return map(Natural, arg)

class TestNatural(unittest.TestCase):

    def test_conversion_from_int(self):
        a = Natural(23)
        self.assertEqual(23, a)
        self.assertEqual(23, int(a))

        b = Natural(0xFFFF)
        self.assertEqual(0xFFFF, b)
        self.assertEqual(0xFFFF, int(b))

    def test_conversion_from_bytes(self):
        a = Natural.from_bytes("\x00")
        self.assertEqual(0, a)

        b = Natural.from_bytes("\xFF\xFF")
        self.assertEqual(0xFFFF, b)

    def test_conversion_to_bytes(self):
        a = Natural(0x17)
        self.assertEqual("\x17", a.to_bytes())

        b = Natural(0xFFFF)
        self.assertEqual("\xFF\xFF", b.to_bytes())

    def test_negative_number_is_not_natural(self):
        self.assertRaises(ValueError, Natural, -1)

    def test_floating_number_is_not_natural(self):
        self.assertRaises(ValueError, Natural, 1.0)

    def test_equality(self):
        # Test Natural==Natural and Natural==int
        a, b, c = Naturals(89, 89, 90)
        self.failUnless(a == b)
        self.failUnless(a == 89)
        self.failIf(a == c)
        self.failIf(a == 90)

    def test_inequality(self):
        # Test Natural!=Natural and Natural!=int
        a, b, c = Naturals(89, 89, 90)
        self.failUnless(a != c)
        self.failUnless(a != 90)
        self.failIf(a != b)
        self.failIf(a != 89)

    def test_less_than(self):
        # Test Natural<Natural and Natural<int
        a, b, c = Naturals(13, 13, 14)
        self.failUnless(a < c)
        self.failUnless(a < 14)
        self.failIf(a < b)
        self.failIf(a < 13)

    def test_addition(self):
        # Test Natural+Natural and Natural+int
        a, b = Naturals(7, 90)
        self.assertEqual(a + b, 97)
        self.assertEqual(a + 90, 97)
        self.assertEqual(a + (-7), 0)
        self.assertRaises(ValueError, lambda: a + (-8))

    def test_subtraction(self):
        # Test Natural-Natural and Natural-int
        a, b = Naturals(7, 90)
        self.assertEqual(b - a, 83)
        self.assertEqual(b - 7, 83)
        self.assertEqual(b - (-7), 97)
        self.assertRaises(ValueError, lambda: a - b)
        self.assertRaises(ValueError, lambda: a - 90)

    def test_remainder(self):
        # Test Natural%Natural and Natural%int
        a, b = Naturals(23, 5)
        self.assertEqual(a % b, 3)
        self.assertEqual(a % 5, 3)
        self.assertRaises(ZeroDivisionError, lambda: a % 0)

    def test_power(self):
        # Test Natural**Natural, Natural**int and int**Natural
        a, b = Naturals(3, 4)
        self.assertEqual(a ** b, 81)
        self.assertEqual(a ** 4, 81)
        self.assertEqual(3 ** b, 81)
        self.assertRaises(ValueError, lambda: a ** -1)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestNatural)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
