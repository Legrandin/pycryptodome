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

from Crypto.Util.py3compat import *

def Naturals(*arg):
    return map(Natural, arg)

class TestNatural(unittest.TestCase):

    def test_init_and_equality(self):
        a = Natural(23)
        d = Natural(a)
        self.assertRaises(ValueError, Natural, 1.0)
        self.assertRaises(ValueError, Natural, -1)

        c = Natural(10)
        self.failUnless(a == a)
        self.failUnless(a == d)
        self.failIf(a == c)

    def test_conversion_to_bytes(self):
        a = Natural(0x17)
        self.assertEqual(b("\x17"), a.to_bytes())

        c = Natural(0xFFFF)
        self.assertEqual(b("\xFF\xFF"), c.to_bytes())
        self.assertEqual(b("\x00\xFF\xFF"), c.to_bytes(3))
        self.assertRaises(ValueError, c.to_bytes, 1)

    def test_conversion_to_int(self):
        a = Natural(23)
        self.assertEqual(int(a), 23)

        f = Natural(2**1000)
        self.assertEqual(int(f), 2**1000)

    def test_equality_with_ints(self):
        a = Natural(23)
        self.failUnless(a == 23)
        self.failIf(a == 24)

    def test_conversion_from_bytes(self):
        a = Natural.from_bytes(b("\x00"))
        self.assertEqual(0, a)

        a = Natural.from_bytes(b("\x00\x00"))
        self.assertEqual(0, a)

        c = Natural.from_bytes(b("\xFF\xFF"))
        self.assertEqual(0xFFFF, c)

    def test_inequality(self):
        # Test Natural!=Natural and Natural!=int
        a, d, c = Naturals(89, 89, 90)
        self.failUnless(a != c)
        self.failUnless(a != 90)
        self.failIf(a != d)
        self.failIf(a != 89)

    def test_less_than(self):
        # Test Natural<Natural and Natural<int
        a, d, c = Naturals(13, 13, 14)
        self.failUnless(a < c)
        self.failUnless(a < 14)
        self.failIf(a < d)
        self.failIf(a < 13)

    def test_addition(self):
        # Test Natural+Natural and Natural+int
        a, d = Naturals(7, 90)
        self.assertEqual(a + d, 97)
        self.assertEqual(a + 90, 97)
        self.assertEqual(a + (-7), 0)
        self.assertRaises(ValueError, lambda: a + (-8))

    def test_subtraction(self):
        # Test Natural-Natural and Natural-int
        a, d = Naturals(7, 90)
        self.assertEqual(d - a, 83)
        self.assertEqual(d - 7, 83)
        self.assertEqual(d - (-7), 97)
        self.assertRaises(ValueError, lambda: a - d)
        self.assertRaises(ValueError, lambda: a - 90)

    def test_remainder(self):
        # Test Natural%Natural and Natural%int
        a, d = Naturals(23, 5)
        self.assertEqual(a % d, 3)
        self.assertEqual(a % 5, 3)
        self.assertRaises(ZeroDivisionError, lambda: a % 0)

    def test_exponentiation(self):
        a, d, e = Naturals(23, 5, 17)

        self.assertEqual(pow(a, d, e), 7)
        self.assertEqual(pow(a, 5, e), 7)
        self.assertEqual(pow(a, d, 17), 7)
        self.assertEqual(pow(a, 5, 17), 7)
        self.assertEqual(pow(a, 0, 17), 1)

        self.assertRaises(ValueError, pow, a, 5, 0)
        self.assertRaises(ValueError, pow, a, 5, -4)
        self.assertRaises(ValueError, pow, a, -3, 8)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestNatural)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
