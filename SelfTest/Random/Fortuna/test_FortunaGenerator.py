# -*- coding: utf-8 -*-
#
#  SelfTest/Random/Fortuna/test_FortunaGenerator.py: Self-test for the FortunaGenerator module
#
# =======================================================================
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================
#

"""Self-tests for Crypto.Random.Fortuna.FortunaGenerator"""

__revision__ = "$Id$"

from Crypto.Util.python_compat import *

import unittest
from binascii import b2a_hex

class FortunaGeneratorTests(unittest.TestCase):
    def setUp(self):
        global FortunaGenerator
        from Crypto.Random.Fortuna import FortunaGenerator

    def test_encode_counter(self):
        """FortunaGenerator.encode_counter"""
        # should raise TypeError when passed non-integer types
        self.assertRaises(TypeError, FortunaGenerator.encode_counter, "1", 16)
        self.assertRaises(TypeError, FortunaGenerator.encode_counter, "1", "16")
        self.assertRaises(TypeError, FortunaGenerator.encode_counter, 1, "16")

        # Fortuna's counter must be positive, or else encode_counter should return some error
        self.assertRaises((ValueError, AssertionError), FortunaGenerator.encode_counter, -1, 16)
        self.assertRaises((ValueError, AssertionError), FortunaGenerator.encode_counter, 0, 16)

        # size == 0 should return some error
        self.assertRaises((OverflowError, AssertionError, ValueError), FortunaGenerator.encode_counter, 1, 0)
        self.assertRaises((OverflowError, AssertionError, ValueError), FortunaGenerator.encode_counter, 0, 0)

        # should raise OverflowError if we try to represent a number that is too big
        self.assertRaises(OverflowError, FortunaGenerator.encode_counter, 256, 1)
        self.assertRaises(OverflowError, FortunaGenerator.encode_counter, 2L**128, 16)

        # Fortuna uses a little-endian counter
        self.assertEqual("\x01", FortunaGenerator.encode_counter(1, 1))
        self.assertEqual("\x01" + "\x00" * 15, FortunaGenerator.encode_counter(1, 16))
        self.assertEqual("\x02" + "\x00" * 15, FortunaGenerator.encode_counter(2, 16))
        self.assertEqual("\xff\xff\xff\xff", FortunaGenerator.encode_counter(0xFFFFffffL, 4))
        self.assertEqual("\xfe\xff\xff\xff", FortunaGenerator.encode_counter(0xFFFFfffeL, 4))
        self.assertEqual("\xef\xbe\xad\xde", FortunaGenerator.encode_counter(0xDEADBEEFL, 4))

        # Big numbers: 128 bits
        self.assertEqual("c477a2b1db6678b7eac97f08a9723e3c",
            b2a_hex(FortunaGenerator.encode_counter(0x3c3e72a9087fc9eab77866dbb1a277c4L, 16)))
        self.assertEqual("ad2808ef90e2f716dd935eeb4f42008b",
            b2a_hex(FortunaGenerator.encode_counter(0x8b00424feb5e93dd16f7e290ef0828adL, 16)))
        self.assertEqual("4049081397803a90df767c2b25f34059",
            b2a_hex(FortunaGenerator.encode_counter(0x5940f3252b7c76df903a809713084940L, 16)))

        # Big number: 256 bits
        self.assertEqual('98014eb6d8e53710e8c1cc0217b56db450912d6e063e44cede54aa5f4cc6fd5c',
            b2a_hex(FortunaGenerator.encode_counter(0x5cfdc64c5faa54dece443e066e2d9150b46db51702ccc1e81037e5d8b64e0198L, 32)))
        self.assertEqual('0663c68fac53f2a308af47374aa4ccd4a703c0e803b7714ed78f583a039905bb',
            b2a_hex(FortunaGenerator.encode_counter(0xbb0599033a588fd74e71b703e8c003a7d4cca44a3747af08a3f253ac8fc66306L, 32)))

def get_tests():
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaGeneratorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
