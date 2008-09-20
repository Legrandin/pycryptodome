# -*- coding: utf-8 -*-
#
#  SelfTest/Random/Fortuna/test_FortunaAccumulator.py: Self-test for the FortunaAccumulator module
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

"""Self-tests for Crypto.Random.Fortuna.FortunaAccumulator"""

__revision__ = "$Id$"

from Crypto.Util.python_compat import *

import unittest
from binascii import b2a_hex

class FortunaAccumulatorTests(unittest.TestCase):
    def setUp(self):
        global FortunaAccumulator
        from Crypto.Random.Fortuna import FortunaAccumulator

    def test_FortunaPool(self):
        """FortunaAccumulator.FortunaPool"""
        pool = FortunaAccumulator.FortunaPool()
        self.assertEqual(0, pool.length)
        self.assertEqual("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456", pool.hexdigest())

        pool.append("abc")

        self.assertEqual(3, pool.length)
        self.assertEqual("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358", pool.hexdigest())

        pool.append("dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

        self.assertEqual(56, pool.length)
        self.assertEqual("0cffe17f68954dac3a84fb1458bd5ec99209449749b2b308b7cb55812f9563af", b2a_hex(pool.digest()))

        pool.reset()

        self.assertEqual(0, pool.length)

        pool.append("a" * 10**6)

        self.assertEqual(10**6, pool.length)
        self.assertEqual("80d1189477563e1b5206b2749f1afe4807e5705e8bd77887a60187a712156688", b2a_hex(pool.digest()))

    def test_which_pools(self):
        """FortunaAccumulator.which_pools"""

        # which_pools(0) should fail
        self.assertRaises(AssertionError, FortunaAccumulator.which_pools, 0)

        self.assertEqual(FortunaAccumulator.which_pools(1), [0])
        self.assertEqual(FortunaAccumulator.which_pools(2), [0, 1])
        self.assertEqual(FortunaAccumulator.which_pools(3), [0])
        self.assertEqual(FortunaAccumulator.which_pools(4), [0, 1, 2])
        self.assertEqual(FortunaAccumulator.which_pools(5), [0])
        self.assertEqual(FortunaAccumulator.which_pools(6), [0, 1])
        self.assertEqual(FortunaAccumulator.which_pools(7), [0])
        self.assertEqual(FortunaAccumulator.which_pools(8), [0, 1, 2, 3])
        for i in range(1, 32):
            self.assertEqual(FortunaAccumulator.which_pools(2L**i-1), [0])
            self.assertEqual(FortunaAccumulator.which_pools(2L**i), range(i+1))
            self.assertEqual(FortunaAccumulator.which_pools(2L**i+1), [0])
        self.assertEqual(FortunaAccumulator.which_pools(2L**31), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**32), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**33), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**34), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**35), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**36), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**64), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**128), range(32))

def get_tests():
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaAccumulatorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
