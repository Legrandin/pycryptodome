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

    def test_accumulator(self):
        """FortunaAccumulator.FortunaAccumulator"""
        fa = FortunaAccumulator.FortunaAccumulator()

        # This should fail, because we haven't seeded the PRNG yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Spread some test data across the pools (source number 42)
        # This would be horribly insecure in a real system.
        for p in range(32):
            fa.add_random_event(42, p, "X" * 32)
            self.assertEqual(32+2, fa.pools[p].length)

        # This should still fail, because we haven't seeded the PRNG with 64 bytes yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Add more data
        for p in range(32):
            fa.add_random_event(42, p, "X" * 32)
            self.assertEqual((32+2)*2, fa.pools[p].length)

        # The underlying RandomGenerator should get seeded with Pool 0
        #   s = SHAd256(chr(42) + chr(32) + "X"*32 + chr(42) + chr(32) + "X"*32)
        #     = SHA256(h'edd546f057b389155a31c32e3975e736c1dec030ddebb137014ecbfb32ed8c6f')
        #     = h'aef42a5dcbddab67e8efa118e1b47fde5d697f89beb971b99e6e8e5e89fbf064'
        # The counter and the key before reseeding is:
        #   C_0 = 0
        #   K_0 = "\x00" * 32
        # The counter after reseeding is 1, and the new key after reseeding is
        #   C_1 = 1
        #   K_1 = SHAd256(K_0 || s)
        #       = SHA256(h'0eae3e401389fab86640327ac919ecfcb067359d95469e18995ca889abc119a6')
        #       = h'aafe9d0409fbaaafeb0a1f2ef2014a20953349d3c1c6e6e3b962953bea6184dd'
        # The first block of random data, therefore, is
        #   r_1 = AES-256(K_1, 1)
        #       = AES-256(K_1, h'01000000000000000000000000000000')
        #       = h'b7b86bd9a27d96d7bb4add1b6b10d157'
        # The second block of random data is
        #   r_2 = AES-256(K_1, 2)
        #       = AES-256(K_1, h'02000000000000000000000000000000')
        #       = h'2350b1c61253db2f8da233be726dc15f'
        # The third and fourth blocks of random data (which become the new key) are
        #   r_3 = AES-256(K_1, 3)
        #       = AES-256(K_1, h'03000000000000000000000000000000')
        #       = h'f23ad749f33066ff53d307914fbf5b21'
        #   r_4 = AES-256(K_1, 4)
        #       = AES-256(K_1, h'04000000000000000000000000000000')
        #       = h'da9667c7e86ba247655c9490e9d94a7c'
        #   K_2 = r_3 || r_4
        #       = h'f23ad749f33066ff53d307914fbf5b21da9667c7e86ba247655c9490e9d94a7c'
        # The final counter value is 5.
        self.assertEqual("aef42a5dcbddab67e8efa118e1b47fde5d697f89beb971b99e6e8e5e89fbf064",
            fa.pools[0].hexdigest())
        self.assertEqual("\x00" * 32, fa.generator.key)
        self.assertEqual(0, fa.generator.counter)

        result = fa.random_data(32)

        self.assertEqual("b7b86bd9a27d96d7bb4add1b6b10d157" "2350b1c61253db2f8da233be726dc15f", b2a_hex(result))
        self.assertEqual("f23ad749f33066ff53d307914fbf5b21da9667c7e86ba247655c9490e9d94a7c", b2a_hex(fa.generator.key))
        self.assertEqual(5, fa.generator.counter)

    def test_accumulator_pool_length(self):
        """FortunaAccumulator.FortunaAccumulator minimum pool length"""
        fa = FortunaAccumulator.FortunaAccumulator()

        # This test case is hard-coded to assume that FortunaAccumulator.min_pool_size is 64.
        self.assertEqual(fa.min_pool_size, 64)

        # The PRNG should not allow us to get random data from it yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Add 60 bytes, 4 at a time (2 header + 2 payload) to each of the 32 pools
        for i in range(15):
            for p in range(32):
                # Add the bytes to the pool
                fa.add_random_event(2, p, "XX")

                # The PRNG should not allow us to get random data from it yet
                self.assertRaises(AssertionError, fa.random_data, 1)

        # Add 4 more bytes to pool 0
        fa.add_random_event(2, 0, "XX")

        # We should now be able to get data from the accumulator
        fa.random_data(1)

def get_tests():
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaAccumulatorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
