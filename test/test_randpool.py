#
# Test script for Crypto.Util.randpool.
#

__revision__ = "$Id: test_randpool.py,v 1.3 2003-02-28 15:24:01 akuchling Exp $"

import unittest
from Crypto.Hash import SHA
from Crypto.Util import randpool

class RandomPoolTest (unittest.TestCase):

    def setUp (self):
        self.pool = randpool.RandomPool(160, hash=SHA)

    def tearDown (self):
        del self.pool

    def test_init (self):
        "Check initial state"
        self.assertEquals(self.pool.entropy, self.pool.bits)

    def test_get_bytes (self):
        "Check retrieving of bytes from the pool"
        start_entropy = self.pool.entropy
        self.assert_(self.pool.entropy > 0)

        # Draw out half of the pool's entropy
        size = self.pool.entropy / 8 / 2
        self.pool.get_bytes(size)
        self.assertEquals(self.pool.entropy, start_entropy - size*8)

        # Draw out the rest of the pool's entropy
        self.pool.get_bytes(size)
        self.assertEquals(self.pool.entropy, 0)

        # Remove yet more data; entropy stays at zero
        self.pool.get_bytes(size)
        self.assertEquals(self.pool.entropy, 0)

# class RandomPoolTest


if __name__ == "__main__":
    unittest.main()
