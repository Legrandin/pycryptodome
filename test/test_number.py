#
# Test script for Crypto.Util.number.
#

__revision__ = "$Id$"

import unittest
from Crypto.Util import number

class NumberTest (unittest.TestCase):

    def test_getRandomNumber (self):
        "Check generation of N-bit random numbers"
        def f(N):
            return '\xff' * N

        self.assertEquals(number.getRandomNumber(1, f), 1)
        self.assertEquals(number.getRandomNumber(4, f), 15)
        self.assertEquals(number.getRandomNumber(8, f), 255)
        self.assertEquals(number.getRandomNumber(12, f), 4095)
        self.assertEquals(number.getRandomNumber(16, f), 65535)

    def test_GCD (self):
        "Check GCD computation"
        self.assertEquals(number.GCD(1, 5), 1)
        self.assertEquals(number.GCD(2, 6), 2)
        self.assertEquals(number.GCD(16, 12), 4)

    def test_inverse (self):
        "Check computation of inverses"
        self.assertEquals(number.inverse(9, 10), 9)
        self.assertEquals(number.inverse(1, 2), 1)
        self.assertEquals(number.inverse(529, 10502), 3097)

    def test_getPrime (self):
        "Check generation of primes"
        def f(n):
            return '\xff' * n
        self.assertEquals(number.getPrime(1, f), 3)
        self.assertEquals(number.getPrime(2, f), 3)
        self.assertEquals(number.getPrime(8, f), 257)
        self.assertEquals(number.getPrime(75, f), 37778931862957161709601L)

    def test_isPrime (self):
        "Check verification of primes"
        self.assertFalse(number.isPrime(1))
        self.assert_(number.isPrime(2))
        self.assert_(number.isPrime(3))
        self.assertFalse(number.isPrime(4))
        self.assert_(number.isPrime(37778931862957161709601L))
        self.assertFalse(number.isPrime(37778931862957161709603L))

    def test_longbytes (self):
        "Check conversion between bytes and integers"
        self.assertEquals(number.long_to_bytes(1), '\x01')
        self.assertEquals(number.long_to_bytes(1, 2), '\x00\x01')
        self.assertEquals(number.long_to_bytes(511), '\x01\xff')

        self.assertEquals(number.bytes_to_long("\x01"), 1)
        self.assertEquals(number.bytes_to_long("\xff\x01"), 0xff01)
        self.assertEquals(number.bytes_to_long("\x12\x34\x01"), 0x123401)

    def test_size (self):
        "Check measurement of number sizes"
        self.assertEquals(number.size(1), 1)
        self.assertEquals(number.size(15), 4)
        self.assertEquals(number.size(255), 8)
        self.assertEquals(number.size(256), 9)


# class NumberTest


if __name__ == "__main__":
    unittest.main()
