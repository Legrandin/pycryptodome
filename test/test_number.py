#
# Test script for Crypto.Util.number.
#

__revision__ = "$Id: test_number.py,v 1.4 2003/04/04 18:21:35 akuchling Exp $"

from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.Util import number

tested_modules = [ "Crypto.Util.number" ]

class NumberTest (TestScenario):

    def setup (self):
        pass

    def shutdown (self):
        pass

    def check_getRandomNumber (self):
        "Check generation of N-bit random numbers"
        def f(N):
            return '\xff' * N

        self.test_val('number.getRandomNumber(1, f)', 1)
        self.test_val('number.getRandomNumber(4, f)', 15)
        self.test_val('number.getRandomNumber(8, f)', 255)
        self.test_val('number.getRandomNumber(12, f)', 4095)
        self.test_val('number.getRandomNumber(16, f)', 65535)

    def check_GCD (self):
        "Check GCD computation"
        self.test_val('number.GCD(1, 5)', 1)
        self.test_val('number.GCD(2, 6)', 2)
        self.test_val('number.GCD(16, 12)', 4)

    def check_inverse (self):
        "Check computation of inverses"
        self.test_val('number.inverse(9, 10)', 9)
        self.test_val('number.inverse(1, 2)', 1)
        self.test_val('number.inverse(529, 10502)', 3097)

    def check_getPrime (self):
        "Check generation of primes"
        def f(n):
            return '\xff' * n
        self.test_val('number.getPrime(1, f)', 3)
        self.test_val('number.getPrime(2, f)', 3)
        self.test_val('number.getPrime(8, f)', 257)
        self.test_val('number.getPrime(75, f)', 37778931862957161709601L)

    def check_isPrime (self):
        "Check verification of primes"
        self.test_bool('number.isPrime(1)', want_true=0)
        self.test_bool('number.isPrime(2)')
        self.test_bool('number.isPrime(3)')
        self.test_bool('number.isPrime(4)', want_true=0)
        self.test_bool('number.isPrime(37778931862957161709601L)')
        self.test_bool('number.isPrime(37778931862957161709603L)',
                       want_true=0)

    def check_longbytes (self):
        "Check conversion between bytes and integers"
        self.test_val('number.long_to_bytes(1)', '\x01')
        self.test_val('number.long_to_bytes(1, 2)', '\x00\x01')
        self.test_val('number.long_to_bytes(511)', '\x01\xff')

        self.test_val('number.bytes_to_long("\x01")', 1)
        self.test_val('number.bytes_to_long("\xff\x01")', 0xff01)
        self.test_val('number.bytes_to_long("\x12\x34\x01")', 0x123401)

    def check_size (self):
        "Check measurement of number sizes"
        self.test_val('number.size(1)', 1)
        self.test_val('number.size(15)', 4)
        self.test_val('number.size(255)', 8)
        self.test_val('number.size(256)', 9)


# class NumberTest


if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
