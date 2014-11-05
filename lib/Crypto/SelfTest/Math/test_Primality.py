#
#  SelfTest/Math/test_Primality.py: Self-test for Primality module
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

from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import (
        PROBABLY_PRIME, COMPOSITE,
        miller_rabin_test, lucas_test,
        )


class TestPrimality(unittest.TestCase):

    primes = (13, 17, 19, 23, 2**127-1,)
    composites = (12, 7*23, (2**19-1)*(2**67-1), 9746347772161,)

    def test_miller_rabin(self):
        for prime in self.primes:
            self.assertEqual(miller_rabin_test(prime, 3), PROBABLY_PRIME)
        for composite in self.composites:
            self.assertEqual(miller_rabin_test(composite, 3), COMPOSITE)

    def test_lucas(self):
        for prime in self.primes:
            self.assertEqual(lucas_test(prime), PROBABLY_PRIME)
        for composite in self.composites:
            self.assertEqual(lucas_test(composite), COMPOSITE)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestPrimality)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
