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

    def test_generator(self):
        """FortunaGenerator.AESGenerator"""
        fg = FortunaGenerator.AESGenerator()

        # We shouldn't be able to read data until we've seeded the generator
        self.assertRaises(Exception, fg.pseudo_random_data, 1)
        self.assertEqual(0, fg.counter.next_value())

        # Seed the generator, which should set the key and increment the counter.
        fg.reseed("Hello")
        self.assertEqual("0ea6919d4361551364242a4ba890f8f073676e82cf1a52bb880f7e496648b565", b2a_hex(fg.key))
        self.assertEqual(1, fg.counter.next_value())

        # Read 2 full blocks from the generator
        self.assertEqual("7cbe2c17684ac223d08969ee8b565616" +       # counter=1
                         "717661c0d2f4758bd6ba140bf3791abd",        # counter=2
            b2a_hex(fg.pseudo_random_data(32)))

        # Meanwhile, the generator will have re-keyed itself and incremented its counter
        self.assertEqual("33a1bb21987859caf2bbfc5615bef56d" +       # counter=3
                         "e6b71ff9f37112d0c193a135160862b7",        # counter=4
            b2a_hex(fg.key))
        self.assertEqual(5, fg.counter.next_value())

        # Read another 2 blocks from the generator
        self.assertEqual("fd6648ba3086e919cee34904ef09a7ff" +       # counter=5
                         "021f77580558b8c3e9248275f23042bf",        # counter=6
            b2a_hex(fg.pseudo_random_data(32)))


        # Try to read more than 2**20 bytes using the internal function.  This should fail.
        self.assertRaises(AssertionError, fg._pseudo_random_data, 2**20+1)

def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaGeneratorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
