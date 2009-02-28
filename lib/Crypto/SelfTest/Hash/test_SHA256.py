# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/SHA256.py: Self-test for the SHA-256 hash function
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
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHA256LL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================
#

"""Self-test suite for Crypto.Hash.SHA256"""

__revision__ = "$Id$"

import unittest

class LargeSHA256Test(unittest.TestCase):
    def runTest(self):
        """SHA256: 512/520 MiB test"""
        from Crypto.Hash import SHA256
        zeros = '\0' * (1024*1024)

        h = SHA256.new(zeros)
        for i in xrange(511):
            h.update(zeros)

        # This test vector is from PyCrypto's old testdata.py file.
        self.assertEqual('9acca8e8c22201155389f65abbf6bc9723edc7384ead80503839f49dcc56d767', h.hexdigest()) # 512 MiB

        for i in xrange(8):
            h.update(zeros)

        # This test vector is from PyCrypto's old testdata.py file.
        self.assertEqual('abf51ad954b246009dfe5a50ecd582fd5b8f1b8b27f30393853c3ef721e7fa6e', h.hexdigest()) # 520 MiB

def get_tests(config={}):
    # Test vectors from FIPS PUB 180-2
    # This is a list of (expected_result, input[, description]) tuples.
    test_data = [
        # FIPS PUB 180-2, B.1 - "One-Block Message"
        ('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
            'abc'),

        # FIPS PUB 180-2, B.2 - "Multi-Block Message"
        ('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
            'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),

        # FIPS PUB 180-2, B.3 - "Long Message"
        ('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
            'a' * 10**6,
             '"a" * 10**6'),

        # Test for an old PyCrypto bug.
        ('f7fd017a3c721ce7ff03f3552c0813adcc48b7f33f07e5e2ba71e23ea393d103',
            'This message is precisely 55 bytes long, to test a bug.',
            'Length = 55 (mod 64)'),
    ]

    from Crypto.Hash import SHA256
    from common import make_hash_tests
    tests = make_hash_tests(SHA256, "SHA256", test_data)

    if config.get('slow_tests'):
        tests += [LargeSHA256Test()]

    return tests

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
