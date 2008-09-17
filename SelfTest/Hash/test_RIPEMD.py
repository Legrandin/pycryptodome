# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/test_RIPEMD.py: Self-test for the RIPEMD-160 hash function
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

#"""Self-test suite for Crypto.Hash.RIPEMD"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # Test vectors downloaded 2008-09-12 from
    #   http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    ('9c1185a5c5e9fc54612808977ee8f548b2258d31', '', "'' (empty string)"),
    ('0bdc9d2d256b3ee9daae347be6f4dc835a467ffe', 'a'),
    ('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc', 'abc'),
    ('5d0689ef49d2fae572b881b123a85ffa21595f36', 'message digest'),

    ('f71c27109c692c1b56bbdceb5b9d2865b3708dbc',
        'abcdefghijklmnopqrstuvwxyz',
        'a-z'),

    ('12a053384a9c0c88e405a06c27dcf49ada62eb2b',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        'abcdbcd...pnopq'),

    ('b0e20b6e3116640286ed3a87a5713079b21f5189',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        'A-Z, a-z, 0-9'),

    ('9b752e45573d4b39f4dbd3323cab82bf63326bfb',
        '1234567890' * 8,
        "'1234567890' * 8"),

    ('52783243c1697bdbe16d37f97f68f08325dc1528',
        'a' * 10**6,
        '"a" * 10**6'),
]

def get_tests():
    from Crypto.Hash import RIPEMD
    from common import make_hash_tests
    return make_hash_tests(RIPEMD, "RIPEMD", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
