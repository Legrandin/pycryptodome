# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/MD4.py: Self-test for the MD4 hash function
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

"""Self-test suite for Crypto.Hash.MD4"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # Test vectors from RFC 1320
    ('31d6cfe0d16ae931b73c59d7e0c089c0', '', "'' (empty string)"),
    ('bde52cb31de33e46245e05fbdbd6fb24', 'a'),
    ('a448017aaf21d8525fc10ae87aa6729d', 'abc'),
    ('d9130a8164549fe818874806e1c7014b', 'message digest'),

    ('d79e1c308aa5bbcdeea8ed63df412da9', 'abcdefghijklmnopqrstuvwxyz',
        'a-z'),

    ('043f8582f241db351ce627e153e7f0e4',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        'A-Z, a-z, 0-9'),

    ('e33b4ddc9c38f2199c3e7b164fcc0536',
        '1234567890123456789012345678901234567890123456'
        + '7890123456789012345678901234567890',
        "'1234567890' * 8"),
]

def get_tests():
    from Crypto.Hash import MD4
    from common import make_hash_tests
    return make_hash_tests(MD4, "MD4", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
