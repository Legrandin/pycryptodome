# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/SHA.py: Self-test for the SHA-1 hash function
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

"""Self-test suite for Crypto.Hash.SHA"""

__revision__ = "$Id$"

# Test vectors from various sources
# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # FIPS PUB 180-2, A.1 - "One-Block Message"
    ('a9993e364706816aba3e25717850c26c9cd0d89d', 'abc'),

    # FIPS PUB 180-2, A.2 - "Multi-Block Message"
    ('84983e441c3bd26ebaae4aa1f95129e5e54670f1',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),

    # FIPS PUB 180-2, A.3 - "Long Message"
#    ('34aa973cd4c4daa4f61eeb2bdbad27316534016f',
#        'a' * 10**6,
#         '"a" * 10**6'),

    # RFC 3174: Section 7.3, "TEST4" (multiple of 512 bits)
    ('dea356a2cddd90c7a7ecedc5ebb563934f460452',
        "01234567" * 80,
        '"01234567" * 80'),
]

def get_tests(config={}):
    from Crypto.Hash import SHA
    from common import make_hash_tests
    return make_hash_tests(SHA, "SHA", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
