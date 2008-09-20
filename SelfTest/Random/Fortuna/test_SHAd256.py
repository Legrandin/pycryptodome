# -*- coding: utf-8 -*-
#
#  SelfTest/Random/Fortuna/test_SHAd256.py: Self-test for the SHAd256 hash function
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

"""Self-test suite for Crypto.Random.Fortuna.SHAd256"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # I could not find any test vectors for SHAd256, so I made these vectors by
    # feeding some sample data into several plain SHA256 implementations
    # (including OpenSSL, the "sha256sum" tool, and this implementation).
    # This is a subset of the resulting test vectors.  The complete list can be
    # found at: http://www.dlitz.net/crypto/shad256-test-vectors/
    ('5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456',
        '', "'' (empty string)"),
    ('4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358',
        'abc'),
    ('0cffe17f68954dac3a84fb1458bd5ec99209449749b2b308b7cb55812f9563af',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
]

def get_tests():
    from Crypto.Random.Fortuna import SHAd256
    from Crypto.SelfTest.Hash.common import make_hash_tests
    return make_hash_tests(SHAd256, "SHAd256", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
