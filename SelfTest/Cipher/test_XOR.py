# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/XOR.py: Self-test for the XOR "cipher"
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

"""Self-test suite for Crypto.Cipher.XOR"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors written from scratch.  (Nobody posts XOR test vectors on the web?  How disappointing.)
    ('01', '01',
        '00',
        'zero key'),

    ('0102040810204080', '0003050911214181',
        '01',
        '1-byte key'),

    ('0102040810204080', 'cda8c8a2dc8a8c2a',
        'ccaa',
        '2-byte key'),

    ('ff'*64, 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0'*2,
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '32-byte key'),

    # XOR truncates at 32 bytes.
    ('ff'*64, 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0'*2,
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f55',
        '33-byte key (truncated to 32 bytes)'),
]

def get_tests(config={}):
    from Crypto.Cipher import XOR
    from common import make_stream_tests
    return make_stream_tests(XOR, "XOR", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
