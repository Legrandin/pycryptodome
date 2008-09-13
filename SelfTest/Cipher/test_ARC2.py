# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/ARC2.py: Self-test for the Alleged-RC2 cipher
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

"""Self-test suite for Crypto.Cipher.ARC2"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key[, description]) tuples.
test_data = [
    # Test vectors from RFC 2268

    # 63-bit effective key length
#    ('0000000000000000', 'ebb773f993278eff', '0000000000000000', "RFC2268-1"),

    # 64-bit effective key length
    ('ffffffffffffffff', '278b27e42e2f0d49', 'ffffffffffffffff', "RFC2268-2"),
    ('1000000000000001', '30649edf9be7d2c2', '3000000000000000', "RFC2268-3"),
    ('0000000000000000', '61a8a244adacccf0', '88',               "RFC2268-4"),
    ('0000000000000000', '6ccf4308974c267f', '88bca90e90875a',   "RFC2268-5"),
    ('0000000000000000', '1a807d272bbe5db1',
        '88bca90e90875a7f0f79c384627bafb2', "RFC2268-6"),

    # 128-bit effective key length
    ('0000000000000000', '2269552ab0f85ca6',
        '88bca90e90875a7f0f79c384627bafb2', "RFC2268-7"),
    ('0000000000000000', '5b78d3a43dfff1f1',
        '88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e',
        "RFC2268-8"),
]

def make_testsuite():
    from Crypto.Cipher import ARC2
    from common import make_block_testsuite
    return make_block_testsuite(ARC2, "ARC2", test_data)

if __name__ == '__main__':
    import unittest
    unittest.main(defaultTest='make_testsuite')

# vim:set ts=4 sw=4 sts=4 expandtab:
