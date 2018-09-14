#
#  SelfTest/Hash/test_Poly1305.py: Self-test for the Poly1305 module
#
# ===================================================================
#
# Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
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

"""Self-test suite for Crypto.Hash._Poly1305"""

import json
import unittest

from Crypto.Util.py3compat import tobytes, _memoryview, unhexlify, hexlify

from Crypto.Hash import _Poly1305

test_data = [
    (
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        hexlify(b"Cryptographic Forum Research Group").decode(),
        "a8061dc1305136c6c22b8baf0c0127a9",
        "RFC7539",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "49ec78090e481ec6c26b33b91ccc0307",
        "https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7 A",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "48656c6c6f20776f726c6421",
        "a6f745008f81c916a20dcc74eef2b2f0",
        "https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7 B",
        {}
    ),
]


def get_tests(config={}):

    from common import make_mac_tests
    tests = make_mac_tests(_Poly1305, "Poly1305", test_data)
    return tests


if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
