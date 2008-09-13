# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/ARC4.py: Self-test for the Alleged-RC4 cipher
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

"""Self-test suite for Crypto.Cipher.ARC4"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key[, description]) tuples.
test_data = [
    # Test vectors from Eric Rescorla's message with the subject
    # "RC4 compatibility testing", sent to the cipherpunks mailing list on
    # September 13, 1994.
    # http://cypherpunks.venona.com/date/1994/09/msg00420.html

    ('0123456789abcdef', '75b7878099e0c596', '0123456789abcdef',
        'Test vector 0'),

    ('0000000000000000', '7494c2e7104b0879', '0123456789abcdef',
        'Test vector 1'),

    ('0000000000000000', 'de188941a3375d3a', '0000000000000000',
        'Test vector 2'),

    ('00000000000000000000', 'd6a141a7ec3c38dfbd61', 'ef012345',
        'Test vector 3'),

    ('01' * 512,
        '7595c3e6114a09780c4ad452338e1ffd9a1be9498f813d76533449b6778dcad8'
        + 'c78a8d2ba9ac66085d0e53d59c26c2d1c490c1ebbe0ce66d1b6b1b13b6b919b8'
        + '47c25a91447a95e75e4ef16779cde8bf0a95850e32af9689444fd377108f98fd'
        + 'cbd4e726567500990bcc7e0ca3c4aaa304a387d20f3b8fbbcd42a1bd311d7a43'
        + '03dda5ab078896ae80c18b0af66dff319616eb784e495ad2ce90d7f772a81747'
        + 'b65f62093b1e0db9e5ba532fafec47508323e671327df9444432cb7367cec82f'
        + '5d44c0d00b67d650a075cd4b70dedd77eb9b10231b6b5b741347396d62897421'
        + 'd43df9b42e446e358e9c11a9b2184ecbef0cd8e7a877ef968f1390ec9b3d35a5'
        + '585cb009290e2fcde7b5ec66d9084be44055a619d9dd7fc3166f9487f7cb2729'
        + '12426445998514c15d53a18c864ce3a2b7555793988126520eacf2e3066e230c'
        + '91bee4dd5304f5fd0405b35bd99c73135d3d9bc335ee049ef69b3867bf2d7bd1'
        + 'eaa595d8bfc0066ff8d31509eb0c6caa006c807a623ef84c3d33c195d23ee320'
        + 'c40de0558157c822d4b8c569d849aed59d4e0fd7f379586b4b7ff684ed6a189f'
        + '7486d49b9c4bad9ba24b96abf924372c8a8fffb10d55354900a77a3db5f205e1'
        + 'b99fcd8660863a159ad4abe40fa48934163ddde542a6585540fd683cbfd8c00f'
        + '12129a284deacc4cdefe58be7137541c047126c8d49e2755ab181ab7e940b0c0',
        '0123456789abcdef',
        "Test vector 4"),
]

def make_testsuite():
    from Crypto.Cipher import ARC4
    from common import make_stream_testsuite
    return make_stream_testsuite(ARC4, "ARC4", test_data)

if __name__ == '__main__':
    import unittest
    unittest.main(defaultTest='make_testsuite')

# vim:set ts=4 sw=4 sts=4 expandtab:
