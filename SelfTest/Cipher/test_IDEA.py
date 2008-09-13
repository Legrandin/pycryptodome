# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/IDEA.py: Self-test for the IDEA cipher
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

"""Self-test suite for Crypto.Cipher.IDEA"""

__revision__ = "$Id$"

# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from
    # http://web.archive.org/web/20001006183113/http://www.it-sec.com/pdffiles/testdata.zip

    # Test_Cases_IDEA.txt
    ('d53fabbf94ff8b5f', '1d0cb2af1654820a', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('848f836780938169', 'd7e0468226d0fc56', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('819440ca2065d112', '264a8bba66959075', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('6889f5647ab23d59', 'f963468b52f45d4d', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('df8c6fc637e3dad1', '29358cc6c83828ae', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('ac4856242b121589', '95cd92f44bacb72d', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('cbe465f232f9d85c', 'bce24dc8d0961c44', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('6c2e3617da2bac35', '1569e0627007b12e', '729a27ed8f5c3e8baf16560d14c90b43'),

    # NewTestCases.txt
    ('d53fabbf94ff8b5f', '1320f99bfe052804', '000027ed8f5c3e8baf16560d14c90b43'),
    ('848f836780938169', '4821b99f61acebb7', '000027ed8f5c3e8baf16560d14c90b43'),
    ('819440ca2065d112', 'c88600093b348575', '000027ed8f5c3e8baf16560d14c90b43'),
    ('6889f5647ab23d59', '61d5397046f99637', '000027ed8f5c3e8baf16560d14c90b43'),
    ('df8c6fc637e3dad1', 'ef4899b48de5907c', '000027ed8f5c3e8baf16560d14c90b43'),
    ('ac4856242b121589', '85c6b232294c2f27', '000027ed8f5c3e8baf16560d14c90b43'),
    ('cbe465f232f9d85c', 'b67ac767c0c06a55', '000027ed8f5c3e8baf16560d14c90b43'),
    ('6c2e3617da2bac35', 'b2229067630f7045', '000027ed8f5c3e8baf16560d14c90b43'),

    ('0000abbf94ff8b5f', '65861be574e1eab6', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('848f836780938169', 'd7e0468226d0fc56', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('819440ca2065d112', '264a8bba66959075', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('6889f5647ab23d59', 'f963468b52f45d4d', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('df8c6fc637e3dad1', '29358cc6c83828ae', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('ac4856242b121589', '95cd92f44bacb72d', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('cbe465f232f9d85c', 'bce24dc8d0961c44', '729a27ed8f5c3e8baf16560d14c90b43'),
    ('6c2e3617da2bac35', '1569e0627007b12e', '729a27ed8f5c3e8baf16560d14c90b43'),

    ('0000abbf94ff8b5f', 'cbbb2e6c05ee8c89', '000027ed8f5c3e8baf16560d14c90b43'),
    ('848f836780938169', '4821b99f61acebb7', '000027ed8f5c3e8baf16560d14c90b43'),
    ('819440ca2065d112', 'c88600093b348575', '000027ed8f5c3e8baf16560d14c90b43'),
    ('6889f5647ab23d59', '61d5397046f99637', '000027ed8f5c3e8baf16560d14c90b43'),
    ('df8c6fc637e3dad1', 'ef4899b48de5907c', '000027ed8f5c3e8baf16560d14c90b43'),
    ('ac4856242b121589', '85c6b232294c2f27', '000027ed8f5c3e8baf16560d14c90b43'),
    ('cbe465f232f9d85c', 'b67ac767c0c06a55', '000027ed8f5c3e8baf16560d14c90b43'),
    ('6c2e3617da2bac35', 'b2229067630f7045', '000027ed8f5c3e8baf16560d14c90b43'),
]

def make_testsuite():
    from Crypto.Cipher import IDEA
    from common import make_block_testsuite
    return make_block_testsuite(IDEA, "IDEA", test_data)

if __name__ == '__main__':
    import unittest
    unittest.main(defaultTest='make_testsuite')

# vim:set ts=4 sw=4 sts=4 expandtab:
