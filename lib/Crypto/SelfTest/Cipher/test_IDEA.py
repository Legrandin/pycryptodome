# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/IDEA.py: Self-test for the IDEA cipher
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

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

def get_tests(config={}):
    from Crypto.Cipher import IDEA
    from common import make_block_tests
    return make_block_tests(IDEA, "IDEA", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
