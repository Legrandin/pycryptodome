# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_224.py: Self-test for the SHA-3/224 hash function
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

"""Self-test suite for Crypto.Hash.SHA3_224"""

from Crypto.SelfTest.Hash.loader import load_tests
from StringIO import StringIO

def get_tests(config={}):
    from Crypto.Hash import SHA3_224
    from common import make_hash_tests

    test_data = load_tests("ShortMsgKAT_SHA3-224.txt")
    return make_hash_tests(SHA3_224, "SHA3_224", test_data,
        digest_size=SHA3_224.digest_size,
        oid="2.16.840.1.101.3.4.2.7")

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
