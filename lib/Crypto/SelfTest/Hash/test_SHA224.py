# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/SHA.py: Self-test for the SHA-1 hash function
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

"""Self-test suite for Crypto.Hash.SHA224"""

__revision__ = "$Id$"

# Test vectors from various sources
# This is a list of (expected_result, input[, description]) tuples.
test_data = [

    # RFC 3874: Section 3.1, "Test Vector #1
    ('23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7', 'abc'),

    # RFC 3874: Section 3.2, "Test Vector #2
    ('75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),

    # RFC 3874: Section 3.3, "Test Vector #3
    ('20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67', 'a' * 10**6, "'a' * 10**6"),

]

def get_tests(config={}):
    from Crypto.Hash import SHA224
    from common import make_hash_tests
    return make_hash_tests(SHA224, "SHA224", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
