# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/ARC2.py: Self-test for the Alleged-RC2 cipher
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

"""Self-test suite for Crypto.Cipher.ARC2"""

__revision__ = "$Id$"

from common import dict     # For compatibility with Python 2.1 and 2.2

import unittest
from Crypto.Util.py3compat import *

# This is a list of (plaintext, ciphertext, key[, description[, extra_params]]) tuples.
test_data = [
    # Test vectors from RFC 2268

    # 63-bit effective key length
    (b('0000000000000000'), b('ebb773f993278eff'), b('0000000000000000'),
        'RFC2268-1', dict(effective_keylen=63)),

    # 64-bit effective key length
    (b('ffffffffffffffff'), b('278b27e42e2f0d49'), b('ffffffffffffffff'),
        'RFC2268-2', dict(effective_keylen=64)),
    (b('1000000000000001'), b('30649edf9be7d2c2'), b('3000000000000000'),
        'RFC2268-3', dict(effective_keylen=64)),
    (b('0000000000000000'), b('61a8a244adacccf0'), b('88'),
        'RFC2268-4', dict(effective_keylen=64)),
    (b('0000000000000000'), b('6ccf4308974c267f'), b('88bca90e90875a'),
        'RFC2268-5', dict(effective_keylen=64)),
    (b('0000000000000000'), b('1a807d272bbe5db1'), b('88bca90e90875a7f0f79c384627bafb2'),
        'RFC2268-6', dict(effective_keylen=64)),

    # 128-bit effective key length
    (b('0000000000000000'), b('2269552ab0f85ca6'), b('88bca90e90875a7f0f79c384627bafb2'),
        "RFC2268-7", dict(effective_keylen=128)),
    (b('0000000000000000'), b('5b78d3a43dfff1f1'),
        b('88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e'),
        "RFC2268-8", dict(effective_keylen=129)),

    # Test vectors from PyCrypto 2.0.1's testdata.py
    # 1024-bit effective key length
    (b('0000000000000000'), b('624fb3e887419e48'), b('5068696c6970476c617373'),
        'PCTv201-0'),
    (b('ffffffffffffffff'), b('79cadef44c4a5a85'), b('5068696c6970476c617373'),
        'PCTv201-1'),
    (b('0001020304050607'), b('90411525b34e4c2c'), b('5068696c6970476c617373'),
        'PCTv201-2'),
    (b('0011223344556677'), b('078656aaba61cbfb'), b('5068696c6970476c617373'),
        'PCTv201-3'),
    (b('0000000000000000'), b('d7bcc5dbb4d6e56a'), b('ffffffffffffffff'),
        'PCTv201-4'),
    (b('ffffffffffffffff'), b('7259018ec557b357'), b('ffffffffffffffff'),
        'PCTv201-5'),
    (b('0001020304050607'), b('93d20a497f2ccb62'), b('ffffffffffffffff'),
        'PCTv201-6'),
    (b('0011223344556677'), b('cb15a7f819c0014d'), b('ffffffffffffffff'),
        'PCTv201-7'),
    (b('0000000000000000'), b('63ac98cdf3843a7a'), b('ffffffffffffffff5065746572477265656e6177617953e5ffe553'),
        'PCTv201-8'),
    (b('ffffffffffffffff'), b('3fb49e2fa12371dd'), b('ffffffffffffffff5065746572477265656e6177617953e5ffe553'),
        'PCTv201-9'),
    (b('0001020304050607'), b('46414781ab387d5f'), b('ffffffffffffffff5065746572477265656e6177617953e5ffe553'),
        'PCTv201-10'),
    (b('0011223344556677'), b('be09dc81feaca271'), b('ffffffffffffffff5065746572477265656e6177617953e5ffe553'),
        'PCTv201-11'),
    (b('0000000000000000'), b('e64221e608be30ab'), b('53e5ffe553'),
        'PCTv201-12'),
    (b('ffffffffffffffff'), b('862bc60fdcd4d9a9'), b('53e5ffe553'),
        'PCTv201-13'),
    (b('0001020304050607'), b('6a34da50fa5e47de'), b('53e5ffe553'),
        'PCTv201-14'),
    (b('0011223344556677'), b('584644c34503122c'), b('53e5ffe553'),
        'PCTv201-15'),
]

class BufferOverflowTest(unittest.TestCase):
    # Test a buffer overflow found in older versions of PyCrypto

    def setUp(self):
        global ARC2
        from Crypto.Cipher import ARC2

    def runTest(self):
        """ARC2 with keylength > 128"""
        key = "x" * 16384
        mode = ARC2.MODE_ECB
        self.assertRaises(ValueError, ARC2.new, key, mode)

def get_tests(config={}):
    from Crypto.Cipher import ARC2
    from common import make_block_tests

    tests = make_block_tests(ARC2, "ARC2", test_data)
    tests.append(BufferOverflowTest())

    return tests

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
