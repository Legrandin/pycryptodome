# -*- coding: utf-8 -*-
#
#  SelfTest/Protocol/test_KDF.py: Self-test for key derivation functions
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

__revision__ = "$Id$"

import unittest
from binascii import unhexlify

from Crypto.Util.py3compat import *

from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Hash import SHA1, HMAC
from Crypto.Cipher import AES, DES3

from Crypto.Protocol.KDF import PBKDF1, PBKDF2, _S2V

def t2b(t): return unhexlify(b(t))

class PBKDF1_Tests(unittest.TestCase):

    # List of tuples with test data.
    # Each tuple is made up by:
    #       Item #0: a pass phrase
    #       Item #1: salt (8 bytes encoded in hex)
    #       Item #2: output key length
    #       Item #3: iterations to use
    #       Item #4: expected result (encoded in hex)
    _testData = (
            # From http://www.di-mgt.com.au/cryptoKDFs.html#examplespbkdf
            ("password","78578E5A5D63CB06",16,1000,"DC19847E05C64D2FAF10EBFB4A3D2A20"),
    )

    def test1(self):
        v = self._testData[0]
        res = PBKDF1(v[0], t2b(v[1]), v[2], v[3], SHA1)
        self.assertEqual(res, t2b(v[4]))

class PBKDF2_Tests(unittest.TestCase):

    # List of tuples with test data.
    # Each tuple is made up by:
    #       Item #0: a pass phrase
    #       Item #1: salt (encoded in hex)
    #       Item #2: output key length
    #       Item #3: iterations to use
    #       Item #4: expected result (encoded in hex)
    _testData = (
            # From http://www.di-mgt.com.au/cryptoKDFs.html#examplespbkdf
            ("password","78578E5A5D63CB06",24,2048,"BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643"),
            # From RFC 6050
            ("password","73616c74", 20, 1,          "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            ("password","73616c74", 20, 2,          "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            ("password","73616c74", 20, 4096,       "4b007901b765489abead49d926f721d065a429c1"),
            ("passwordPASSWORDpassword","73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
                                    25, 4096,       "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
            ( 'pass\x00word',"7361006c74",16,4096,  "56fa6aa75548099dcc37d7f03425e0c3"),
    )

    def test1(self):
        # Test only for HMAC-SHA1 as PRF

        def prf(p,s):
            return HMAC.new(p,s,SHA1).digest()

        for i in xrange(len(self._testData)):
            v = self._testData[i]
            res  = PBKDF2(v[0], t2b(v[1]), v[2], v[3])
            res2 = PBKDF2(v[0], t2b(v[1]), v[2], v[3], prf)
            self.assertEqual(res, t2b(v[4]))
            self.assertEqual(res, res2)

class S2V_Tests(unittest.TestCase):

    # Sequence of test vectors.
    # Each test vector is made up by:
    #   Item #0: a tuple of strings
    #   Item #1: an AES key
    #   Item #2: the result
    #   Item #3: the cipher module S2V is based on
    # Everything is hex encoded
    _testData = [

            # RFC5297, A.1
            (
             (  '101112131415161718191a1b1c1d1e1f2021222324252627',
                '112233445566778899aabbccddee' ),
            'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
            '85632d07c6e8f37f950acd320a2ecc93',
            AES
            ),

            # RFC5297, A.2
            (
             (  '00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddcc'+
                'bbaa99887766554433221100',
                '102030405060708090a0',
                '09f911029d74e35bd84156c5635688c0',
                '7468697320697320736f6d6520706c61'+
                '696e7465787420746f20656e63727970'+
                '74207573696e67205349562d414553'),
            '7f7e7d7c7b7a79787776757473727170',
            '7bdb6e3b432667eb06f4d14bff2fbd0f',
            AES
            ),

        ]

    def test1(self):
        """Verify correctness of test vector"""
        for tv in self._testData:
            s2v = _S2V.new(t2b(tv[1]), tv[3])
            for s in tv[0]:
                s2v.update(t2b(s))
            result = s2v.derive()
            self.assertEqual(result, t2b(tv[2]))

    def test2(self):
        """Verify that no more than 127(AES) and 63(TDES)
        components are accepted."""
        key = bchr(0)*16
        for module in (AES, DES3):
            s2v = _S2V.new(key, module)
            max_comps = module.block_size*8-1
            for i in xrange(max_comps):
                s2v.update(b("XX"))
            self.assertRaises(TypeError, s2v.update, b("YY"))

def get_tests(config={}):
    tests = []
    tests += list_test_cases(PBKDF1_Tests)
    tests += list_test_cases(PBKDF2_Tests)
    tests += list_test_cases(S2V_Tests)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4
