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
from Crypto.Hash import SHA1, HMAC, SHA256
from Crypto.Cipher import AES, DES3

from Crypto.Protocol.KDF import PBKDF1, PBKDF2, _S2V, HKDF

def t2b(t):
    if t is None:
        return None
    return unhexlify(b(t))

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


class HKDF_Tests(unittest.TestCase):

    # Test vectors from RFC5869, Appendix A
    # Each tuple is made up by:
    #       Item #0: hash module
    #       Item #1: secret
    #       Item #2: salt
    #       Item #3: context
    #       Item #4: expected result
    _test_vector  = (
            (
                SHA256,
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                42,
                "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865"
            ),
            (
                SHA256,
                "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f" +
                "707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                82,
                "b11e398dc80327a1c8e7f78c596a4934" +
                "4f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87"
            ),
            (
                SHA256,
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                None,
                None,
                42,
                "8da4e775a563c18f715f802a063c5a31" +
                "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                "9d201395faa4b61a96c8"
            ),
            (
                SHA1,
                "0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                42,
                "085a01ea1b10f36933068b56efa5ad81" +
                "a4f14b822f5b091568a9cdd4f155fda2" +
                "c22e422478d305f3f896"
            ),
            (
                SHA1,
                "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f" +
                "707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                82,
                "0bd770a74d1160f7c9f12cd5912a06eb" +
                "ff6adcae899d92191fe4305673ba2ffe" +
                "8fa3f1a4e5ad79f3f334b3b202b2173c" +
                "486ea37ce3d397ed034c7f9dfeb15c5e" +
                "927336d0441f4c4300e2cff0d0900b52" +
                "d3b4"
            ),
            (
                SHA1,
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                42,
                "0ac1af7002b3d761d1e55298da9d0506" +
                "b9ae52057220a306e07b6b87e8df21d0" +
                "ea00033de03984d34918"
            ),
            (
                SHA1,
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                None,
                "",
                42,
                "2c91117204d745f3500d636a62f64f0a" +
                "b3bae548aa53d423b0d1f27ebba6f5e5" +
                "673a081d70cce7acfc48"
            )
        )

    def test1(self):
        for tv in self._test_vector:
            secret, salt, info, exp = [ t2b(tv[x]) for x in (1,2,3,5) ]
            key_len, hashmod = [ tv[x] for x in (4,0) ]

            output = HKDF(secret, key_len, salt, hashmod, 1, info)
            self.assertEqual(output, exp)

    def test2(self):
        ref = HKDF(b("XXXXXX"), 12, b("YYYY"), SHA1)

        # Same output, but this time split over 2 keys
        key1, key2 = HKDF(b("XXXXXX"), 6, b("YYYY"), SHA1, 2)
        self.assertEqual((ref[:6], ref[6:]), (key1, key2))

        # Same output, but this time split over 3 keys
        key1, key2, key3 = HKDF(b("XXXXXX"), 4, b("YYYY"), SHA1, 3)
        self.assertEqual((ref[:4], ref[4:8], ref[8:]), (key1, key2, key3))

def get_tests(config={}):
    tests = []
    tests += list_test_cases(PBKDF1_Tests)
    tests += list_test_cases(PBKDF2_Tests)
    tests += list_test_cases(S2V_Tests)
    tests += list_test_cases(HKDF_Tests)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4
