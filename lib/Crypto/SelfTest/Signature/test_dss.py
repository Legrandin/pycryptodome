# -*- coding: utf-8 -*-
#
#  SelfTest/Signature/test_dss.py: Self-test for DSS signatures
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

import re
import sys
import copy
import unittest
from binascii import unhexlify
from StringIO import StringIO

if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto.Hash import *
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util.number import bytes_to_long, long_to_bytes

#
# This is a list of test vectors.
#
# Each item is an object with the following members:
#  desc, P, Q, G, X, Y, Msg, K, Signature [, Result='P'/'F' ]
#
# http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3dsatestvectors.zip
#
test_vectors = []


class TestVector(object):
    pass


def load_test_module(module):
    f = StringIO(module.content)
    line = '\n'
    test_count = 1
    while line:
        line = f.readline()

        # New domain parameters
        if line.startswith('[mod'):
            domain_params = TestVector()

            res = re.match("\[mod = L=(\d+), N=(\d+), ([^\]]+)\]", line)
            if not res:
                continue
            domain_params.hashmod = __import__("Crypto.Hash." +
                                               res.group(3).replace("-", ""),
                                               globals(), locals(), ["new"])
            domain_params.desc = "DSS test # (%s, %s) with " % \
                                 (res.group(1), res.group(2))
            
            f.readline()        # Eat one empty line
            line = f.readline()
            for comp in 'P', 'Q', 'G':
                res = re.match(comp + ' = ([0-9a-fA-F]+)', line)
                setattr(domain_params, comp, long(res.group(1), 16))
                line = f.readline()
            continue

        # Read actual test
        if line.startswith('Msg'):
            tv = copy.copy(domain_params)
            tv.desc = tv.desc.replace("#", "#" + str(test_count))
            for comp in 'Msg', 'X', 'Y', 'K', 'R', 'S':
                if line == '\n':
                    line = f.readline()
                res = re.match(comp + ' = ([0-9a-fA-F]+)', line)
                if not res:
                    continue
                if comp in ('X', 'Y'):
                    setattr(tv, comp, long(res.group(1), 16))
                else:
                    setattr(tv, comp, unhexlify(res.group(1)))
                line = '\n'
            setattr(tv, 'Signature', tv.R + tv.S)
            
            # Optionally add the validity flag
            line = f.readline()
            res = re.match("Result = ([PF])", line)
            if res:
                setattr(tv, "Result", res.group(1))
            
            test_vectors.append(tv)
            test_count += 1
            continue

        # This line is ignored


def load_tests():
    from Crypto.SelfTest.Signature import FIPS_186_3_SigGen_txt as SigGen_txt
    from Crypto.SelfTest.Signature import FIPS_186_3_SigVer_rsp as SigVer_rsp
    
    load_test_module(SigGen_txt)
    load_test_module(SigVer_rsp)


class StrRNG:

    def __init__(self, randomness):
        length = len(randomness)
        self._idx = 0
        # Fix required to get the right K (see how randint() works!)
        self._randomness = long_to_bytes(bytes_to_long(randomness) - 1, length)

    def __call__(self, n):
        out = self._randomness[self._idx:self._idx + n]
        self._idx += n
        return out


class FIPS_DSS_Tests(unittest.TestCase):
   
    # 1st 1024 bit key from SigGen.txt
    P = 0xa8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283L
    Q = 0xf85f0f83ac4df7ea0cdf8f469bfeeaea14156495L
    G = 0x2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33L
    X = 0xc53eae6d45323164c7d07af5715703744a63fc3aL
    Y = 0x313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970bL

    def shortDescription(self):
        return self.description

    def test1(self):
        """Positive tests for signature generation"""
        
        for tv in test_vectors:
            if not hasattr(tv, "K"):
                continue

            self.description = tv.desc
            key = DSA.construct([tv.Y, tv.G, tv.P, tv.Q, tv.X])
            hash_obj = tv.hashmod.new(tv.Msg)
            signer = DSS.new(key, 'fips-186-3', randfunc=StrRNG(tv.K))
            signature = signer.sign(hash_obj)
            self.assertEqual(signature, tv.Signature)

    def test2(self):
        """Positive tests for signature verification"""

        for tv in test_vectors:
            # Skip incorrect signatures
            if getattr(tv, "Result", "P") != "P":
                continue
            
            self.description = tv.desc
            key = DSA.construct([tv.Y, tv.G, tv.P, tv.Q])
            hash_obj = tv.hashmod.new(tv.Msg)
            signer = DSS.new(key, 'fips-186-3')
            self.failUnless(signer.verify(hash_obj, tv.Signature))

    def test3(self):
        """Negative tests for signature verification"""

        for tv in test_vectors:
            # Skip correct signatures
            if getattr(tv, "Result", None) != "F":
                continue
            
            self.description = tv.desc
            key = DSA.construct([tv.Y, tv.G, tv.P, tv.Q])
            hash_obj = tv.hashmod.new(tv.Msg)
            signer = DSS.new(key, 'fips-186-3')
            self.failIf(signer.verify(hash_obj, tv.Signature))

    def test4(self):
        """Verify that unapproved hashes are rejected"""

        from Crypto.Hash import RIPEMD160

        self.description = "Unapproved hash (RIPEMD160) test"
        key = DSA.construct((self.Y, self.G, self.P, self.Q))
        hash_obj = RIPEMD160.new()
        signer = DSS.new(key, 'fips-186-3')
        self.assertRaises(ValueError, signer.sign, hash_obj)
        self.assertRaises(ValueError, signer.verify, hash_obj, b("\x00") * 40)

    def test5(self):
        """Verify that unknown modes/encodings are rejected"""

        self.description = "Unknown mode test"
        key = DSA.construct((self.Y, self.G, self.P, self.Q))
        self.assertRaises(ValueError, DSS.new, key, 'fips-186-0')
 
        self.description = "Unknown encoding test"
        self.assertRaises(ValueError, DSS.new, key, 'fips-186-3', 'xml')

    def test6(self):
        """Verify ASN.1 encoding"""

        self.description = "ASN.1 encoding test"
        key = DSA.construct((self.Y, self.G, self.P, self.Q, self.X))
        hash_obj = SHA1.new()
        signer = DSS.new(key, 'fips-186-3', 'der')
        signature = signer.sign(hash_obj)
        
        # Verify that output looks like a SEQUENCE
        self.assertEqual(bord(signature[0]), 48)
        self.failUnless(signer.verify(hash_obj, signature))

        # Verify that ASN.1 parsing fails as expected
        signature = bchr(7) + signature[1:]
        self.failIf(signer.verify(hash_obj, signature))

    def test7(self):
        """Verify public/private method"""

        self.description = "can_sign() test"
        key = DSA.construct((self.Y, self.G, self.P, self.Q, self.X))
        signer = DSS.new(key, 'fips-186-3')
        self.failUnless(signer.can_sign())

        key = DSA.construct((self.Y, self.G, self.P, self.Q))
        signer = DSS.new(key, 'fips-186-3')
        self.failIf(signer.can_sign())


def get_tests(config={}):
    tests = []
    load_tests()
    tests += list_test_cases(FIPS_DSS_Tests)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
