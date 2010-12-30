# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/DES.py: Self-test for the (Single) DES cipher
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

"""Self-test suite for Crypto.Cipher.DES"""

__revision__ = "$Id$"

from common import dict     # For compatibility with Python 2.1 and 2.2
from Crypto.Util.py3compat import *
import unittest

# This is a list of (plaintext, ciphertext, key, description) tuples.
SP800_17_B1_KEY = b("01") * 8
SP800_17_B2_PT = b("00") * 8
test_data = [
    # Test vectors from Appendix A of NIST SP 800-17
    # "Modes of Operation Validation System (MOVS): Requirements and Procedures"
    # http://csrc.nist.gov/publications/nistpubs/800-17/800-17.pdf

    # Appendix A - "Sample Round Outputs for the DES"
    (b('0000000000000000'), b('82dcbafbdeab6602'), b('10316e028c8f3b4a'),
        "NIST SP800-17 A"),

    # Table B.1 - Variable Plaintext Known Answer Test
    (b('8000000000000000'), b('95f8a5e5dd31d900'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #0'),
    (b('4000000000000000'), b('dd7f121ca5015619'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #1'),
    (b('2000000000000000'), b('2e8653104f3834ea'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #2'),
    (b('1000000000000000'), b('4bd388ff6cd81d4f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #3'),
    (b('0800000000000000'), b('20b9e767b2fb1456'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #4'),
    (b('0400000000000000'), b('55579380d77138ef'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #5'),
    (b('0200000000000000'), b('6cc5defaaf04512f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #6'),
    (b('0100000000000000'), b('0d9f279ba5d87260'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #7'),
    (b('0080000000000000'), b('d9031b0271bd5a0a'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #8'),
    (b('0040000000000000'), b('424250b37c3dd951'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #9'),
    (b('0020000000000000'), b('b8061b7ecd9a21e5'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #10'),
    (b('0010000000000000'), b('f15d0f286b65bd28'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #11'),
    (b('0008000000000000'), b('add0cc8d6e5deba1'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #12'),
    (b('0004000000000000'), b('e6d5f82752ad63d1'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #13'),
    (b('0002000000000000'), b('ecbfe3bd3f591a5e'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #14'),
    (b('0001000000000000'), b('f356834379d165cd'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #15'),
    (b('0000800000000000'), b('2b9f982f20037fa9'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #16'),
    (b('0000400000000000'), b('889de068a16f0be6'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #17'),
    (b('0000200000000000'), b('e19e275d846a1298'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #18'),
    (b('0000100000000000'), b('329a8ed523d71aec'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #19'),
    (b('0000080000000000'), b('e7fce22557d23c97'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #20'),
    (b('0000040000000000'), b('12a9f5817ff2d65d'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #21'),
    (b('0000020000000000'), b('a484c3ad38dc9c19'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #22'),
    (b('0000010000000000'), b('fbe00a8a1ef8ad72'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #23'),
    (b('0000008000000000'), b('750d079407521363'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #24'),
    (b('0000004000000000'), b('64feed9c724c2faf'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #25'),
    (b('0000002000000000'), b('f02b263b328e2b60'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #26'),
    (b('0000001000000000'), b('9d64555a9a10b852'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #27'),
    (b('0000000800000000'), b('d106ff0bed5255d7'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #28'),
    (b('0000000400000000'), b('e1652c6b138c64a5'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #29'),
    (b('0000000200000000'), b('e428581186ec8f46'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #30'),
    (b('0000000100000000'), b('aeb5f5ede22d1a36'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #31'),
    (b('0000000080000000'), b('e943d7568aec0c5c'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #32'),
    (b('0000000040000000'), b('df98c8276f54b04b'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #33'),
    (b('0000000020000000'), b('b160e4680f6c696f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #34'),
    (b('0000000010000000'), b('fa0752b07d9c4ab8'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #35'),
    (b('0000000008000000'), b('ca3a2b036dbc8502'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #36'),
    (b('0000000004000000'), b('5e0905517bb59bcf'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #37'),
    (b('0000000002000000'), b('814eeb3b91d90726'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #38'),
    (b('0000000001000000'), b('4d49db1532919c9f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #39'),
    (b('0000000000800000'), b('25eb5fc3f8cf0621'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #40'),
    (b('0000000000400000'), b('ab6a20c0620d1c6f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #41'),
    (b('0000000000200000'), b('79e90dbc98f92cca'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #42'),
    (b('0000000000100000'), b('866ecedd8072bb0e'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #43'),
    (b('0000000000080000'), b('8b54536f2f3e64a8'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #44'),
    (b('0000000000040000'), b('ea51d3975595b86b'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #45'),
    (b('0000000000020000'), b('caffc6ac4542de31'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #46'),
    (b('0000000000010000'), b('8dd45a2ddf90796c'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #47'),
    (b('0000000000008000'), b('1029d55e880ec2d0'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #48'),
    (b('0000000000004000'), b('5d86cb23639dbea9'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #49'),
    (b('0000000000002000'), b('1d1ca853ae7c0c5f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #50'),
    (b('0000000000001000'), b('ce332329248f3228'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #51'),
    (b('0000000000000800'), b('8405d1abe24fb942'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #52'),
    (b('0000000000000400'), b('e643d78090ca4207'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #53'),
    (b('0000000000000200'), b('48221b9937748a23'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #54'),
    (b('0000000000000100'), b('dd7c0bbd61fafd54'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #55'),
    (b('0000000000000080'), b('2fbc291a570db5c4'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #56'),
    (b('0000000000000040'), b('e07c30d7e4e26e12'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #57'),
    (b('0000000000000020'), b('0953e2258e8e90a1'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #58'),
    (b('0000000000000010'), b('5b711bc4ceebf2ee'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #59'),
    (b('0000000000000008'), b('cc083f1e6d9e85f6'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #60'),
    (b('0000000000000004'), b('d2fd8867d50d2dfe'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #61'),
    (b('0000000000000002'), b('06e7ea22ce92708f'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #62'),
    (b('0000000000000001'), b('166b40b44aba4bd6'), SP800_17_B1_KEY,
        'NIST SP800-17 B.1 #63'),

    # Table B.2 - Variable Key Known Answer Test
    (SP800_17_B2_PT, b('95a8d72813daa94d'), b('8001010101010101'),
        'NIST SP800-17 B.2 #0'),
    (SP800_17_B2_PT, b('0eec1487dd8c26d5'), b('4001010101010101'),
        'NIST SP800-17 B.2 #1'),
    (SP800_17_B2_PT, b('7ad16ffb79c45926'), b('2001010101010101'),
        'NIST SP800-17 B.2 #2'),
    (SP800_17_B2_PT, b('d3746294ca6a6cf3'), b('1001010101010101'),
        'NIST SP800-17 B.2 #3'),
    (SP800_17_B2_PT, b('809f5f873c1fd761'), b('0801010101010101'),
        'NIST SP800-17 B.2 #4'),
    (SP800_17_B2_PT, b('c02faffec989d1fc'), b('0401010101010101'),
        'NIST SP800-17 B.2 #5'),
    (SP800_17_B2_PT, b('4615aa1d33e72f10'), b('0201010101010101'),
        'NIST SP800-17 B.2 #6'),
    (SP800_17_B2_PT, b('2055123350c00858'), b('0180010101010101'),
        'NIST SP800-17 B.2 #7'),
    (SP800_17_B2_PT, b('df3b99d6577397c8'), b('0140010101010101'),
        'NIST SP800-17 B.2 #8'),
    (SP800_17_B2_PT, b('31fe17369b5288c9'), b('0120010101010101'),
        'NIST SP800-17 B.2 #9'),
    (SP800_17_B2_PT, b('dfdd3cc64dae1642'), b('0110010101010101'),
        'NIST SP800-17 B.2 #10'),
    (SP800_17_B2_PT, b('178c83ce2b399d94'), b('0108010101010101'),
        'NIST SP800-17 B.2 #11'),
    (SP800_17_B2_PT, b('50f636324a9b7f80'), b('0104010101010101'),
        'NIST SP800-17 B.2 #12'),
    (SP800_17_B2_PT, b('a8468ee3bc18f06d'), b('0102010101010101'),
        'NIST SP800-17 B.2 #13'),
    (SP800_17_B2_PT, b('a2dc9e92fd3cde92'), b('0101800101010101'),
        'NIST SP800-17 B.2 #14'),
    (SP800_17_B2_PT, b('cac09f797d031287'), b('0101400101010101'),
        'NIST SP800-17 B.2 #15'),
    (SP800_17_B2_PT, b('90ba680b22aeb525'), b('0101200101010101'),
        'NIST SP800-17 B.2 #16'),
    (SP800_17_B2_PT, b('ce7a24f350e280b6'), b('0101100101010101'),
        'NIST SP800-17 B.2 #17'),
    (SP800_17_B2_PT, b('882bff0aa01a0b87'), b('0101080101010101'),
        'NIST SP800-17 B.2 #18'),
    (SP800_17_B2_PT, b('25610288924511c2'), b('0101040101010101'),
        'NIST SP800-17 B.2 #19'),
    (SP800_17_B2_PT, b('c71516c29c75d170'), b('0101020101010101'),
        'NIST SP800-17 B.2 #20'),
    (SP800_17_B2_PT, b('5199c29a52c9f059'), b('0101018001010101'),
        'NIST SP800-17 B.2 #21'),
    (SP800_17_B2_PT, b('c22f0a294a71f29f'), b('0101014001010101'),
        'NIST SP800-17 B.2 #22'),
    (SP800_17_B2_PT, b('ee371483714c02ea'), b('0101012001010101'),
        'NIST SP800-17 B.2 #23'),
    (SP800_17_B2_PT, b('a81fbd448f9e522f'), b('0101011001010101'),
        'NIST SP800-17 B.2 #24'),
    (SP800_17_B2_PT, b('4f644c92e192dfed'), b('0101010801010101'),
        'NIST SP800-17 B.2 #25'),
    (SP800_17_B2_PT, b('1afa9a66a6df92ae'), b('0101010401010101'),
        'NIST SP800-17 B.2 #26'),
    (SP800_17_B2_PT, b('b3c1cc715cb879d8'), b('0101010201010101'),
        'NIST SP800-17 B.2 #27'),
    (SP800_17_B2_PT, b('19d032e64ab0bd8b'), b('0101010180010101'),
        'NIST SP800-17 B.2 #28'),
    (SP800_17_B2_PT, b('3cfaa7a7dc8720dc'), b('0101010140010101'),
        'NIST SP800-17 B.2 #29'),
    (SP800_17_B2_PT, b('b7265f7f447ac6f3'), b('0101010120010101'),
        'NIST SP800-17 B.2 #30'),
    (SP800_17_B2_PT, b('9db73b3c0d163f54'), b('0101010110010101'),
        'NIST SP800-17 B.2 #31'),
    (SP800_17_B2_PT, b('8181b65babf4a975'), b('0101010108010101'),
        'NIST SP800-17 B.2 #32'),
    (SP800_17_B2_PT, b('93c9b64042eaa240'), b('0101010104010101'),
        'NIST SP800-17 B.2 #33'),
    (SP800_17_B2_PT, b('5570530829705592'), b('0101010102010101'),
        'NIST SP800-17 B.2 #34'),
    (SP800_17_B2_PT, b('8638809e878787a0'), b('0101010101800101'),
        'NIST SP800-17 B.2 #35'),
    (SP800_17_B2_PT, b('41b9a79af79ac208'), b('0101010101400101'),
        'NIST SP800-17 B.2 #36'),
    (SP800_17_B2_PT, b('7a9be42f2009a892'), b('0101010101200101'),
        'NIST SP800-17 B.2 #37'),
    (SP800_17_B2_PT, b('29038d56ba6d2745'), b('0101010101100101'),
        'NIST SP800-17 B.2 #38'),
    (SP800_17_B2_PT, b('5495c6abf1e5df51'), b('0101010101080101'),
        'NIST SP800-17 B.2 #39'),
    (SP800_17_B2_PT, b('ae13dbd561488933'), b('0101010101040101'),
        'NIST SP800-17 B.2 #40'),
    (SP800_17_B2_PT, b('024d1ffa8904e389'), b('0101010101020101'),
        'NIST SP800-17 B.2 #41'),
    (SP800_17_B2_PT, b('d1399712f99bf02e'), b('0101010101018001'),
        'NIST SP800-17 B.2 #42'),
    (SP800_17_B2_PT, b('14c1d7c1cffec79e'), b('0101010101014001'),
        'NIST SP800-17 B.2 #43'),
    (SP800_17_B2_PT, b('1de5279dae3bed6f'), b('0101010101012001'),
        'NIST SP800-17 B.2 #44'),
    (SP800_17_B2_PT, b('e941a33f85501303'), b('0101010101011001'),
        'NIST SP800-17 B.2 #45'),
    (SP800_17_B2_PT, b('da99dbbc9a03f379'), b('0101010101010801'),
        'NIST SP800-17 B.2 #46'),
    (SP800_17_B2_PT, b('b7fc92f91d8e92e9'), b('0101010101010401'),
        'NIST SP800-17 B.2 #47'),
    (SP800_17_B2_PT, b('ae8e5caa3ca04e85'), b('0101010101010201'),
        'NIST SP800-17 B.2 #48'),
    (SP800_17_B2_PT, b('9cc62df43b6eed74'), b('0101010101010180'),
        'NIST SP800-17 B.2 #49'),
    (SP800_17_B2_PT, b('d863dbb5c59a91a0'), b('0101010101010140'),
        'NIST SP800-17 B.2 #50'),
    (SP800_17_B2_PT, b('a1ab2190545b91d7'), b('0101010101010120'),
        'NIST SP800-17 B.2 #51'),
    (SP800_17_B2_PT, b('0875041e64c570f7'), b('0101010101010110'),
        'NIST SP800-17 B.2 #52'),
    (SP800_17_B2_PT, b('5a594528bebef1cc'), b('0101010101010108'),
        'NIST SP800-17 B.2 #53'),
    (SP800_17_B2_PT, b('fcdb3291de21f0c0'), b('0101010101010104'),
        'NIST SP800-17 B.2 #54'),
    (SP800_17_B2_PT, b('869efd7f9f265a09'), b('0101010101010102'),
        'NIST SP800-17 B.2 #55'),
]

class RonRivetTest(unittest.TestCase):
    """ Ronald L. Rivet's DES test, see 
        http://people.csail.mit.edu/rivest/Destest.txt
    ABSTRACT
    --------

    We present a simple way to test the correctness of a DES implementation:
    Use the recurrence relation:

        X0      =       9474B8E8C73BCA7D (hexadecimal)

        X(i+1)  =       IF  (i is even)  THEN  E(Xi,Xi)  ELSE  D(Xi,Xi)

    to compute a sequence of 64-bit values:  X0, X1, X2, ..., X16.  Here
    E(X,K)  denotes the DES encryption of  X  using key  K, and  D(X,K)  denotes
    the DES decryption of  X  using key  K.  If you obtain

        X16     =       1B1A2DDB4C642438

    your implementation does not have any of the 36,568 possible single-fault 
    errors described herein.
    """
    def runTest(self):
        from Crypto.Cipher import DES
        from binascii import b2a_hex

        X = []
        X[0:] = [b('\x94\x74\xB8\xE8\xC7\x3B\xCA\x7D')]
        
        for i in range(16):
            c = DES.new(X[i],DES.MODE_ECB)
            if not (i&1): # (num&1) returns 1 for odd numbers 
                X[i+1:] = [c.encrypt(X[i])] # even
            else:
                X[i+1:] = [c.decrypt(X[i])] # odd

        self.assertEqual(b2a_hex(X[16]),
            b2a_hex(b('\x1B\x1A\x2D\xDB\x4C\x64\x24\x38')))

def get_tests(config={}):
    from Crypto.Cipher import DES
    from common import make_block_tests
    return make_block_tests(DES, "DES", test_data) + [RonRivetTest()]

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
