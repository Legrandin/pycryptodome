# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_256.py: Self-test for the SHA-3/256 hash function
#
# Written in 2013 by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
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

"""Self-test suite for Crypto.Hash.SHA3_256"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
# Test vectors from ``Keccak: Known-answer and Monte Carlo test results'',
# Version 3.0, January 14, 2011 <http://keccak.noekeon.org/KeccakKAT-3.zip>
    ('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
     '',
     'Empty string'),
     
    ('eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a',
     '\xcc',
     '1 byte message'),

    ('e78c421e6213aff8de1f025759a4f2c943db62bbde359c8737e19b3776ed2dd2',
     '\xde\x8f\x1b?\xaaKp@\xedEc\xc3\xb8\xe5\x98%1x\xe8~M\r\xf7'
    +'^O\xf2\xf2\xde\xddZ\x0b\xe0F',
     '33 bytes message'),
     
    ('e717a7769448abbe5fef8187954a88ac56ded1d22e63940ab80d029585a21921',
    '\xb3-\x95\xb0\xb9\xaa\xd2\xa8\x81m\xe6\xd0m\x1f\x86\x00\x85\x05\xbd'
    +'\x8c\x14\x12On\x9a\x16;Z*\xdeU\xf85\xd0\xec8\x80\xefPp\r;%\xe4,\xc0'
    +'\xaf\x05\x0c\xcd\x1b\xe5\xe5U\xb20\x87\xe0M{\xf9\x816"x\x0cs\x13\xa1'
    +'\x95O\x87@\xb6\xee-?q\xf7h\xddA\x7fR\x04\x82\xbd:\x08\xd4\xf2"\xb4'
    +'\xee\x9d\xbd\x01TG\xb35\x07\xddP\xf3\xabBG\xc5\xde\x9a\x8a\xbdb\xa8'
    +'\xde\xce\xa0\x1e;\x87\xc8\xb9\'\xf5\xb0\x8b\xeb7gLo\x8e8\x0c\x04',
    '136 bytes (block size) message'),
    
    ('59e904b2aa0ccbf2a9d127446f113b7cc3d07b970e07a322325ecee66ae0c9ca',
     "19\x84\x0b\x8a\xd4\xbc\xd3\x90\x92\x91o\xd9\xd0\x17\x98"
    +"\xffZ\xa1\xe4\x8f4p,r\xdf\xe7K\x12\xe9\x8a\x11N1\x8c\xdd-G"
    +"\xa9\xc3 \xff\xf9\x08\xa8\xdb\xc2\xa5\xb1\xd8rg\xc8\xe9\x83"
    +"\x82\x98a\xa5gU\x8b7\xb2\x92\xd4W^ \r\xe9\xf1\xdeEu_\xaf\xf9"
    +"\xef\xae4\x96NC6\xc2Y\xf1\xe6e\x99\xa7\xc9\x04\xec\x02S\x9f"
    +"\x1a\x8e\xab\x87\x06\xe0\xb4\xf4\x8fr\xfe\xc2yI\t\xeeJ{\t-`a"
    +"\xc7D\x81\xc9\xe2\x1b\x932\xdc|nH-\x7f\x9c\xc3!\x0b8\xa6\xf8"
    +"\x8fy\x18\xc2\xd8\xc5^d\xa4(\xce+h\xfd\x07\xabW*\x8b\n#\x88fO"
    +"\x99H\x9f\x04\xebT\xdf\x13v'\x18\x10\xe0\xe7\xbc\xe3\x96\xf5"
    +"(\x07q\x0e\r\xea\x94\xebI\xf4\xb3g'\x12`\xc3Ek\x98\x18\xfc"
    +"zr#Nk\xf2 _\xf6\xa3eF P\x15\xeb\xd7\xd8\xc2Rz\xa40\xf5\x8e\x0e"
    +"\x8a\xc9z{ky<\xd4\x03\xd5\x17\xd6b\x95\xf3z4\xd0\xb7\xd2\xfa{"
    +"\xc3E\xac\x04\xca\x1e&d\x80\xde\xec9\xf5\xc8\x86A\xc9\xdc\x0b"
    +"\xd15\x81X\xfd\xec\xdd\x96h[\xbb\xb5\xc1\xfe^\xa8\x9d,\xb4\xa9"
    +"\xd5\xd1+\xb8\xc8\x93(\x1f\xf3\x8e\x87\xd6\xb4\x84\x1f\x06P\t"
    +"-D~\x01? \xea\x93N\x18", 
     '319 bytes message'),
     
# Test vectors from http://www.di-mgt.com.au/sha_testvectors.html
    ('4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
     'abc',
     '"abc", the bit string (0x)616263 of length 24 bits.'),
     
    ('45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371',
     'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     ' "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).'),
     
    ('f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67',
     'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh'
     +'ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     '896 bits message'),
     
    ('fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96',
     'a' * 1000000,
     'one million (1,000,000) repetitions of the character "a" (0x61).'),
]

def get_tests(config={}):
    from Crypto.Hash import SHA3_256
    from common import make_hash_tests
    return make_hash_tests(SHA3_256, "SHA3_256", test_data,
        digest_size=SHA3_256.digest_size,
        oid="*-not yet assigned-*")

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
