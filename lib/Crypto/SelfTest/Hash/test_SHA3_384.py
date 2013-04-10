# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_384.py: Self-test for the SHA-3/384 hash function
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

"""Self-test suite for Crypto.Hash.SHA3_384"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
# Test vectors from ``Keccak: Known-answer and Monte Carlo test results'',
# Version 3.0, January 14, 2011 <http://keccak.noekeon.org/KeccakKAT-3.zip>
    ('2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b'
    +'2dd2b21362337441ac12b515911957ff',
     '',
     'Empty string'),
     
    ('1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641'
    +'f5fa1e8641d7958336ee7b11c58f73e9',
     '\xcc',
     '1 byte message'),

    ('cf38764973f1ec1c34b5433ae75a3aad1aaef6ab197850c56c8617bcd6a882f66'
    +'66883ac17b2dccdbaa647075d0972b5',
     '\xde\x8f\x1b?\xaaKp@\xedEc\xc3\xb8\xe5\x98%1x\xe8~M\r\xf7'
    +'^O\xf2\xf2\xde\xddZ\x0b\xe0F',
     '33 bytes message'),
     
     ('9fb5700502e01926824f46e9f61894f9487dbcf8ae6217203c85606f97556653'
     +'9376d6239db04aef9bf48ca4f191a90b',
      "\xe3W\x80\xeb\x97\x99\xadLwS]M\xdbh<\xf3>\xf3gqS'\xcfLJX\xed\x9c"
     +"\xbd\xcd\xd4\x86\xf6i\xf8\x01\x89\xd5I\xa96O\xa8*Q\xa5&T\xecr\x1b"
     +"\xb3\xaa\xb9]\xce\xb4\xa8jj\xfa\x93\x82m\xb9#Q~\x92\x8f3\xe3\xfb"
     +"\xa8P\xd4V`\xef\x83\xb9\x87j\xcc\xaf\xa2\xa9\x98z%K\x13|n\x14\n!i"
     +"\x1e\x10iA8H",
     '104 byte (block size) message'),
    
    ('e0100d6a02568b244df7ea67f280ae5d956be63836b02bbfe8875d6dbed164655'
    +'82e5b4da7a67602508c679f0a50ea2d',
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
    ('f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f'
    +'8c681e4afaf31a34db29fb763e3c28e',
     'abc',
     '"abc", the bit string (0x)616263 of length 24 bits.'),
     
    ('b41e8896428f1bcbb51e17abd6acc98052a3502e0d5bf7fa1af949b4d3c855e7c'
    +'4dc2c390326b3f3e74c7b1e2b9a3657',
     'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     ' "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).'),
     
    ('cc063f34685135368b34f7449108f6d10fa727b09d696ec5331771da46a923b6c'
    +'34dbd1d4f77e595689c1f3800681c28',
     'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh'
     +'ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     '896 bits message'),
     
    ('0c8324e1ebc182822c5e2a086cac07c2fe00e3bce61d01ba8ad6b71780e2dec5f'
    +'b89e5ae90cb593e57bc6258fdd94e17',
     'a' * 1000000,
     'one million (1,000,000) repetitions of the character "a" (0x61).'),
]

def get_tests(config={}):
    from Crypto.Hash import SHA3_384
    from common import make_hash_tests
    return make_hash_tests(SHA3_384, "SHA3_384", test_data,
        digest_size=SHA3_384.digest_size,
        oid="*-not yet assigned-*")

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
