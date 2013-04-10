# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_512.py: Self-test for the SHA-3/512 hash function
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

"""Self-test suite for Crypto.Hash.SHA3_512"""

__revision__ = "$Id$"


# This is a list of (expected_result, input[, description]) tuples.
test_data = [
# Test vectors from ``Keccak: Known-answer and Monte Carlo test results'',
# Version 3.0, January 14, 2011 <http://keccak.noekeon.org/KeccakKAT-3.zip>
    ('0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304'
    +'c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e',
     '',
     'Empty string'),
     
     
    ('8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160'
    +'b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9',
     '\xcc',
     '1 byte message'),

    ('9a7688e31aaf40c15575fc58c6b39267aad3722e696e518a9945cf7f7c0fea84c'
    +'b3cb2e9f0384a6b5dc671ade7fb4d2b27011173f3eeeaf17cb451cf26542031',
     '\xde\x8f\x1b?\xaaKp@\xedEc\xc3\xb8\xe5\x98%1x\xe8~M\r\xf7'
    +'^O\xf2\xf2\xde\xddZ\x0b\xe0F',
     '33 bytes message'),
     
     ('6b4b0f126863552a6f40f45e295dc79b9ba2a88ea7c3b2f607ac1a8431a97844'
     +'c2a7b664443fb23c05739df5494fe9824db80b7f3e67872142f17e2c5544e1ef',
      '\x1e\xed\x9c\xba\x17\x9a\x00\x9e\xc2\xecU\x08w=\xd3\x05G|\xa1\x17'
      +'\xe6\xd5i\xe6k_d\xc6\xbcd\x80\x1c\xe2Z\x84$\xceJ&\xd5u\xb8\xa6\xfb'
      +'\x10\xea\xd3\xfd\x19\x92\xed\xdd\xee\xc2\xeb\xe7\x15\r\xc9\x8fc'
      +'\xad\xc3#~\xf5{\x919z\xa8\xa7',
     '72 byte (block size) message'),
    
    ('3d370dc850bc7e159cee3f24d9e915b5b1306ff403c32c7a3a3844f3fc8d90e35'
    +'f56d83bdd9c637bc45e440e1f27ccd56b6b3872ec19101bbe31845108dce929',
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
    ('18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d'
    +'0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96',
     'abc',
     '"abc", the bit string (0x)616263 of length 24 bits.'),
     
    ('6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09'
    +'965435d97ca32c3cfed7201ff30e070cd947f1fc12b9d9214c467d342bcba5d',
     'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     ' "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).'),
     
    ('ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f'
    +'3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682',
     'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh'
     +'ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     '896 bits message'),
     
    ('5cf53f2e556be5a624425ede23d0e8b2c7814b4ba0e4e09cbbf3c2fac7056f61e'
    +'048fc341262875ebc58a5183fea651447124370c1ebf4d6c89bc9a7731063bb',
     'a' * 1000000,
     'one million (1,000,000) repetitions of the character "a" (0x61).'),

]

def get_tests(config={}):
    from Crypto.Hash import SHA3_512
    from common import make_hash_tests
    return make_hash_tests(SHA3_512, "SHA3_512", test_data,
        digest_size=SHA3_512.digest_size,
        oid="*-not yet assigned-*")

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
