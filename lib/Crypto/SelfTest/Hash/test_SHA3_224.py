# -*- coding: utf-8 -*-
#
# SelfTest/Hash/test_SHA3_224.py: Self-test for the SHA-3/224 hash function
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

"""Self-test suite for Crypto.Hash.SHA3_224"""

__revision__ = "$Id$"

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
# Test vectors from ``Keccak: Known-answer and Monte Carlo test results'',
# Version 3.0, January 14, 2011 <http://keccak.noekeon.org/KeccakKAT-3.zip>
    ('f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd',
     '',
     'Empty string'),
     
    ('a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802',
     '\xcc',
     '1 byte message'),
     
    ('f217812e362ec64d4dc5eacfabc165184bfa456e5c32c2c7900253d0',
     '\xde\x8f\x1b?\xaaKp@\xedEc\xc3\xb8\xe5\x98%1x\xe8~M\r\xf7'
    +'^O\xf2\xf2\xde\xddZ\x0b\xe0F',
     '33 bytes message'),
     
    ('6d735fb7579135f61b771b2bb0d81514cde9c977accf6feaf6edebf0',
     '\x15}[~E\x07\xf6m\x9a&tv\xd381\xe7\xbbv\x8dM\x04\xcc48\xda'
    +'\x12\xf9\x01\x02c\xea_\xca\xfb\xde%y\xdb/kX\xf9\x11\xd5\x93'
    +'\xd5\xf7\x9f\xb0_\xe3Yn?\xa8\x0f\xf2\xf7a\xd1\xb0\xe5p\x80'
    +'\x05\\\x11\x8cS\xe5<\xdbc\x05Ra\xd7\xc9\xb2\xb3\x9b\xd9\n\xcc'
    +'2R\x0c\xbb\xdb\xda,O\xd8\x85m\xbc\xee\x1712\xa2g\x91\x98\xda'
    +'\xf80\x07\xa9\xb5\xc5\x15\x11\xaeIvly*)R\x03\x88DN\xbe\xfe(%o'
    +'\xb3=B`C\x9c\xbas\xa9G\x9e\xe0\x0cc',
     '144 bytes (block size) message'),
     
    ('c1c80b60ecbe67b7a49940df5e3ee7f31c1304844d9a333a172983ff',
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
    ('c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8',
     'abc',
     '"abc", the bit string (0x)616263 of length 24 bits.'),
     
    ('e51faa2b4655150b931ee8d700dc202f763ca5f962c529eae55012b6',
     'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     ' "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).'),
     
    ('344298994b1b06873eae2ce739c425c47291a2e24189e01b524f88dc',
     'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh'
     +'ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     '896 bits message'),
     
    ('19f9167be2a04c43abd0ed554788101b9c339031acc8e1468531303f',
     'a' * 1000000,
     'one million (1,000,000) repetitions of the character "a" (0x61).'),
     
]

def get_tests(config={}):
    from Crypto.Hash import SHA3_224
    from common import make_hash_tests
    return make_hash_tests(SHA3_224, "SHA3_224", test_data,
        digest_size=SHA3_224.digest_size,
        oid="*-not yet assigned-*")

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
