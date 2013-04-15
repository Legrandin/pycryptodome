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
     
    ('93c6bf585e994b1669184ac71dc8e772b53443e668da0786d528090b',
     '\x94\xb7\xfa\x0b\xc1\xc4N\x94\x9b\x1dv\x17\xd3\x1bG \xcb'
    +'\xe7\xcaW\xc6\xfaO@\x94\xd4v\x15g\xe3\x89\xec\xc6Oih\xe4'
    +'\x06M\xf7\r\xf86\xa4}\x0cq36\xb5\x02\x8b5\x93\r)\xebz\x7f'
    +'\x9aZ\xf9\xad\\\xf4At[\xae\xc9\xbb\x01L\xee\xffZA\xba\\\x1c'
    +'\xe0\x85\xfe\xb9\x80\xba\xb9\xcfy\xf2\x15\x8e\x03\xef~c\xe2'
    +'\x9c8\xd7\x81j\x84\xd4\xf7\x1e\x0fT\x8b\x7f\xc3\x16\x08Z\xe3'
    +'\x8a\x06\x0f\xf9\xb8\xde\xc3o\x91\xad\x9e\xbc\n[l3\x8c\xbb'
    +'\x8ffY\xd3B\xa2Ch\xcf',
     '142 bytes (block size - 2) message'),
    
    ('bfe15bb51f680f2f489f0fdeb32f271090a09d1563f29feaf92104e0',
    '\xea@\xe8<\xb1\x8b:$,\x1e\xccl\xcd\x0bxS\xa49\xda\xb2\xc5i'
    +'\xcf\xc6\xdc8\xa1\x9f\\\x90\xac\xbfv\xae\xf9\xea7B\xff;T\xef'
    +'}6\xeb|\xe4\xff\x1c\x9a\xb3\xbc\x11\x9c\xffk\xe9<\x03\xe2\x08'
    +'x35\xc0\xab\x817\xbe[\x10\xcd\xc6o\xf3\xf8\x9a\x1b\xdd\xc6\xa1'
    +'\xee\xd7OPL\xber\x90i\x0b\xb2\x95\xa8r\xb9\xe3\xfe,\xee\x9elg'
    +'\xc4\x1d\xb8\xef\xd7\xd8c\xcf\x10\xf8@\xfea\x8ey6\xda=\xca\\\xa6'
    +'\xdf\x93?$\xf6\x95K\xa0\x80\x1a\x12\x94\xcd\x8d~f\xdf\xaf\xec',
     '143 bytes (block size - 1) message'),
     
    ('6d735fb7579135f61b771b2bb0d81514cde9c977accf6feaf6edebf0',
     '\x15}[~E\x07\xf6m\x9a&tv\xd381\xe7\xbbv\x8dM\x04\xcc48\xda'
    +'\x12\xf9\x01\x02c\xea_\xca\xfb\xde%y\xdb/kX\xf9\x11\xd5\x93'
    +'\xd5\xf7\x9f\xb0_\xe3Yn?\xa8\x0f\xf2\xf7a\xd1\xb0\xe5p\x80'
    +'\x05\\\x11\x8cS\xe5<\xdbc\x05Ra\xd7\xc9\xb2\xb3\x9b\xd9\n\xcc'
    +'2R\x0c\xbb\xdb\xda,O\xd8\x85m\xbc\xee\x1712\xa2g\x91\x98\xda'
    +'\xf80\x07\xa9\xb5\xc5\x15\x11\xaeIvly*)R\x03\x88DN\xbe\xfe(%o'
    +'\xb3=B`C\x9c\xbas\xa9G\x9e\xe0\x0cc',
     '144 bytes (block size) message'),
     
    ('6d93153145904cebe0e8a66c272bedf4f0d0a3c53ab30264135431a7',
     '\x83k4\xb5\x15Goa?\xe4G\xa4\xe0\xc3\xf3\xb8\xf2\t\x10\xac'
    +'\x89\xa3\x97pU\xc9`\xd2\xd5\xd2\xb7+\xd8\xac\xc7\x15\xa9\x03'
    +'S!\xb8g\x03\xa4\x11\xdd\xe0FmX\xa5\x97ig*\xa6\n\xd5\x87\xb8H'
    +'\x1d\xe4\xbb\xa5R\xa1dWyx\x95\x01\xecS\xd5@\xb9\x04\x82\x1f2'
    +'\xb0\xbd\x18U\xb0NHH\xf9\xf8\xcf\xe9\xeb\xd8\x91\x1b\xe9W\x81'
    +'\xa7Y\xd7\xad\x97$\xa7\x10-\xbeWgv\xb7\xc62\xbc9\xb9\xb5\xe1'
    +'\x90W\xe2&U*Y\x94\xc1\xdb\xb3\xb5\xc7\x87\x1a\x11\xf5Sp\x11\x04LS',
     '145 bytes (block size + 1) message'),
     
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
