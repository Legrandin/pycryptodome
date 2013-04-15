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
     
    ('fe5f30a315584092a271fdbcf4347a24d14a1f98cadc88df288c36cea8f89e902'
    +'0019933bcd4f5a7479e3e4a57644c49',
     '\x00i\x17\xb6O\x9d\xcd\xf1\xd2\xd8|\x8aas\xb6Oe\x87\x16\x8e\x80\xfa'
    +'\xa8\x0f\x82\xd8O`0\x1eV\x1e1-\x9f\xbc\xe6/9\xa6\xfbGn\x01\xe9%\xf2k'
    +'\xcc\x91\xdeb\x14I\xbee\x04\xc5\x04\x83\n\xae9@\x96\xc8\xfcv\x94e\x10'
    +'Q6]N\xe9\x07\x01\x01\xec\x9bh\x08o.\xa8\xf8\xab{\x81\x1e\xa8\xad\x93'
    +'M\\\x9bb\xc6\nGq',
     '102 byte (block size - 2) message'),
     
    ('a4e5ee130fc105818cd1a0de74f1085b9b4d93889c509dc3a208b5230d39d8f304'
    +'bb403f72bf0cf5e02c4c4a0831f328',
     '\xf1<\x97,R\xcb<\xc4\xa4\xdf(\xc9\x7f-\xf1\x1c\xe0\x89\xb8\x15Fk\xe8'
    +'\x88c$>\xb3\x18\xc2\xad\xb1\xa4\x17\xcb\x10A0\x85\x98T\x17 \x19{\x9b'
    +'\x1c\xb5\xba#\x18\xbdUt\xd1\xdf!t\xaf\x14\x88AI\xba\x9b/Dm`\x9d\xf2@'
    +'\xce3U\x99\x95{\x8e\xc8\x08v\xd9\xa0\x85\xae\x08I\x07\xbcYa\xb2\x0b'
    +'\xf5\xf6\xcaX\xd5\xda\xb3\x8a\xdb',
     '103 byte (block size - 1) message'),
     
     ('9fb5700502e01926824f46e9f61894f9487dbcf8ae6217203c85606f97556653'
     +'9376d6239db04aef9bf48ca4f191a90b',
      "\xe3W\x80\xeb\x97\x99\xadLwS]M\xdbh<\xf3>\xf3gqS'\xcfLJX\xed\x9c"
     +"\xbd\xcd\xd4\x86\xf6i\xf8\x01\x89\xd5I\xa96O\xa8*Q\xa5&T\xecr\x1b"
     +"\xb3\xaa\xb9]\xce\xb4\xa8jj\xfa\x93\x82m\xb9#Q~\x92\x8f3\xe3\xfb"
     +"\xa8P\xd4V`\xef\x83\xb9\x87j\xcc\xaf\xa2\xa9\x98z%K\x13|n\x14\n!i"
     +"\x1e\x10iA8H",
     '104 byte (block size) message'),
     
    ('f2e0ff6cf4801cff2eca1703e4e956c007a1f2709430f1f7a0a4fdd16a063522a4'
    +'dfb6c41fa529c2e325f8cdd4f8da96',
     'd\xec\x02\x1c\x95\x85\xe0\x1f\xfem1\xbbP\xd4Ly\xb6\x99=rg\x81c\xdb'
    +'GIG\xa0SgF\x19\xd1X\x01j\xdb$?\\\x8dP\xaa\x92\xf5\n\xb3nW\x9f\xf2'
    +'\xda\xbbx\n+R\x93p\xda\xa2\x99 |\xfb\xcd\xd3\xa9\xa2P\x06\xd1\x9cO'
    +'\x1f\xe3>K\x1e\xae\xc3\x15\xd8\xc6\xee\x1es\x06#\xfd\x19A\x87[\x92'
    +'N\xb5}m\x0c.\xdcNx\xd6',
     '105 byte (block size + 1) message'),

    ('8aeede5d6e2f9f1c7a6644a8da0f93574df8ca33b2ed9d364615e1f9cf1a801315'
    +'410733881ce0dad2f6fb5a916a97e1',
     '\xe6O>J\xce\\\x84\x18\xd6_\xec+\xc5\xd2\xa3\x03\xddE\x804sn;\r\xf7'
    +'\x19\t\x8b\xe7\xa2\x06\xde\xafR\xd6\xba\x821l\xaf3\x0e\xf8R7Q\x88'
    +'\xcd\xe2\xb3\x9c\xc9J\xa4IW\x8a~*\x8e?Z\x9dh\xe8\x16\xb8\xd1h\x89'
    +'\xfb\xc0\xeb\xf0\x93\x9d\x04\xf603\xae\x9a\xe2\xbd\xabs\xb8\x8c&'
    +'\xd6\xbd%\xeeF\x0e\xe1\xefX\xfb\n\xfa\x92\xccS\x9f\x8cv\xd3\xd0\x97'
    +'\xe7\xa6\xa6>\xbb\x9bX\x87\xed\xf3\xcf\x07`(\xc5\xbb\xd5\xb9\xdb2'
    +'\x117\x1a\xd3\xfe\x12\x1dN\x9b\xf4B)\xf4\xe1\xec\xf5\xa0\xf9\xf0\xeb'
    +'\xa4\xd5\xce\xb7(x\xab"\xc3\xf0\xebZbS#\xacf\xf7\x06\x1fJ\x81\xfa'
    +'\xc84G\x1e\x0cYU?\x10\x84u\xfe)\rC\xe6\xa0U\xae>\xe4o\xb6t"\xf8\x14'
    +'\xa6\x8cK\xe3\xe8\xc9',
     '206 byte (block size * 2 - 2) message'),
     
    ('29e62d8c1b71f826544a0cbfcdd99cf8aa1c97e153063120d295edf69e2ecb5a278'
    +'3c66760d0f87bf944516824ccfcb1',
     '\xd2\xcb-s03\xf9\xe9\x13\x951(\x088<\xc4\xf0\xca\x97N\x87\xech@\rR'
     +'\xe9k?\xa6\x98J\xc5\x8d\x9a\xd0\x93\x8d\xdeZ\x970\x08\xd8\x18\xc4'
     +'\x96\x07\xd9\xde"\x84\xe7a\x8f\x1b\x8a\xed\x83r\xfb\xd5.\xd5EW\xaf'
     +'B \xfa\xc0\x9d\xfa\x84C\x01\x16\x99\xb9}t?\x8f+\x1a\xef57\xeb\xb4]'
     +'\xcc\x9e\x13\xdf\xb48B\x8e\xe1\x90\xa4\xef\xdb<\xae\xb7\xf3\x931'
     +'\x17\xbfc\xab\xdc~W\xbe\xb4\x17\x1c~\x1a\xd2`\xab\x05\x87\x80lM\x13'
     +'{c\x16\xb5\n\xbc\x9c\xce\r\xff:\xca\xdaG\xbb\xb8k\xe7w\xe6\x17\xbb'
     +'\xe5x\xffE\x19\x84M\xb3`\xe0\xa9lg\x01)\x0ev\xbb\x95\xd2o\x0f\x80L'
     +'\x8aO\'\x17\xea\xc4\xe7\xde\x9f,\xff;\xbcU\xa1~wl\r\x02\x85`2\xa6'
     +'\xcd\x10\xad(8',
     '207 byte (block size * 2 - 1) message'),
     
    ('eb2f1bf2d9ee857b189318dfaf49dc3fad79501189ac9b5765dfb234ec4a62f0b'
    +'0e34e7ac3f494d6f05c7bb86ae5cda2',
    "\xf2\x99\x89Ua=\xd4\x14\xcc\x11\x1d\xf5\xce0\xa9\x95\xbby.&\x0b\x0e7"
   +"\xa5\xb1\xd9B\xfe\x90\x17\x1aJ\xc2\xf6mI(\xd7\xad7\x7fM\x05T\xcb\xf4"
   +"\xc5#\xd2\x1fn_7\x9doK\x02\x8c\xdc\xb9\xb1u\x8d;9f2B\xff<\xb6\xed\xe6"
   +"\xa3jo\x05\xdb;\xc4\x1e\r\x86\x1b8Km\xecX\xbb\tm\nB/\xd5B\xdf\x17^\x1b"
   +"\xe1W\x1f\xb5*\xe6o-\x86\xa2\xf6\x82J\x8c\xfa\xac\xba\xc4\xa7I*\xd0C>"
   +"\xeb\x15EJ\xf8\xf3\x12\xb3\xb2\xa5wu\x0e>\xfb\xd3p\xe8\xa8\xca\xc1X%"
   +"\x81\x97\x1f\xba;\xa4\xbd\rv\xe7\x18\xda\xcf\x843\xd3:Y\xd2\x87\xf8\xcc"
   +"\x92#Nz'\x10A\xb5&\xe3\x89\xef\xb0\xe4\x0bj\x18\xb3\xaa\xf6X\xe8.\xd1"
   +"\xc7\x861\xfd#\xb4\xc3\xeb'\xc3\xfa\xec\x86\x85",
     '208 byte (block size * 2) message'),
    
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
