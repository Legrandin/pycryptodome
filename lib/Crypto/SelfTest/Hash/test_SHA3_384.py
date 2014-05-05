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

# Data for Monte Carlo Test (MCT) from ``Keccak: Known-answer and
# Monte Carlo test results'', Version 3.0, January 14, 2011
# <http://keccak.noekeon.org/KeccakKAT-3.zip>
#
# This is a tuple (seed, checkpoints, iterations)
# See ``Description of Known Answer Test (KAT) and Monte Carlo Test
# (MCT) for SHA-3 Candidate Algorithm Submissions''
# <http://csrc.nist.gov/groups/ST/hash/documents/SHA3-KATMCT1.pdf>
# for a description of the methodology
mct_data = (
    "6cd4c0c5cb2ca2a0f1d1aecebac03b52e64ea03d1a1654372936545b92b"
    "bc5484a59db74bb60f9c40ceb1a5aa35a6fafe80349e14c253a4e8b1d77"
    "612ddd81ace926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9"
    "bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1c"
    "b40439d835a724e2fae7",
    [
        '875aa5adc9fbd6578faf297e29d30c7a1ebdaec4206dcebe6c1e8dec49c349b7d166a64061d1c176dc36bfd2806d34f4',
        '57aa4a97795e48c76c552c4f703a15fc45e522cdf04b059eea6fdb48d4d465016ae1b2323d7e47b79bfad3383cde855b',
        '53da39af8ce58044c1a9a5c0df9b646d34fc8991379e6fcef38667435211fb93d158c6e2c846460555994b23b71494a3',
        '1c1604bacac3f5aea63d9a434db6be290fcc91513e0708b0a0728c8661bcabf7a45110761ecd8dd4356882ded0705e05',
        'be15a2900e6b154e165880df07fdb0822f129563abad967a364d475ecd4f02d8bed832f17a96bf6eb33584ac7e57b5f3',
        'c91df80d4e78026846bd75b3da3c1a758fc2935a737988d884fd4b5fa7bce906262c67475aa0590f9cd398712e8cd339',
        '4d3f2633348433bc3534944d327895945f71ce072cb07537ec77fd2d51a1b299f41de06e2d744450ea077b61b2f6f176',
        'bd1b83af08eca70832661e20fa9d0a381402cd2d9dada7cbd194ba0288c99df7ef018f4b5e0c07dd8e3b2decda42d908',
        '62e6ac7b623a5f6688d58413b4f48eeb3962bb5225dcae470c5982ecc4b751d0d59765367cc149f6f4c22ac93f65a92a',
        '76809e1fa739ac59aaa37db9a7350c31530bf7b83f350510575982c9c868d75a6da83248a90b4f7642c6521faab81ade',
        'cf1e6b7e0644ec68716a924a27f129dd6d2cbcb5e75f3ee5b5ff33a79bc972ef4b2d173135cee671121ae0883bce2dbe',
        'da253dc5c7e1b2c4d4b402de79ced6d85f8d0933daeba00f54fe77ec12270f23bc7e0bdb8110b38e1ece72aee0f18324',
        'c8e59586d655d6e5658d2f586b1d1a22b59de23af1da046ebac7705dab600900ac6e0f2299c1de4cf27ef3ab083a1165',
        'de2dbba2478a9954435965f38ed9298cf3b46a2bc18f76f4e1f552a2aa91573077b1cdd44b5f7b64f7a7f6fd8999ed71',
        '9d78b210fc8bdee797538fc2ce744522ce6380687c4528a6a35993fb9c9c73324be508d7673197712d1122a874a39cf0',
        'f24c5bc0c4ee07643897f229b1234cc19d0c76ec099b3f4d4815af1d65dbec633689edd8e5f76dc729b6735f892c1a5f',
        '2c6839dd63b9b30e060e8f089588ba9af383dedafa0d09d276b72ee5b44646c6d3adf7b211e6fd02a270e6df8b59f493',
        '0ccd9e1ec8665a0acbf3fb391126e61329d43dc22809b07940dfd0f76ea2d064238d6433708cc5959cacbd4bad4d7933',
        'abfa3cf3feabb66eba194d8041c5d3b7d8014d8ba554aca56eeee467db9f7f80c77e9db44731fd3e2421962f174ea51b',
        '6e925d4c4e3d1c11884107dc1ce1b2fd7f609f2d0c15e8896ca7fbaf6103e50dc069a0d57e30851e23d4a67cc03a4e93',
        'ba428505f819cafd954b11e05e1c565eec46653e7fd65f9d79d6a317aaa5c2f3cad6192ec1f4ec36e3ea31dd012426e8',
        '281be8ed31f5e1cbd9ff9c796196f92ab232b26c53babad8dfe82c116fd4999c32cb88b535765ab879478b8c876dd686',
        '632f9d677a0811a98a2915fe1a8731d03022bffc4b473bcaf6d004059421e6208a85e5c712d2fc0b774faea5a57d2a79',
        '46bfcedf0484560f918e1d61a6d7757e93937bb0456a387d4588a4c3147d90fd0d9eb251faeabec2b0f80e284ca75b12',
        '9c05300f596bb171b5f5ee3054712c5757a847e499cab2513374818cbe0418de690ca6d623726c5eeb1deab4e3d7aa7a',
        '00963a2d929e9035301fd1e996577034f3969a9101e28da6b9accb0e74194d6da1ea2213e35c1813061b08112db0e1ec',
        'f14e63b54cd6edb145588dc5d89379e10c6ab16aaf117684d9d8a7c99b5bf91bbdaabb31e6de593a838ffee7512df17a',
        'bf3a4e18efe232818dbe84970b28d8b80c07e1539afbe184f3a7dbc640cb89825f2beb116669fc613134f71621e9afed',
        '5d0028433e185ee78cc767dca6636413087b802053919af8849145baab35fc9f14a0b044376b1d931188a2b67acf77e8',
        'b47844724e15a8cf3b67b2d699b7ce64809d8beddc19d40812c0bed42e5f27540f8eeb5bb3b2d37eab80687751ffc37b',
        'e63529d2fd4310d39a9338cef115642a9c659de5c257d42e78bfe24b5d2ebcea5c3a98243de74b7e69b11e9aacd14a1f',
        '6a59b0776fb98630c6700d7987c1788da470f57e6461162409b79066375f70dbbac0d16cecab97bd211409ef71d8605a',
        '95dfe5d5ad9f7c1cfd14957e4d880ae4f700368a734ff47bc87b5b4f7d717681b4b21b23c9e10d91352a8800529fac0d',
        '0e030dd353198c96b85e3d8fc0f137848288e776ca98ac602d16a264feac2243f42cb5d58fd16ad7f2408f799f7a5793',
        'fb48dc0fc3aebe78b28043c7d20533ea26337fad7afc40842d05be34ba2c10f9a44999786bdd7425b628f1f1fa12bd55',
        '53b7df1628e33e2da51ea9103c46aaf4ad10830f47239a5cd5e98572d114114dc48c3a9516422b6df8c257cae2cf19e3',
        'b4299780fc21d5c4b0a6a616803dcd4dd0c27c3330478bceee8383f91cdcbac370fb497e708a109a4074eac2498ee498',
        '6cd32463bf09cde5fafca657199e7d1595d7d8dbbd123ee9c1446fb4d05e874886a6fd5bfef04ca6324d4b032c8c8c08',
        'ec12c8722b225d4b72c4df9c772ef811e94fccede4112410f5e05397e85ab96c1e895b92f3ddab5fb54714141d884242',
        '11c8abd4a6347e6f155f9f4d777b23d74096c084c5a7db79b42609f86df7530238051aa878a358a028d614a196e74ed4',
        '9ea17707580b1dcda6a4b0ffc465e5f3fd20625a562e98326b54bcc1ccc26b0d7348d551f5687ed4a58c00319e9dbe00',
        '5eb5e5663d6b539c86768ff30e29ec88f4c1d499b48de3a771694eac912eb0aeffaee2bd48ad07427287866edadc407a',
        '3ec0f156bad7385162e842ad14fbf3daf1449b92fd2472ab6559c37f3893904c4b9a011ec2fa54d7afbce1524d5151bd',
        '3c45d9df5f665eb89367641fada2cf9c912ecc5bf2f8bdd8c4ab39936f4d117e14bad970ffc2dc85b183c8a62184f06e',
        '5cdc250d80088d18e9572eb07648dab78c9b8f80ebb30603f3a46c077f773a30ac9f2a17f3e7a45c08bca0354d6ef551',
        '79b8f5c809cd2a2753a71af2300358cd6e98a3a40f0eac2286ea31d34d6f19d28ff7052710e501a2658a2ea421961632',
        'd5685b3a3c2e806843f401ea7edd912a890d90ef332ee57cdf97eba7cc42c082c06799688a779b64f81c1ac1bcb0ddc6',
        '3c6168b337133e4eedfb53a743d63f23ba395491125cd780a1fd5b16f7f7e76ac6b7f3d57458ac85ef56fade389a6c20',
        '74c54a2f0aff0a3657e450a0ae48816106645a076c8bf62ff08ad678a4008f972ce86f10a4c9e4b01d4a6e0ebd63ca52',
        'dbf67091f0a25d14aa8a1046c0df35b5ab9b8765cf8428f3b66c360a82d13a4fc81676927c7a24e6a7413b3e8b996c2f',
        '62044078b84fcaa1b23dabfd441aae264923939859d566cda2c2f3220b514bb3d1b42f81f5d2bd2ea2e27039da4118aa',
        '373138ba3b97a9f5581f1635172d841f5eb3e73df90cc303095797e30d4d3d21ceabde79776cf27ff1b34481e010e41f',
        'ab485e49a6f81da2e85c9684edc5d3ae19899d63145900bc2397c7d253869528e17f73de2932b8e578374931f06d4a06',
        '49d5ad6a04cd9661831f862068d17ab8d80846d7233e312065f2b1a7c25df74bb0e69b7ab002adef316afeff5b438eea',
        'b482cc6112fc8ca758f878f5047fecc7ea96fd69d684b4d6c6b98a9839bd22f9b1e1f0acc6e200d1ec0ac87f8f81b97c',
        '79bc8af55e1e3874306088aa194686b40ca1dd36b53481ce9e6f3b8d156cf7cc57b0e69ea81c4ab73f26d3ad00d95fee',
        '6ea364c153530af51c34209a1ae774594cef7684cd15123b7ee4cb095e5e96b67038a6df1daee1a8997136c27e0876dd',
        'b7c5063a7acb8151827524e34df3cc2943c04836bb86927c9c11df1c6efb1b894ed651143efc55fd6950c1b2f5c447a5',
        '15162b2a65e66ee6f8217630364e644dda3148f9f1e151299d1e16530892b1ca85a6875455abc0d4c71b128f9f3af84d',
        'a0595077621ffc823f0ebcac88efbe00a9abd5a62471831d88be4590d9ccce3e99dcbede8283cefe053b347bfc1e30d0',
        '3f4d8d6c72d822887a267f155d3aa7ec47e1066f974948f74c5987daf04d3749b0874e2d912b3884b62d29faeb41ac2e',
        '7b3fcf1ce743bc9582fe03492e63ee514d49f025bab938063051d731d80c347bc8a7d7211860b6cbb4c23ac82729c2d2',
        '0ea1152f7f006e9aef34476668418452e182b7ac741698ab42d3b81ead61c03992e752565f9fee72ee95bab775286997',
        '403ed10aee31d217ff5739b2faa5254c3639afe251a4d7d15cd454b386b57370a6c758d496b4e71d88babaf530e11f8b',
        'e5d90f86fdb2b7263c2daab05159752bf301cbbb570b73b42ad70ac070f0cc9e961326fe7eecdfd88410391f75abcd63',
        '947edd7c6cc5f4c2ed064e554ee97f17673a8206a8d707ca82dfcee8b006a9da6f2aa963b700d7460c52293bf5e1591c',
        '6a971e3cd22a0797041d70051e0ad2942aa728872ca8d878da75656af6a58bd6f02e0c4e596c58e3c69d4c971da5453f',
        '15d231946b0af6f2e6ea524d9a5217eec6a4ce77472f919e091c9588e8f9a50638e3fd7c78b14f9054a373f213a227fa',
        '7cbecaee3f54a288fa41b1e0f8f476091c05c971213f2276447b1fd08ce11631bf8218dd58f2c72e88ba8bb984fe5df2',
        '2844f632a1416dc3061a3354b9af4710a81449b9709851dc592ef1a8fee0c647e7a66e2252080568ddec97d166be020b',
        '8fc80ddbefa5ba5187ee9b23c2b6090385571e4d5a26afd4511ff72c215002da59f26288fdb53cd080c45b6d1621254d',
        '0a8ad0337100a07157970894664d4a0a55fd47392f67c18a6ef95103263d9efa03cfa95e5881f99188448d8374b9730f',
        '949dce8222c86682b5b43e021d837fd88d1790d8222bfdec75238c3cc1e73a4d8bcc58f10e3b346ad29cd1bcf9f4d261',
        '5464792b02c45a1c85df4b7bc974842b320421b87613ae3936fbaa7fd63ea0a3a72495f54470233db5e9fe4f83342115',
        '8c72ad922298c6a1873f5c3dcc311a5783b992450ec62db78f225e198f0aa4f2d0f6be3f894a6371184473b32d7536b8',
        'b72b5441ef3b2f4be69ad152b1bee507695639a79735467da2a28b4f9a8c314e4726588be637561efab8134690b24a3e',
        'a2d89330ecab06ecd427e9348c1454510ffefe171141f8bc276608dc8ac92316e97abd1500ce0a23a21749657e17d1db',
        'cad257a269c483d910eae191846a00d51b0c32c6955109fdd6f72c314a166580f5cfa46f603f8ce6df0972701c7e4ae1',
        '5dea7bb8f22f70bb1540fbb24bdc1722ac5871c18e996412ab07c3613421d0462de759405f6ea624ac5c48e89f2fa858',
        '30935b72dfd0989b0aeeb13be74115ded5283dc332721be5f7401ee14b8ba6b498609319d86118d9a6c68068bbaa556a',
        '349478b336723d3cc7db7b82181f0102a2591336618543c7c8d2185965228afb3500c5e0f6900f16c15ec9c1dd6837ff',
        '8c1e8bcdaaaaa1c357c2103a4c1b2cb2367f57c7edd6c07b75fec5fa08689e339474924bb164163b09338a7c444b621f',
        'f9667ee8a7fcb4944ba6ed8ddb57786be3978b9e81961b15578192cbd530789f27efca8568c3bf2c94d10bf917dc292d',
        'cd4e7f37d02a9178f1c0422cd0c027bfe572f571073b977dc4b8434f76cfff9857360c2e9291e6d66f7775ddea4ce336',
        '4f56a8a7fe43837ca1cbac1ede6fbe55adb183701fa169fe55f9459302a1b7f819dd3c5e08cb5a2e43fe01c75ea282a2',
        '6765a20c7e4f90424770b4dc10f288132f4ff34f4088756e01f97203cacf5c9cd680ec4a73d3921506beec214fc0ce3b',
        '3026721c2e313d98de71f3b4619e9c452113b6ce780d8d4157131fef1d6ccc6a146aa7ed37fe90c1d25837c32202e586',
        'ef6a799c87fed4cb15862031916c83d1d4237901c4605d9a8fac93c15fb4ddafaa89104e37c6f0687e75238f153fafc3',
        '6d5af64055ce131f11c4a43d0c34a70e4bdea8f976154084afcf79a61d7563c1a8f1fb943bf589e2b3fa84ce3754ca27',
        'ebd8f340ca94ec0385346f8a2c6263b1b7459a5788328a19b2d62267d9339dd1f51b89cbcfffbccde68c78a852bf5e77',
        'f83e03ee0763f45a95a8255cf944bbd56911e25a6af1a1de984de0bc7c6a6388898d75c0864dc64be6b9b6687abb9334',
        'f6b85110c16bfd213f2009060f06deff85dfb03c3d635fa665803a0625ed25c8c6c43fd0e780a7513c713df7cf66be7e',
        'cd9050ea321713b140cfea91aff8c1b9f9f0aacc0decfa150445cae68ad171dd1650c0971268ff63bdabae4e25542f62',
        '18b26fc9a97e0c40e2a62a08860c6f33d7d765db649c83c19fbb6ec7f18c89e1dda7e27efddebd3e68d6d37e747a4e93',
        'a2cbdf59eb23af8c26737572af5b2bc961a00ab612148da2b626969a2c5d0a1265d4012a6695bb500e0e9b3113d5909a',
        '00a7b7889fbafd85ec19e0c16195d893ffc31c8a20b910f5b9d63d15117ca71e7b6e41b3aad309fa47fd2e3fdf1cab3e',
        '4fd0048a22e484c1a6cc2273b09c65e10b262a1f8721027a316ff046d01bb9956e87a6827914146f1c52f02f1bd8dcbb',
        '2d446f9d009f6cab7f5cf1ec348c164461cd5d7e2339229f01748b87b5d97fe9932e3329a7b4daa5677d473ff8236f29',
        '82e56708bffb11714db3aea49e70411b91575c540c780708be4a4d08e4af2e8a10f388987775a337ed028574492efb80',
        'dfda2ff783b6ff797d96f27a78c025bb5f7e9a24c306171d8091aaa0b79787beec1d488972f70b58c74ff08d5bca911e'
    ],
    1000
)

def get_tests(config={}):
    from Crypto.Hash import SHA3_384
    from common import make_hash_tests
    return make_hash_tests(SHA3_384, "SHA3_384", test_data,
        digest_size=SHA3_384.digest_size,
        oid="2.16.840.1.101.3.4.2.9",
        mct_data = mct_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
