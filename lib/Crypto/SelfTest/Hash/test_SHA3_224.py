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
        'fc08fb195d16069f6142b17450c587336b4bd819d4eabd457bcc69da',
        '7410a1bf7d2fed6db5ac85314540561715580c7afa36fb814bf9e4c3',
        '37d1f0667737d11688d01317737125535c2606b3613d8cab224d56a6',
        'd24a62623df3dc0bf2bfc8264f95a0fc8a962dae6f575999d1bfd156',
        '2798f250e65547170e11fe64e1b68394a00d5272cd77b3d2513f99c9',
        '1a474f9b49cef5fc18231368409eb80cb86b3c5cc0007a4f45499326',
        'd7b3f6ce06641760e31c8307b3d0eed9b2e4674751c4fc273911274c',
        '74ebb2bb5e8673c7812501c483421e979c71de6eaa7671f173c455a1',
        '34553202c086e4930123ba6866c93a972893c6bb351ed16066d1eebd',
        'c69a74abdf58b643d718a90770843c94e792f4fd53e7a0453e980907',
        '33d5c054cb291496a7842ae3c640ddf1f28ee92b04cc6d8745d955bb',
        'fe00ad642a8c7bdd47af8804e26c63cc5ab13b87e5b4279de034ae2d',
        '73c9744a31bf2195118c8a89801282718669d085ceb53912aef03f12',
        'b7b23bfde2d22d703ccd0d145dfffaafbf9d8c5c6a0279897e78a7d7',
        'ed2da11cab97c1cb9d2f7c705145200674f7fe092d10d11ba93053c3',
        '0466b919118acf3da57e629a7b241da75b0147c4fe595f0ca3bd0e28',
        '5b34a7fdd053c27f1a3619618f7783d47f7789d5ecfd4e253ccfa9cf',
        'aad6e69a4e8a1e72ad3b8b4b350f2a99fefaec58a01e193c36f45fba',
        'ff4ff1bcbb77e91799ffdaf627a6953d6b6b74b52c8d65e3e9f324d0',
        'd62b5124598b516fa6e8544b184bf50dfe5bd90c633313fa9e7de43c',
        '037cd29e87fe530e4f793c7a463b1be6fc84e8ee8e9ebe9959a5eff7',
        'daaae1a46fc3d7b29fea4e4f5f8e4751f616a90e9441380a64fcb52d',
        '585fddda89f2624772e5392e78284f0041c5d4a7946f19bffa758121',
        'a51743b2398bfcfeacdd6f5a0009a1c09f5394f8bdfc04b0f597a850',
        'a2c7f99d9a1a32babd9bd02a2891bb352ebfbae3ad646f8a84ed7941',
        '915139c9fd3163f67858fc241002853b1f259bbdc1b4fdb7aa379f40',
        '6e5e1dcdf49e47bb8c8afead2d8b159a57f39881ab661cc303913e0c',
        '7ed0a54abc5e3a6aa099c63173c35738c5d3c1cad041777fa444e0af',
        '275b0a3fa82d1a0b4f38dcf4cce5cd9abbe0d5b79d70b3b5a1ada571',
        'ee0cf8e5734c1eb01dce7b81763c3d7db8a2a8a6ce20a931716510b6',
        '9e43d46b4cf6bf15feed2fddb5c35416308fde4040e25f924419a2f9',
        'a01e898567efc602fad39f3c1501f8c6258bf91a089264c16c8b6e8d',
        '7252865617d6913b712a72a70daf365d772c045c4cc3dac653c4ff6a',
        'dd22df60b8c339dcdc4eb166c57b8aaec4301c3d202cc97804ed4312',
        'aed1c41095b4ba7933a333429688df6667c8183b19aebe2d4b64ce96',
        '9dc2a662feb3c4a44250f35718339d3aa8a2c270d04912d3c9f85872',
        '7b25224e05b494a5c736cce5c8c50dd009fd7a0e32dac259f30dcb99',
        '98d032f0d0e48b54fcaaeb476cd92ac35fa8010aa16deb4036a87607',
        'b3f4776fc97ee5107647657dbab18071d3e5359c6ee89ac5b0066fb5',
        'f461bcff6336792fdb63107faded55857c1c8bb34d6c9638f22d4d3b',
        '002b0bd2f038f18c712fef3455b5cf1fd0c1614d327e2fca52efb514',
        'af1b23d22d8c4cc48555eb8c15de030ecd27e4971c5f0d6c03c34235',
        '5eea9c1228ab125ce086db7cef81503ca2808bb7f8086a18ae71a42e',
        'f09ef043115d03e14d3a1faf461f7ecc98c9a3e1dd195fe3c2bda588',
        '3d055016399acf0fddcb02869d0c3aac2604ca478b3b9a61bfcda6a2',
        '88ac19e4799e6f82c3dad8204ac36a67c361a66d09c6b69680725bf8',
        '39efc0ce05a2ddf99939b0510308d707b1b2d50f115cd12cfcd008ee',
        '1c817d9a97a426fb85e4089bbf1dfbc8d4782058ad3c371c72b630ae',
        'bd7342b1c42134c03459ec3ae2986a4d22f6e5bf3b0b50cd36fc0e40',
        'be7162fd13b651a037aa98bc87f565be5a86f985188c4ba722b7d412',
        '7003fbc4932882d536beaba2d286ea76722d14a9baed787b466adcb4',
        '87643fa828011b2556d62f30a4bbe82d2703ea89a210c1c4a55c4016',
        '18c0251bdb57bb79a1537c10ec6bf38531154b972be7257a94560dfc',
        '2a332504e2d6d26b375ff238f9060ec3fe335cb76f50645be39ba33d',
        '48a04e12a0da5847701d505280f39fecbc692eb3742e0ba9e99f631e',
        '423c69ad350560584bf2a388ea35711a8b1b1cb0b0944016c1d1f6ea',
        '5512e9b93997be88c676ba88e446108e43bfb13ce6bb1d37d55a122a',
        'ed2580e52ad65996acda41b8bf2300015228b634d070537bbb5b65bd',
        '53b99ba0f0266bdd80dc15c4d6715daaef9ca0f044f5dce48fff5e68',
        'ebd4136ba2042ce11864010943011bb9bd801e0643ab419c66a971e6',
        '48e14e9803fc76487e71daf46e11e672badb15948296d66004bd3035',
        'a6406b0871698ab3da585ee215887ecefa37bd46cf619c2fb04a6646',
        '8ac1015f056f3634e7087bdec7c76e1cad9c26451bea488d22f16ad3',
        '8babfcaabfa284f10aed5328f376bfaf3468fbec97cf8ea81c2633d7',
        '1f51be11b575ef2fdf247ce819f0feaaa12eea74ce1d8540966a282e',
        '684b8ec77c4f6f4cde90fa45ebdd93f04888ff81fc3bb0d0fda340e2',
        '035129091ae8c21771a3a851af15ee0d4e69e7c6e645e931b0e4a50c',
        'c507b85e35a365502745e459fc0f0e4d418385613af0111c9ec718e6',
        '644a1093ac61f98dea5194ade993d42eb613fc1048cd6b90967050c7',
        '13beb337f08d2b6ea32c99de2038cfb1be56405a7ac7acc98da17a5e',
        '77b2dcb36af72be856f221153b2e4a29387e2aa506f0db238d7c060b',
        '0252b5f2e8046cc1cda83008f1ec56c0139f2c5f54a731d2f4396c4f',
        'ae0cccc1b64ee4ed104ae52602931d013b2fde62aa9164e8ae6011e7',
        'bcabacd1192c09a7abc4b54b663761831145bb0e7cd390a57e9c6239',
        '67e418f7a9ebdcdfb851bcd00801b0b3ef04ecd93f38040fae2afbb6',
        '1544e6f6698ef41a3b7b5050a1a16c7b9a19a773fb082d8b450d93d5',
        'd2ad21aa3842bebae901680b38b08fecab8c3925af804e3a3f7a548e',
        '3f55e6750e8dd6f8d01e9c1d3287c54b5be3887eb3452de0ace62329',
        '8af3e0a17c3370882ac84e73055fa07df5b642b292d5e754e2127893',
        '7dc3e4fa77ce7cc1b3e690dbf26341cd339e8d2944f6447116e3d5cb',
        '6630ebddfc64345cc7ae4aeff42a05b5e6b5950e65e74f25539406fd',
        '0a5fc26d928fe0f2517181c99c79da39c4cc9ea052c1790622ee81c9',
        '760cf92707c12f6c1c0463f5ea195bf2c6d5a80dfcbd54a6d3d48d7f',
        'a9cd6e9a9b74a509d9fd39b6f91602faaf3ae07bb14f942313743b6c',
        '565fd8a3b2177100d1ae6edc39bcafc106a19e5a27297d3e2681568d',
        'c34a8c01ff70d77a3b6355440dedd4bfdba641bec8bdfc7273382309',
        '96850e802123009ebf505f8b22d2ac5e724856555c3c1a0b9cf4d8d9',
        '342ce4d679cbaf9ae9aa4af1e75b0222162bfde45788145afa2be07a',
        'd2909fb064eab1499a98f97a92e4f24db05ce533425a468e991c976d',
        'ed30d042316112e4897373406bdb57f19c4b359f7cec7a698204063f',
        'fedab5d66007a6a4383380a25937f6c271017d5d7bb9f2ab45106537',
        '7aff60820200d3c54599f7db8f0ef2abfd56b3d53ca22311e9cbea53',
        '009cccdc50608c0dba53110bb1ee093ee71d27330e59404bdeb68200',
        'a5489cd08e017f79c47e45224b04bd90b59382c8868752fa9e6c4055',
        '8c27a759ffdda19c1a210c8a4449741f7cd3c174eea923706a2f8282',
        '8c011007246cbf2358a61156fdf052d946b9f94536588b18ef128d5a',
        'f69b96785a4e75544fc62182c63a4b534ed3f52d432b581924812623',
        '72c2de3843a51121a5a0ce8bc848412da8dd3b6e5ec3804388eae328',
        '4c21150715813100a2e4802fc041a2df36e8d07f5b5a7e6ae036fb07',
        '11d978de9f5c134b434e98e631272066e86bb0f5b07711f2a41ef089'
    ],
    1000
)

def get_tests(config={}):
    from Crypto.Hash import SHA3_224
    from common import make_hash_tests
    return make_hash_tests(SHA3_224, "SHA3_224", test_data,
        digest_size=SHA3_224.digest_size,
        oid="2.16.840.1.101.3.4.2.7",
        mct_data=mct_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
