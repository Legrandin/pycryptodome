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

    ('fe71d01c2ee50e054d6b07147ef62954fde7e6959d6eeba68e3c94107eb0084d',
     'w\xee\x80K\x9f2\x95\xab#by\x8br\xb0\xa1\xb2\xd3)\x1d\xce\xb8\x13'
    +'\x98\x965X0\xf3K;2\x85aS\x1f\x80y\xb7\x9an\x99\x80pQP\x86d\x02\xfd'
    +'\xc1v\xc0X\x97\xe3Y\xa6\xcb\x1az\xb0g8>\xb4\x97\x18*~Z\xefp8\xe4'
    +'\xc9m\x13;\'\x82\x91t\x17\xe3\x91S[^\x1bQ\xf4}\x8e\xd7\xe4\xd4\x02'
    +'_\xe9\x8d\xc8{\x9c\x16"aK\xff=\x10)\xe6\x8e7-\xe7\x19\x808W\xcaR'
    +'\x06|\xdd\xaa\xd9X\x95\x1c\xb2\x06\x8c\xc6',
     '134 bytes (block size - 2) message'),

    ('bd6f5492582a7c1b116304de28314df9fffe95b0da11af52fe9440a717a34859',
     '\xb7q\xd5\xce\xf5\xd1\xa4\x1a\x93\xd1VC\xd7\x18\x1d*.\xf0\xa8\xe8M'
    +'\x91\x81/ \xed!\xf1G\xbe\xf72\xbf:`\xef@g\xc3sK\x85\xbc\x8c\xd4qx'
    +'\x0f\x10\xdc\x9e\x82\x91\xb5\x839\xa6w\xb9`!\x8fq\xe7\x93\xf2yz\xea'
    +'4\x94\x06Q()\x06]7\xbbU\xeayo\xa4\xf5o\xd8\x89kI\xb2\xcd\x19\xb42'
    +'\x15\xad\x96|q+$\xe5\x03-\x06R2\xe0,\x12t\t\xd2\xedAF\xb9\xd7]v=R'
    +'\xdb\x98\xd9I\xd3\xb0\xfe\xd6\xa8\x05/\xbb',
     '135 bytes (block size - 1) message'),

    ('e717a7769448abbe5fef8187954a88ac56ded1d22e63940ab80d029585a21921',
    '\xb3-\x95\xb0\xb9\xaa\xd2\xa8\x81m\xe6\xd0m\x1f\x86\x00\x85\x05\xbd'
    +'\x8c\x14\x12On\x9a\x16;Z*\xdeU\xf85\xd0\xec8\x80\xefPp\r;%\xe4,\xc0'
    +'\xaf\x05\x0c\xcd\x1b\xe5\xe5U\xb20\x87\xe0M{\xf9\x816"x\x0cs\x13\xa1'
    +'\x95O\x87@\xb6\xee-?q\xf7h\xddA\x7fR\x04\x82\xbd:\x08\xd4\xf2"\xb4'
    +'\xee\x9d\xbd\x01TG\xb35\x07\xddP\xf3\xabBG\xc5\xde\x9a\x8a\xbdb\xa8'
    +'\xde\xce\xa0\x1e;\x87\xc8\xb9\'\xf5\xb0\x8b\xeb7gLo\x8e8\x0c\x04',
    '136 bytes (block size) message'),

    ('a95d50b50b4545f0947441df74a1e9d74622eb3baa49c1bbfc3a0cce6619c1aa',
     '\x04A\x0e1\x08*GXK@o\x05\x13\x98\xa6\xab\xe7NM\xa5\x9b\xb6\xf8^kI'
    +'\xe8\xa1\xf7\xf2\xca\x00\xdf\xbaTb\xc2\xcd+\xfd\xe8\xb6O\xb2\x1dp'
    +'\xc0\x83\xf1\x13\x18\xb5jR\xd0;\x81\xca\xc5\xee\xc2\x9e\xb3\x1b\xd0'
    +'\x07\x8baVxm\xa3\xd6\xd8\xc30\x98\xc5\xc4{\xb6z\xc6M\xb1Ae\xafe\xb4'
    +'ED\xd8\x06\xdd\xe5\xf4\x87\xd57<\x7f\x97\x92\xc2\x99\xe9hk~X!\xe7'
    +'\xc8\xe2E\x83\x15\xb9\x96\xb5g}\x92m\xacW\xb3\xf2-\xa8s\xc6\x01\x01j\r',
     '137 bytes (block size + 1) message'),

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
        '070a4221bbee9511e927a33e5d6cf8c1f4375631a14dfd110f27a2ab1ad0b195',
        'e7416697e7165be86a06f6ded86f2f418b83647bc346a0e1f7dfa22cf621f1d1',
        '5fd82dd2b8f5dfd7f0b565253ee68040d37fea7eb2d3adb83a434ff5fd7cd383',
        '49e346f958d844f76f303b6e5a909b513c69e78c833ac591b78fb1a2606aa249',
        '5d4251cdeb9cc18ee17aea27e5f1ddd86a30bd1f4beef7b2df58aa78dcf3402e',
        'cb358bcef5cacd4fd64b1d997e94196e111d3a2bb2152ab5046725b823b6e019',
        '29604eeaae593bd88efcb734a075ab1a7f22d5256a885a0464ac5da0fd84780d',
        '736986428bb415623d41c0b5dff06f501747a73b419d6f5af8a9ea8b0ee40281',
        'c7cea9dec797d4a901dd8af683155bfa397a800782cd546e9f44a451af70f392',
        '2aa5fd1179651d026db31cddb590f95ad0d29280ec4aa145a04186b03a742217',
        '831ad168a555842ae45e71f869f26ddbf4963271ddd67f8d0dd545c9fa6abef5',
        'd3741dc12517c0813140d26d8eeed187856fe2e4c1379e7ddb20ab07a2cbfdf3',
        '33a6450a7d8743b1cf0b852a734aa859b43aa722f1ec92ed10e869b8d233b737',
        '60a243a68a287bf71ba335ee001c25d9581dd05641be9cf82bd1dd929b69c55f',
        '4ce83754271fbffd2d5d1d1f1bb81457f38bf97d1a6837065f54f94a2b259652',
        '9c8d8999c97a6d7380de3ff5eec08118fef5fb62b858bc8f21cc1ea886853e4f',
        '1e814a83ed95af896c3d57f2ac2e3cad40ce996bb1b92cc1e2061191d291d2a1',
        'fc68d4003628d0ed5440a7c79821ac3d4dca44af3e942e081581f5d06f134c1b',
        '61d944cf3b3819f08bb0fbebb50a2e0b9d8f580abbb70c19f457834f792087a6',
        '4ae59ef443058c00a46d931f7145907e28432d0d9fbece584be7f07b91570344',
        '18a45e44aae1067328a94fd59186e6b7c7a4df521000e2f4636598c6915e2ff7',
        '58c0b047f6df544881c1ac5c362b827787aa832c1503a8e2c289d3e9883c04a1',
        '0cc574ae228c2680f96e3a40e66d534f8b655b7ea33175ff330376f5831a804e',
        'a8f9a0cd826fd2fdf741cf5fd969e05a2eec829a60e9e9b8f21b87d2e49d2578',
        'f52e564386ae1d775b79a5cf7073c03aaf53d489f312d3fb7ebb48a76381adad',
        '836a0b1e5f494dc51525ed4c0deef3c7ea172cb6bdef1d13b64d14f68b2bec00',
        'a254fe1d6517bc45b691dd55956108fdc6492ea438e6d9114dd945f42b09740d',
        '70af21450e9b4d8dc56463d940fb9a43ab1386214164dc12b76bdd72d809657b',
        '163e5adcd37bfc3e7c6b3820dacd8700c643babd1fb4cc55941757ef9b76bb8e',
        '0b574e3cae62f27f287458af92ffcd7680ab28dc5d4b00bdfb3aefe37b153b0f',
        '2eede76ff8c425a8be6a6d99ccd49d4e95290d804e9c3fc5cc59dbd9e7bcbe60',
        '2ffef8468ee4fdd2499be00784e244dca5684b348511dc56f7d4e0ae0f83bf3f',
        '7a2003733e9d4309781dcba27d6e0d391accb60a5ada43607b10ce1d6c7e37e9',
        '308cbfdd505eccd06a44b9f442b354832a037563049be44d387c7e9cab0f2d8b',
        '1ef1cc5e6bbd6e83878ccd010c415e4703dc9084eac40ebd5366fe59029c31d7',
        'a3059633585621ef838c3dccc50eb7ba688fb53d22ff5b5b53139e18586b97b2',
        '1047532937b428d8d0979fdb9c63b601559e5cea56d43df9f4cce2b9862b857c',
        'dbe2aa7c02615bfd6c8c984b72c35399764b02b50937407a82ef78edc68d18de',
        'be80fcd5298c95df386ebbf26d8fbca356e5c5288cf11e94cb570edf28578334',
        '5d7935a4b1a2dd66e95ed7d7da55638554684926c899ebc702f23e2d8c0f69c8',
        'a429c6e750d94457080b7ee7bb748955909359d672ad261fa6108c4f0322c613',
        '77e056b7c9588e141cb181e0e2030f15da11de5d980ce1ddd4a17c704120d2d4',
        'dd5e08664cf46e9129c097a9349215d6205d4de4022af4466423fed045b4dc42',
        'ce50bd27c442249893147fc2c8ab8ef1f0ad3cd0a147d0b909943313fccb5a44',
        'e0ff70937a7d8c6c3a3a665def8f589469e38165e91d7160fb19cf42efee12c1',
        '4295ee89f13d9b8aa0726fc16622bee6d212e0a57fa55f2ca013a6f615b99dae',
        '717d35a33f0eb8a85f90077b98ee0bc5cc9a6551c76629c3468bf01bb68dcfd8',
        '948652d7170594d307943b1ac2b9670ba997ce13e093b8a5e8a448a9938df1f3',
        '08c4d552cb2b0747522926a6f6e38b79e943502b4e0b879d3ba73d6b02c7c14e',
        'c7dcbfd0ce1079f118076f31515d5493310c301d74d398a759ee5bfe71bf6de0',
        '41d30edfa2a69e6c1602ceff9e40c585480525e08895afeebf9be4476850be12',
        '172d0f88303560be497c0d31bfc5922c2d28c4b008a2be1b9caf8b1a4567f1f1',
        '933b048ce59132e138fab68be0936576ffb7406e2cd4d76df618d5234f63ce99',
        '109637c268a1dede585b6a7dd435a61af6b426a6152c99a6479b7d7e168d169f',
        'f7d01ab1a0570e739a0271f6c7a6531d1a65673696d6c47d04a64b16ebf36cd0',
        'f2d498b238124f7b27714bd7fb8646e522b5162e909441d3315fec919f05dfd1',
        '0b27178ff2bb084b36ad1de66390c3c82f622641713ac3a91d91b3e806235911',
        '76fdc3e65694508231ce2a1fafc44778b862907a37040b80f27cae1d280a711d',
        '7a34da644e2837f63fb2f7c4f6a695d8cdc95107b128aef27ddf10764d92a6a4',
        '9629804fc960c5cd6d00c696acd9230b4991feedae787bad8009a05bab5c0b4f',
        '8aab62933d4f7ac42777024d5f33e70a919b4726298da2fa3f28f9060afc8e0b',
        '121c1e9e1c8a39d107df4a6613d180baf7686fc01d513260c94497d24d1b0035',
        '03cb5e13649b2e029ee30125b974bbb00b18ceedc9ee8330c4786cac07befd50',
        '5d071b584894b0bc0294b2bf71fd8c72786e3c69f9731e020c17e3ae45db079f',
        '008883e7f907b02401f608bc52588460e4655f20ef68858c038701db21d89965',
        '57a5a2017833a90f3e88cb8a6c994effee894dc44dc98acf50d8f41864905532',
        '40077c55711ab38766e6c9898060e2bacfffcb8065678b38721051848a55f498',
        'd25a4f71228fc4310f531303c46453eba24e23486daea8020e6d11fb368f5fe1',
        '059fdcfc5d4824d1888158c5aca74561c7d99017daae49bb85e82f73e4e524da',
        '3dea54d9cb32ba3a75dca83bc7d820ceb0b69316fb9814779fa1791c6c2e3470',
        '3f0e7b738fa6e151dcd85495f3840ea821366ff5347f608d10939bc468e12c68',
        'c1c5567c3992f83bab2a2f4b1139f26c68c81de23f6ecaf453ef773878eff064',
        'ea00475c091354a0985a1b5d4c5d9ed4b5287240fc55f2aa4fd7e2c13a0e1c0f',
        '575b308ba8c79380c3543e079afc0160bbad6c433d9c9dd7d6a9c33a26352843',
        '74a6fb6145085de791a405a82c96fa58ccfde89d766e4a87c526f81aee0a1700',
        'b663234e3b1ac9689e0a46517a410f0a5b77c0b66cd4aff7d19ab50dd9082136',
        'e3f12db9b75fcf5f78758d9b7e8cf082b152787c3e2cdc0918db70aa978283bd',
        'da9b41ea6467764f15a11c58c8bcd1619057a49cc5372b65fb7570b0e79c3231',
        '5eb2bff6619109254e554e175437b2ff0f058999d0c65aa85d6e0271d1aef3ab',
        '4dcb3f917667e73c467084211a3a0b855385fa76d89af0197609ddf50d2c3b8c',
        '2f9b2bff06fae73679d794334b4da92d11dcd37c24260f90d2c94cba4279c910',
        'a1a9e07fcf622ff95dfaf3d1fc32a7a3650b8071d845c4e85c60561780de99d5',
        'fe3f5dc860dab551a9933d3d840abb23985444daddf8597baadfabd11dc0ee16',
        '38ac7e05ec5fdcab3bde437a0fedfe86689eb4d5c0e1263adc83d3d50f5ccb7b',
        'ea0fca513ae2d5b8fb91e002dc585fc6c718600343ea5f90cf2e8d06414dab9d',
        'f19bb0bc35ab13628b664203a745d4dd64d8f5da823142b86d6afc2a9cea25cc',
        'cbe9b651e9b9629a124c84da8ae6196b33d79594b75dda54c04b938ecb69a313',
        'debd1e41876855a5e13d4784da8ee6166af03d65c9dca77cf595185381b39224',
        '4ffde5f9d8aa40e228c69ae0667a42b922f60ebdb75f09f5ab699d6ca2b54fe1',
        '3cf9817be8dce48e53a80ed53c2c44f4a65e9bd6524b660d53ed5950e311e720',
        '6d91270eb037ea4decec5a2b767a20f68cd05e16d8d93e0f9c140c88bef4b5c5',
        '3103344484a7f8c683dd5aeef94999b329148b29fdf1049042ba517ff6841602',
        'b0ff5704523c764bec5266fa77cae93397132b942bdeb25d2ad0a3e9d0e1aa2a',
        'f2b932f0c417729fe425dea1e5e0f80dace74835fb383a50fa9587f49ca11a1e',
        'af4ea889d2f2431217b8cec114fc561e53a0d24663235a1672d4f8cd7f8dccc8',
        '16f3d0fe8553557c888e270bde97ed32435916b720b93480acc1a9f2cc0f1ecc',
        '6e1408fa10603e1ad532b94997bcb09b3c93fa58717c2b19b5ee2a02e854a856',
        'fcab379402c7e2ff40103e1d10c3765c053f2ec2f61e4cdc1ba65f0414dd6242',
        '62aaf619440401669a130f59c95f34c6e80eaf2a994dd2a49a08fd5a6d456c81',
        '5ec14b3d56833ea070f4dfd6b0c319f5d2f4cb775f848b8c2d598e07c063a15a'
    ],
    1000
)

def get_tests(config={}):
    from Crypto.Hash import SHA3_256
    from common import make_hash_tests
    return make_hash_tests(SHA3_256, "SHA3_256", test_data,
        digest_size=SHA3_256.digest_size,
        oid="2.16.840.1.101.3.4.2.8",
        mct_data=mct_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
