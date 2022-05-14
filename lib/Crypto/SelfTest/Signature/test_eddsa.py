#
# Copyright (c) 2022, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

import unittest
from binascii import unhexlify

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.loader import load_test_vectors_wycheproof
from Crypto.Util.number import bytes_to_long

rfc8032_tv_str = (
    # 7.1 Ed25519
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        None,
        "",
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        None,
        "",
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00"
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        None,
        "",
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a"
    ),
    (
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908"
        "632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1"
        "e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe57"
        "38829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c"
        "941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a"
        "7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b"
        "3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9"
        "a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc10"
        "3b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a4"
        "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a9"
        "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d"
        "502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bd"
        "e1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553"
        "878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089b"
        "eccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a"
        "7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b"
        "82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969b"
        "e3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8"
        "fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1"
        "ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988d"
        "cda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a8"
        "5f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927"
        "094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7"
        "984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57"
        "f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1"
        "b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac09"
        "43bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2"
        "cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041"
        "e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f161"
        "0e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d034"
        "12c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e"
        "4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8ca"
        "c60c905c15fc910840b94c00a0b9d0",
        None,
        "",
        "0aab4c900501b3e24d7cdf4663326a3a"
        "87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b"
        "5e8fcd4f681e30a6ac00a9704a188a03"
    ),
    # 7.2 Ed25519ctx
    (
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",
        "dfc9425e4f968f7f0c29f0259cf5f9ae"
        "d6851c2bb4ad8bfb860cfee0ab248292",
        "f726936d19c800494e3fdaff20b276a8",
        None,
        "666f6f",
        "55a4cc2f70a54e04288c5f4cd1e45a7b"
        "b520b36292911876cada7323198dd87a"
        "8b36950b95130022907a7fb7c4e9b2d5"
        "f6cca685a587b4b21f4b888e4e7edb0d"
    ),
    (
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",
        "dfc9425e4f968f7f0c29f0259cf5f9ae"
        "d6851c2bb4ad8bfb860cfee0ab248292",
        "f726936d19c800494e3fdaff20b276a8",
        None,
        "626172",
        "fc60d5872fc46b3aa69f8b5b4351d580"
        "8f92bcc044606db097abab6dbcb1aee3"
        "216c48e8b3b66431b5b186d1d28f8ee1"
        "5a5ca2df6668346291c2043d4eb3e90d"
    ),
    (
        "0305334e381af78f141cb666f6199f57"
        "bc3495335a256a95bd2a55bf546663f6",
        "dfc9425e4f968f7f0c29f0259cf5f9ae"
        "d6851c2bb4ad8bfb860cfee0ab248292",
        "508e9e6882b979fea900f62adceaca35",
        None,
        "666f6f",
        "8b70c1cc8310e1de20ac53ce28ae6e72"
        "07f33c3295e03bb5c0732a1d20dc6490"
        "8922a8b052cf99b7c4fe107a5abb5b2c"
        "4085ae75890d02df26269d8945f84b0b"
    ),
    (
        "ab9c2853ce297ddab85c993b3ae14bca"
        "d39b2c682beabc27d6d4eb20711d6560",
        "0f1d1274943b91415889152e893d80e9"
        "3275a1fc0b65fd71b4b0dda10ad7d772",
        "f726936d19c800494e3fdaff20b276a8",
        None,
        "666f6f",
        "21655b5f1aa965996b3f97b3c849eafb"
        "a922a0a62992f73b3d1b73106a84ad85"
        "e9b86a7b6005ea868337ff2d20a7f5fb"
        "d4cd10b0be49a68da2b2e0dc0ad8960f"
    ),
    # 7.3 Ed25519ph
    (
        "833fe62409237b9d62ec77587520911e"
        "9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034"
        "c35467ef2efd4d64ebf819683467e2bf",
        "616263",
        SHA512,
        "",
        "98a70222f0b8121aa9d30f813d683f80"
        "9e462b469c7ff87639499bb94e6dae41"
        "31f85042463c2a355a2003d062adf5aa"
        "a10b8c61e636062aaad11c2a26083406"
    )
    )


rfc8032_tv_bytes = []
for tv_str in rfc8032_tv_str:
    rfc8032_tv_bytes.append([unhexlify(i) if isinstance(i, str) else i for i in tv_str])


class TestEdDSA(unittest.TestCase):

    def test_sign(self):
        for sk, _, msg, hashmod, ctx, exp_signature in rfc8032_tv_bytes:
            key = eddsa.import_private_key(sk)
            signer = eddsa.new(key, 'rfc8032', context=ctx)
            if hashmod is None:
                # PureEdDSA
                signature = signer.sign(msg)
            else:
                # HashEdDSA
                hashobj = hashmod.new(msg)
                signature = signer.sign(hashobj)
            self.assertEqual(exp_signature, signature)

    def test_verify(self):
        for _, pk, msg, hashmod, ctx, exp_signature in rfc8032_tv_bytes:
            key = eddsa.import_public_key(pk)
            verifier = eddsa.new(key, 'rfc8032', context=ctx)
            if hashmod is None:
                # PureEdDSA
                verifier.verify(msg, exp_signature)
            else:
                # HashEdDSA
                hashobj = hashmod.new(msg)
                verifier.verify(hashobj, exp_signature)

    def test_negative(self):
        key = ECC.generate(curve="ed25519")
        self.assertRaises(ValueError, eddsa.new, key, 'rfc9999')

        nist_key = ECC.generate(curve="p256")
        self.assertRaises(ValueError, eddsa.new, nist_key, 'rfc8032')


class TestExport_Ed25519(unittest.TestCase):

    def test_raw(self):
        key = ECC.generate(curve="Ed25519")
        x, y = key.pointQ.xy
        raw = bytearray(key._export_ed25519())
        sign_x = raw[31] >> 7
        raw[31] &= 0x7F
        yt = bytes_to_long(raw[::-1])
        self.assertEqual(y, yt)
        self.assertEqual(x & 1, sign_x)

        key = ECC.construct(point_x=0, point_y=1, curve="Ed25519")
        out = key._export_ed25519()
        self.assertEqual(b'\x01' + b'\x00' * 31, out)


class TestImport_Ed25519(unittest.TestCase):

    def test_raw(self):
        Px = 24407857220263921307776619664228778204996144802740950419837658238229122415920
        Py = 56480760040633817885061096979765646085062883740629155052073094891081309750690
        encoded = b'\xa2\x05\xd6\x00\xe1 \xe1\xc0\xff\x96\xee?V\x8e\xba/\xd3\x89\x06\xd7\xc4c\xe8$\xc2d\xd7a1\xfa\xde|'
        key = eddsa.import_public_key(encoded)
        self.assertEqual(Py, key.pointQ.y)
        self.assertEqual(Px, key.pointQ.x)

        encoded = b'\x01' + b'\x00' * 31
        key = eddsa.import_public_key(encoded)
        self.assertEqual(1, key.pointQ.y)
        self.assertEqual(0, key.pointQ.x)


class TestVectorsEdDSAWycheproof(unittest.TestCase):

    def add_tests(self, filename):

        def pk(group):
            elem = group['key']['pk']
            return unhexlify(elem)

        def sk(group):
            elem = group['key']['sk']
            return unhexlify(elem)

        result = load_test_vectors_wycheproof(("Signature", "wycheproof"),
                                              filename,
                                              "Wycheproof ECDSA signature (%s)"
                                              % filename,
                                              group_tag={'pk': pk, 'sk': sk})
        self.tv += result

    def setUp(self):
        self.tv = []
        self.add_tests("eddsa_test.json")

    def test_sign(self, tv):
        if not tv.valid:
            return

        self._id = "Wycheproof EdDSA Sign Test #%d (%s, %s)" % (tv.id, tv.comment, tv.filename)
        key = eddsa.import_private_key(tv.sk)
        signer = eddsa.new(key, 'rfc8032')
        signature = signer.sign(tv.msg)
        self.assertEqual(signature, tv.sig)

    def test_verify(self, tv):
        self._id = "Wycheproof EdDSA Verify Test #%d (%s, %s)" % (tv.id, tv.comment, tv.filename)
        key = eddsa.import_public_key(tv.pk)
        verifier = eddsa.new(key, 'rfc8032')
        try:
            verifier.verify(tv.msg, tv.sig)
        except ValueError:
            assert not tv.valid
        else:
            assert tv.valid

    def runTest(self):
        for tv in self.tv:
            self.test_sign(tv)
            self.test_verify(tv)


def get_tests(config={}):

    tests = []
    tests += list_test_cases(TestExport_Ed25519)
    tests += list_test_cases(TestImport_Ed25519)
    tests += list_test_cases(TestEdDSA)
    tests += [TestVectorsEdDSAWycheproof()]
    return tests


if __name__ == '__main__':
    def suite():
        return unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
