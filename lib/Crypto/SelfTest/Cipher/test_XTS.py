# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from binascii import unhexlify

import pytest

from Crypto import MessageTooLongError
from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHAKE128
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof, wycheproof_id
from Crypto.Util._bytes import tobytes
from Crypto.Util.strxor import strxor

MODE = AES.MODE_XTS

KEY_256 = bytes(range(32))
KEY_512 = bytes(range(64))
TWEAK = bytes(range(16))

BACKENDS = [{"use_aesni": True}, {"use_aesni": False}]

# Key, tweak, plaintext, ciphertext
IEEE_1619_VECTORS = [
    # Vector 2
    (
        unhexlify("1111111111111111111111111111111122222222222222222222222222222222"),
        unhexlify("33333333330000000000000000000000"),
        unhexlify("4444444444444444444444444444444444444444444444444444444444444444"),
        unhexlify("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
    ),
    # Vector 3
    (
        unhexlify("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222"),
        unhexlify("33333333330000000000000000000000"),
        unhexlify("4444444444444444444444444444444444444444444444444444444444444444"),
        unhexlify("af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"),
    ),
    # Vector 4
    (
        unhexlify("2718281828459045235360287471352631415926535897932384626433832795"),
        unhexlify("00000000000000000000000000000000"),
        bytes(range(256)) * 2,
        unhexlify(
            "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
            "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
            "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
            "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
            "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
            "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
            "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
            "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
            "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
            "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
            "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
            "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
            "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
            "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
            "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
            "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568"
        ),
    ),
    # Vector 10
    (
        unhexlify(
            "2718281828459045235360287471352662497757247093699959574966967627"
            "3141592653589793238462643383279502884197169399375105820974944592"
        ),
        unhexlify("ff000000000000000000000000000000"),
        bytes(range(256)) * 2,
        unhexlify(
            "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
            "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
            "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
            "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
            "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
            "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
            "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
            "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
            "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
            "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
            "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
            "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
            "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
            "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
            "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
            "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"
        ),
    ),
]

# Wycheproof, with the tweak extended to 16 bytes: all lengths with ciphertext stealing
STEALING_VECTORS = [
    # message size = 17, key of 256 bits
    (
        unhexlify("f1cebabf4d12b48ae3d9a2d505957d80f3c9b93bda4a1620ab88bf1eaa3b68ad"),
        unhexlify("446ac748982d2c4a0000000000000000"),
        unhexlify("6243adf9588fbc8ed0e16033121abb1332"),
        unhexlify("2476f858a49eb8077a054472d0e26e0670"),
    ),
    # message size = 18, key of 256 bits
    (
        unhexlify("04f00afe02dc8ee16e88d86860301d81636bd586631cfd9ac0b03caee4f3c6ab"),
        unhexlify("ee7c42d66abd83930000000000000000"),
        unhexlify("33d11c52a41a686d337aac237a6b249b465a"),
        unhexlify("14f5fde97ce5d24c708aaac9ca37bfd8f1b5"),
    ),
    # message size = 19, key of 256 bits
    (
        unhexlify("e0a8ee908853b6a08405281547344b73afb82aa7bc955afc1623a222b9d8954c"),
        unhexlify("92da12aebd9a0fd70000000000000000"),
        unhexlify("932b04391c3b3be05dda1a8bc459dbf40821d8"),
        unhexlify("89aa5260212af9db677f662cedf67ded840396"),
    ),
    # message size = 20, key of 256 bits
    (
        unhexlify("2692d795e57204d651a2ed8a4c033febce7863e805e149bfc7691490612eb1c2"),
        unhexlify("5dc6a5f41ae1c83b0000000000000000"),
        unhexlify("399079f0f937f43f2bceef8b9a5f0e2cfd535252"),
        unhexlify("158db9861fe56862dbba3984e7976e3494464488"),
    ),
    # message size = 21, key of 256 bits
    (
        unhexlify("d3343548b06329e2bdfa15f997164904b2a347c1558d35e90e166f8ff8e34259"),
        unhexlify("fd0d03f986dd1edd0000000000000000"),
        unhexlify("74bc823352841ddc011812f5a657b25f669d8df553"),
        unhexlify("ded4e2fb27723bd2a880df6dec79aec323c85c5e3a"),
    ),
    # message size = 22, key of 256 bits
    (
        unhexlify("cf70f06f2d412f61c80880c35bd8c7104fb2e01ee1ade6429af700199357c490"),
        unhexlify("33099878c5badd460000000000000000"),
        unhexlify("463c39b959496659fa4d38ab59d628c6e31e3d38a6bd"),
        unhexlify("7bd6afed0ce2f0741352176580c8de17e829d7090a59"),
    ),
    # message size = 23, key of 256 bits
    (
        unhexlify("16f62b2f730a462072b407f5d88fe04ad8226925d57f14fb71192289ba86a334"),
        unhexlify("5925796dcff1fb080000000000000000"),
        unhexlify("ec3b151e8d6c0ee8298039f108ff0e6319bc6a531930f4"),
        unhexlify("69a208c10babdffaf1775ef678db7a917ff6b74a47b616"),
    ),
    # message size = 24, key of 256 bits
    (
        unhexlify("c2be588c222b8e41bcfa8f8d1dcdb8e236dbb9bc46bb9863b2dbcd55029cfe29"),
        unhexlify("591f110514840d080000000000000000"),
        unhexlify("f6f9fba133b089c4cf82be7ecb0074a5075ca90ccf5b734f"),
        unhexlify("b4a56ecfc0f0107f872d8d4dae3d0c3fb327fa39ad73add1"),
    ),
    # message size = 25, key of 256 bits
    (
        unhexlify("592cbbed28130580b80f2c48d14f1581a906389f21b1496972c4612a7a66d614"),
        unhexlify("05fd34efcf854c980000000000000000"),
        unhexlify("4e5ecb227d0fa9dc74b478d6bbdc48d3ff1f6ce727104f5ce7"),
        unhexlify("b1379bb848aafa899d28e58901d81b9b11bcabb7316b61cee2"),
    ),
    # message size = 26, key of 256 bits
    (
        unhexlify("75303fbf282b2a803cd4395edc0286d39dcbed23d39d53b7c13c8ec70dccff8e"),
        unhexlify("4b0d118dc1a4a8c30000000000000000"),
        unhexlify("47bce7f15832d026c70f21b7acd909d84f2f106dc118bfc36f2c"),
        unhexlify("4f02afc8369d412861aee26391a24dd4d07e4e19a069d72ad471"),
    ),
    # message size = 27, key of 256 bits
    (
        unhexlify("7c22af22c3bc02ab0c947061322903fa126b1b50abf34853c555e69f36240fd5"),
        unhexlify("510725ea9294766a0000000000000000"),
        unhexlify("1bb64c32f139a7bf1daff17b4552755e7be517c737951a5a299061"),
        unhexlify("1950ff47795506b6f39e6f39ce6137f7c134e9bfe5a46e4be980ab"),
    ),
    # message size = 28, key of 256 bits
    (
        unhexlify("777f8456e020732b882e566b88d5b9b53945e81d030a59f559a78c21756060d1"),
        unhexlify("7d26aae9b622d7390000000000000000"),
        unhexlify("c3768bedf91dbb0b5f71b79f4e2c5d487f82f2dd5bcb804180f3f0b3"),
        unhexlify("effa00d17c3087eac647315c8945b99df1976de0fe461c448ffd4c92"),
    ),
    # message size = 29, key of 256 bits
    (
        unhexlify("258db9f29f7008baf536394a1e9637d0fcd374da2b76abee060d28c5f5055784"),
        unhexlify("9dbb6081a761e1d00000000000000000"),
        unhexlify("e450e63051fdaff61609e0ba2193c6175357a4c98616cbae5fbf1879c9"),
        unhexlify("43d66fc948eba53d4cb5180a44082fd9f5e74073300c14d3ea5877068e"),
    ),
    # message size = 30, key of 256 bits
    (
        unhexlify("ea1b0f6c849c684b38d36513c6e44d8fde52c64d2e368a29385ec842959f68cd"),
        unhexlify("b45cb8329281aac50000000000000000"),
        unhexlify("7fbc47289013c7fedf47c7673df2c5f23e181ea0e8975652ce4b40201fa8"),
        unhexlify("888f8a891288caa65d6bc1bc47dee4461c0e00e2c362d74f06d8b94d33e7"),
    ),
    # message size = 31, key of 256 bits
    (
        unhexlify("5794ef1273526008a12ba522cf9695e5790bbef8130efa62e41926a30f9e16f8"),
        unhexlify("322361ac9b5bce910000000000000000"),
        unhexlify("779398782c2e4dfa2ea3177a28ff977df6384596170b4b111f1d9993faee12"),
        unhexlify("401ff4662aba1c188aaf2a89c63a9ff4eed7356821a1470fd74bfb98cc0611"),
    ),
    # message size = 17, key of 512 bits
    (
        unhexlify(
            "2f247ad2e9fd78c55085890ddc1fde397d12663c9afc4efbe227b2d52728068564ce42c96c30967360c9986d63ce82839c3e81d1839b800e8db5aa61980eb3ff"
        ),
        unhexlify("c09e5c393303a1690000000000000000"),
        unhexlify("a431693fb645d0fadd64d5ac98037a1b36"),
        unhexlify("021fbfeb5d7bcec215aae0f32cbe44e9c3"),
    ),
    # message size = 18, key of 512 bits
    (
        unhexlify(
            "9b7931f0ceb44ca542abd4f2a042a213a1e5372d046cbcc0d7aca3b49e3a96215e90efbbd30e8d0e60dee62bf1cd89270ca75aecc1800f0525e0c4ed9eed1ef8"
        ),
        unhexlify("757105d803d4f76a0000000000000000"),
        unhexlify("3c99ae13bc0331dbb5cb3f70b999021f3b3a"),
        unhexlify("ded635c542bfef6ea3df062be35853bd4c2a"),
    ),
    # message size = 19, key of 512 bits
    (
        unhexlify(
            "3503d003bed52c84c854c2bbabdf8a5f5ed17ef95525284b4f6062ae295f750679cd17d8b3e010d1279687f097f76d673ee95191e3444ec5d8b88652454e5052"
        ),
        unhexlify("781579426c73cd030000000000000000"),
        unhexlify("697055ac55cdb8d36531c60ffddc9675c8597d"),
        unhexlify("da84ac3cfc8fdc84b9f7c8890c06921a050408"),
    ),
    # message size = 20, key of 512 bits
    (
        unhexlify(
            "9dbcbd3adde1a6270759ec8c441a863644f89c9f562afed82e33dc8165b6baf6919ea7efb569c53f4ef74d0be3534ac4e0271110aa8b891281317804574a2636"
        ),
        unhexlify("9dab0d1d240f881a0000000000000000"),
        unhexlify("91146833d31f4133429e1446cf1eeed89c677a27"),
        unhexlify("540962035d137c6bc8d7f8a3da1a22d11cad8186"),
    ),
    # message size = 21, key of 512 bits
    (
        unhexlify(
            "983351e42010b6ea8b47c52ddebf14c02b72ce6b59f4eba2e68ef0df22d17a1bcdabf3d13ec88f8c73f78e45b2e75b2b06782359913ffa2075ef75da9e2c6d25"
        ),
        unhexlify("fd72b2accfa9821e0000000000000000"),
        unhexlify("3f6e7daf4a17d234b77a35c111611d12300fc9a1a1"),
        unhexlify("ba6c451acf4b98b3165a0291517934b46a60137b79"),
    ),
    # message size = 22, key of 512 bits
    (
        unhexlify(
            "6ad4435b9f0a0df8189c8478e5a588862084dfd514464e293d6897ec26dd3718635767ca3b78e0f8307b71e834c1b01712f279f5fbe41f92fc35b3b7adcfd215"
        ),
        unhexlify("04656d9694c91fd20000000000000000"),
        unhexlify("132fc33a89f3da1bfc2b7210e4b1565cd03a735fed3d"),
        unhexlify("a1a13772c3bb1c136f93dd92ebcbf7c878b5a3037001"),
    ),
    # message size = 23, key of 512 bits
    (
        unhexlify(
            "752f8761a344b70c17ae1d25b17e65833633ae77a5a3383116d1a222cc3253c61b0cae1afa01583b6d1734c41152ee817357f9e2c419e73ccddb72c9ca391dc4"
        ),
        unhexlify("3da43b3cfcdab2c50000000000000000"),
        unhexlify("4214b0b3e08d5eb2ddff0e7cf954f91c827e3410007935"),
        unhexlify("4a98f3cbc3ac9314789da45522d436d3553a31b618cd42"),
    ),
    # message size = 24, key of 512 bits
    (
        unhexlify(
            "0b082b19964f47db2b0a72ce2c662d5d127f58e5b3c4e75e7d8914a75a097e5e2c05979a782db3b314a2ca9e7203c38108049a8fa8dc1960e8c6decad5a79746"
        ),
        unhexlify("25826dd0496454a10000000000000000"),
        unhexlify("61b55eec99b739292074a42cb5c5c0a2e1570bb2ed643727"),
        unhexlify("360ecdaee1df8acefc6d5ad9bcfc38cdf8705547af6fe25e"),
    ),
    # message size = 25, key of 512 bits
    (
        unhexlify(
            "bb74621b7bcb39d0414b7d610da25fdb771339af43b4649a04cf3820a239944538d194d4dfd40f9471206391a5e63a713a56eb316d87ad240ab2ae98f0669e8e"
        ),
        unhexlify("833aa2e404a6bfc90000000000000000"),
        unhexlify("2720727d5e14666bc3f3cec0fd57cc8a152e3056078a31e719"),
        unhexlify("541286b663cb5ce66daa6adf7881011495539c04440730f0cf"),
    ),
    # message size = 26, key of 512 bits
    (
        unhexlify(
            "77d121def076fff37a216263481c21d7eae7b5b5a148ef28f6b8ce7c9c20bb93e00649661e1a63814e331b38652500deb4887b5ffe4501de4028f695ee60f68a"
        ),
        unhexlify("1ba50eabba30a6e40000000000000000"),
        unhexlify("33a7df8573be5c83a3d799683fd96a55aea94ae14a102623b766"),
        unhexlify("75e09dac09fe7bec1f2c834d7444e29dcde7eb7decbdb40388b8"),
    ),
    # message size = 27, key of 512 bits
    (
        unhexlify(
            "cae7c569fc3e57033bfbeda43a4c1f6812062abf43c1437fa47f34e538a0a9bd6c184cd3b18f758af80c433358c3e71fe0294293cbeaed3fa0ef2fa5f888d361"
        ),
        unhexlify("b40fca5d4d8dcc210000000000000000"),
        unhexlify("e739f5e88075c410b3c0e5abeb96042d84a2b31653133affb6e9dd"),
        unhexlify("070787639b1f709e154fa1625d2d71d6fcbef4e7c44ffa76ebceee"),
    ),
    # message size = 28, key of 512 bits
    (
        unhexlify(
            "b81719157218b29d9058b8f2fd99952ee9590a4f58dcad6bcdce912c7c47cdd180cd13003757f8cdca33a936fa1d62bbd2e9dc823705532002445fc3c48d6eee"
        ),
        unhexlify("5128b55710b9cfb00000000000000000"),
        unhexlify("30b7b22121293d69a42113403b39fe24020c72c4b6142dcf0aa6081c"),
        unhexlify("3174ef3c9333997b4343a0b04e1f672134f9c214f1ba29a6669ee61a"),
    ),
    # message size = 29, key of 512 bits
    (
        unhexlify(
            "b2b6cc354c21237aea43a9e75359ce12852a8ee2ac2c745fbb5cb28455035e59123806fb9599d76904c41ff783760c9f663387478709d4f88f2e53d8bf44c27b"
        ),
        unhexlify("5dad2854f18432a30000000000000000"),
        unhexlify("a923683c4dd76512f71c428df3da54c944ddf0a611a1cff64bf4c95c6c"),
        unhexlify("f035477af806f39b406271ce96b0b0b3e579ac1b63fcafe7705bcd38bd"),
    ),
    # message size = 30, key of 512 bits
    (
        unhexlify(
            "1cf89ec2a64afb2c724fe63fd5d04695313318094735fc2264913f40b7a7a135dc310cfefb32031d42fd9455e77ff940a6f4d54edec7e8410f04cefe5348e11d"
        ),
        unhexlify("c346c5203aa8fc440000000000000000"),
        unhexlify("1f96629258e900cd7878ee30aa62648320a5de01afe6e9086363437c0baa"),
        unhexlify("278adb33deeb075671cff676341b23a7864398a20b748fde457e114d4c71"),
    ),
    # message size = 31, key of 512 bits
    (
        unhexlify(
            "ed378260319f5aebdff6d5bd739b81abad783922d6d5d24b751f07ba5c8a283906a1023db5039fd582af3f41f49528da4a475396bc409b6b21cc3c7dabd785e6"
        ),
        unhexlify("4b5a54eb2f91acca0000000000000000"),
        unhexlify("7cff7d0a90cfa2b351e686a2408c898e8a7ff045da18e4f00175bb7d1a9383"),
        unhexlify("57a61be775ec75d2ef15f7b3fb0c6f8c34f3ab69b421b75f955ed867004b19"),
    ),
]


def get_tag_random(tag, length):
    return SHAKE128.new(data=tobytes(tag)).read(length)


def reference_xts(key, tweak, data, decrypt=False):
    """A slow implementation of XTS, block by block, only for public test values"""

    half = len(key) // 2
    ecb = AES.new(key[:half], AES.MODE_ECB, use_aesni=False)
    operation = ecb.decrypt if decrypt else ecb.encrypt

    value = int.from_bytes(AES.new(key[half:], AES.MODE_ECB, use_aesni=False).encrypt(tweak), "little")

    def next_tweak():
        nonlocal value
        result = value.to_bytes(16, "little")
        value <<= 1
        if value >> 128:
            value ^= (1 << 128) ^ 0x87
        return result

    def process(block, block_tweak):
        return strxor(operation(strxor(block, block_tweak)), block_tweak)

    partial_len = len(data) % 16
    full_len = len(data) - partial_len - (16 if partial_len else 0)

    result = b""
    for i in range(0, full_len, 16):
        result += process(data[i : i + 16], next_tweak())

    if partial_len:
        tweak_1, tweak_2 = next_tweak(), next_tweak()
        if decrypt:
            tweak_1, tweak_2 = tweak_2, tweak_1
        block = process(data[full_len : full_len + 16], tweak_1)
        partial = data[full_len + 16 :]
        result += process(partial + block[partial_len:], tweak_2) + block[:partial_len]

    return result


@pytest.mark.parametrize("backend", BACKENDS)
class TestKnownVectors:
    @pytest.mark.parametrize("vector", IEEE_1619_VECTORS + STEALING_VECTORS)
    def test_vector(self, vector, backend):
        key, tweak, plaintext, ciphertext = vector
        assert AES.new(key, MODE, tweak=tweak, **backend).encrypt(plaintext) == ciphertext
        assert AES.new(key, MODE, tweak=tweak, **backend).decrypt(ciphertext) == plaintext


class TestReference:
    def test_reference(self):
        for vector in IEEE_1619_VECTORS + STEALING_VECTORS:
            key, tweak, plaintext, ciphertext = vector
            assert reference_xts(key, tweak, plaintext) == ciphertext
            assert reference_xts(key, tweak, ciphertext, decrypt=True) == plaintext

    # Across the batches of 64 blocks in the C code
    @pytest.mark.parametrize(
        "length",
        list(range(16, 50)) + [255, 256, 257, 512, 1007, 1008, 1023, 1024, 1025, 1040, 1041, 4096, 5000],
    )
    @pytest.mark.parametrize("key", [KEY_256, KEY_512], ids=["key256", "key512"])
    @pytest.mark.parametrize("backend", BACKENDS)
    def test_lengths(self, length, key, backend):
        plaintext = get_tag_random("plaintext", length)
        ciphertext = reference_xts(key, TWEAK, plaintext)
        assert AES.new(key, MODE, tweak=TWEAK, **backend).encrypt(plaintext) == ciphertext
        assert AES.new(key, MODE, tweak=TWEAK, **backend).decrypt(ciphertext) == plaintext

    @pytest.mark.parametrize(
        "encrypted_tweak",
        [
            b"\xff" * 16,
            b"\x00" * 16,
            b"\x00" * 15 + b"\x80",
            b"\x00" * 7 + b"\x80" + b"\x00" * 8,
            b"\x01" + b"\x00" * 15,
        ],
        ids=["all_ones", "zero", "top_bit", "low_word_top_bit", "low_bit"],
    )
    @pytest.mark.parametrize("backend", BACKENDS)
    def test_tweak_carries(self, encrypted_tweak, backend):
        tweak = AES.new(KEY_256[16:], AES.MODE_ECB).decrypt(encrypted_tweak)
        plaintext = get_tag_random("plaintext", 1000)
        ciphertext = reference_xts(KEY_256, tweak, plaintext)
        assert AES.new(KEY_256, MODE, tweak=tweak, **backend).encrypt(plaintext) == ciphertext
        assert AES.new(KEY_256, MODE, tweak=tweak, **backend).decrypt(ciphertext) == plaintext


class TestParameters:
    def test_tweak_is_mandatory(self):
        with pytest.raises(TypeError, match="tweak"):
            AES.new(KEY_256, MODE)

    def test_tweak_is_keyword_only(self):
        with pytest.raises(TypeError, match="keyword"):
            AES.new(KEY_256, MODE, TWEAK)
        with pytest.raises(TypeError, match="keyword"):
            AES.new(KEY_256, MODE, TWEAK, tweak=TWEAK)

    @pytest.mark.parametrize("length", [0, 1, 8, 15, 17, 32])
    def test_tweak_length(self, length):
        with pytest.raises(ValueError):
            AES.new(KEY_256, MODE, tweak=bytes(length))

    @pytest.mark.parametrize("tweak", [None, 5, "0123456789abcdef"])
    def test_tweak_type(self, tweak):
        with pytest.raises(TypeError):
            AES.new(KEY_256, MODE, tweak=tweak)

    @pytest.mark.parametrize("length", [0, 16, 24, 31, 33, 48, 63, 65, 128])
    def test_key_length(self, length):
        with pytest.raises(ValueError):
            AES.new(bytes(range(length)), MODE, tweak=TWEAK)

    @pytest.mark.parametrize("half", [16, 32])
    def test_equal_keys(self, half):
        key = bytes(range(half)) * 2
        with pytest.raises(ValueError, match="different"):
            AES.new(key, MODE, tweak=TWEAK)

    def test_keys_differ_by_one_bit(self):
        key = bytearray(bytes(range(16)) * 2)
        key[-1] ^= 1
        AES.new(key, MODE, tweak=TWEAK)

    def test_unknown_parameters(self):
        with pytest.raises(TypeError):
            AES.new(KEY_256, MODE, tweak=TWEAK, nonce=b"12345678")
        with pytest.raises(TypeError):
            AES.new(KEY_256, MODE, tweak=TWEAK, threads=2)

    def test_only_aes(self):
        with pytest.raises(ValueError):
            DES3.new(DES3.adjust_key_parity(bytes(range(24))), MODE, tweak=bytes(8))

    def test_attributes(self):
        cipher = AES.new(KEY_256, MODE, tweak=bytearray(TWEAK))
        assert cipher.tweak == TWEAK
        assert isinstance(cipher.tweak, bytes)
        assert cipher.block_size == 16

    def test_tweak_copy(self):
        tweak = bytearray(TWEAK)
        cipher = AES.new(KEY_256, MODE, tweak=tweak)
        tweak[0] ^= 1
        assert cipher.tweak == TWEAK

    @pytest.mark.parametrize("convert", [bytes, bytearray, memoryview])
    def test_buffer_types(self, convert):
        data = get_tag_random("data", 40)
        expected = AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(data)
        cipher = AES.new(convert(KEY_256), MODE, tweak=convert(TWEAK))
        assert cipher.encrypt(convert(data)) == expected


class TestOutput:
    data = get_tag_random("data", 40)
    expected = AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(data)

    @pytest.mark.parametrize("convert", [bytearray, lambda x: memoryview(bytearray(x))])
    def test_output(self, convert):
        output = convert(bytes(40))
        assert AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(self.data, output=output) is None
        assert bytes(output) == self.expected

        assert AES.new(KEY_256, MODE, tweak=TWEAK).decrypt(self.expected, output=output) is None
        assert bytes(output) == self.data

    @pytest.mark.parametrize("backend", BACKENDS)
    @pytest.mark.parametrize("length", [16, 17, 31, 32, 40, 1024, 1040, 1041])
    def test_in_place(self, length, backend):
        data = get_tag_random("data", length)
        expected = reference_xts(KEY_256, TWEAK, data)

        buffer = bytearray(data)
        AES.new(KEY_256, MODE, tweak=TWEAK, **backend).encrypt(buffer, output=buffer)
        assert buffer == expected

        AES.new(KEY_256, MODE, tweak=TWEAK, **backend).decrypt(buffer, output=buffer)
        assert buffer == data

    def test_output_too_short_or_long(self):
        for length in (39, 41):
            with pytest.raises(ValueError):
                AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(self.data, output=bytearray(length))
            with pytest.raises(ValueError):
                AES.new(KEY_256, MODE, tweak=TWEAK).decrypt(self.data, output=bytearray(length))

    def test_output_not_writeable(self):
        with pytest.raises(TypeError):
            AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(self.data, output=bytes(40))
        with pytest.raises(TypeError):
            AES.new(KEY_256, MODE, tweak=TWEAK).decrypt(self.data, output=memoryview(bytes(40)))


class TestPieces:
    data = get_tag_random("data", 1100)

    @pytest.mark.parametrize(
        "lengths",
        [
            (16, 16),
            (16, 17),
            (16, 31),
            (32, 16, 33),
            (1024, 16),
            (1040, 16, 16, 28),
            (16, 1024, 60),
        ],
    )
    def test_pieces(self, lengths):
        data = self.data[: sum(lengths)]
        ciphertext = reference_xts(KEY_256, TWEAK, data)

        for operation, source, target in (("encrypt", data, ciphertext), ("decrypt", ciphertext, data)):
            method = getattr(AES.new(KEY_256, MODE, tweak=TWEAK), operation)
            result, position = b"", 0
            for length in lengths:
                result += method(source[position : position + length])
                position += length
            assert result == target

    def test_empty_pieces(self):
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        assert cipher.encrypt(b"") == b""
        result = cipher.encrypt(self.data[:17])
        assert cipher.encrypt(b"") == b""
        assert result == reference_xts(KEY_256, TWEAK, self.data[:17])

    @pytest.mark.parametrize("length", [1, 8, 15])
    def test_too_short(self, length):
        with pytest.raises(ValueError, match="at least 16"):
            AES.new(KEY_256, MODE, tweak=TWEAK).encrypt(self.data[:length])
        with pytest.raises(ValueError, match="at least 16"):
            AES.new(KEY_256, MODE, tweak=TWEAK).decrypt(self.data[:length])

    def test_short_last_piece(self):
        # The last full block has already been returned: it cannot be stolen from
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        cipher.encrypt(self.data[:32])
        with pytest.raises(ValueError, match="at least 16"):
            cipher.encrypt(self.data[32:37])

    def test_failure_does_not_change_the_state(self):
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        with pytest.raises(ValueError):
            cipher.encrypt(self.data[:5])
        assert cipher.encrypt(self.data[:40]) == reference_xts(KEY_256, TWEAK, self.data[:40])

    @pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
    def test_nothing_after_the_end(self, operation):
        method = getattr(AES.new(KEY_256, MODE, tweak=TWEAK), operation)
        method(self.data[:20])
        with pytest.raises(TypeError, match="multiple of 16"):
            method(self.data[20:36])

    def test_encrypt_then_decrypt(self):
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        cipher.encrypt(self.data[:16])
        with pytest.raises(TypeError):
            cipher.decrypt(self.data[:16])

    def test_decrypt_then_encrypt(self):
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        cipher.decrypt(self.data[:16])
        with pytest.raises(TypeError):
            cipher.encrypt(self.data[:16])


class TestDataLimit:
    limit = 1 << 24

    @pytest.mark.parametrize("operation", ["encrypt", "decrypt"])
    def test_one_call(self, operation):
        data = bytes(self.limit + 1)
        with pytest.raises(MessageTooLongError):
            getattr(AES.new(KEY_256, MODE, tweak=TWEAK), operation)(data)
        with pytest.raises(MessageTooLongError):
            getattr(AES.new(KEY_256, MODE, tweak=TWEAK), operation)(data[:-1] + bytes(16))

        assert len(getattr(AES.new(KEY_256, MODE, tweak=TWEAK), operation)(data[:-1])) == self.limit

    def test_several_calls(self):
        cipher = AES.new(KEY_256, MODE, tweak=TWEAK)
        cipher.encrypt(bytes(self.limit - 16))
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(17))
        cipher.encrypt(bytes(16))
        with pytest.raises(MessageTooLongError):
            cipher.encrypt(bytes(16))
        assert cipher.encrypt(b"") == b""


def load_cavp(file_name):
    # The lengths in bits that are not a whole number of bytes cannot be expressed in this API
    return [
        tv
        for tv in (
            load_test_vectors(
                ("Cipher", "AES"),
                file_name,
                "NIST CAVP " + file_name,
                {"count": int, "dataunitlen": int, "dataunitseqnumber": int},
            )
            or []
        )
        # The file also has section headers, as strings
        if not isinstance(tv, str) and tv.dataunitlen % 8 == 0
    ]


@pytest.mark.parametrize("backend", BACKENDS)
class TestCavp:
    @pytest.mark.parametrize(
        "tv",
        load_cavp("XTSGenAES128.rsp") + load_cavp("XTSGenAES256.rsp"),
        ids=lambda tv: "%s-%d" % (tv.desc.split()[2], tv.count),
    )
    def test_128_bit_tweak(self, tv, backend):
        assert AES.new(tv.key, MODE, tweak=tv.i, **backend).encrypt(tv.pt) == tv.ct
        assert AES.new(tv.key, MODE, tweak=tv.i, **backend).decrypt(tv.ct) == tv.pt

    @pytest.mark.parametrize(
        "tv",
        load_cavp("XTSGenAES128_seqno.rsp") + load_cavp("XTSGenAES256_seqno.rsp"),
        ids=lambda tv: "%s-%d" % (tv.desc.split()[2], tv.count),
    )
    def test_sequence_number(self, tv, backend):
        tweak = tv.dataunitseqnumber.to_bytes(16, "little")
        assert AES.new(tv.key, MODE, tweak=tweak, **backend).encrypt(tv.pt) == tv.ct
        assert AES.new(tv.key, MODE, tweak=tweak, **backend).decrypt(tv.ct) == tv.pt


def load_wycheproof_vectors():
    return load_test_vectors_wycheproof(("Cipher", "wycheproof"), "aes_xts_test.json", "Wycheproof AES-XTS")


@pytest.mark.parametrize("backend", BACKENDS)
class TestWycheproof:
    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    def test_vector(self, tv, backend):
        # AES-192 is in Wycheproof, but not in the standards
        if len(tv.key) == 48:
            with pytest.raises(ValueError):
                AES.new(tv.key, MODE, tweak=bytes(16), **backend)
            return

        # A tweak shorter than 16 bytes is padded with zero bytes on the right
        tweak = tv.iv.ljust(16, b"\x00")
        assert tv.valid
        assert AES.new(tv.key, MODE, tweak=tweak, **backend).encrypt(tv.msg) == tv.ct
        assert AES.new(tv.key, MODE, tweak=tweak, **backend).decrypt(tv.ct) == tv.msg
