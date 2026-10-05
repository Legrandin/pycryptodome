# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from binascii import unhexlify

import pytest

from Crypto.Hash import SHAKE128
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey, EccXPoint, _curves

CURVE448_P = 2**448 - 2**224 - 1
CURVE448_ORDER = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D

# Test vectors for scalar multiplication using point with X=5 as base
# Each tuple is (exponent, X-coordinate)
scalar_base5_test = [
    (1, 5),
    (
        2,
        0x6391322257CAE3D49AEF4665D8BD5CCCAC9ABEFB511E83D75F3C766616266FC1BF3747F1DA00ED7125E8F0255A1208087D32A4BC1C743CB6,
    ),
    (
        3,
        0x1FBE4B3584CAB86170C14B9325840B8A2429B61FB93C42492C002A2807A4E7EA63138EA59BF95652CE9A7D13D0321C7511E3314D0553F34C,
    ),
    (
        4,
        0x93B44A7B78726BA8D0B048BD7144074F8BDAD24EF9D0A6C8264F6C00B135FFCEA11545E80D18364ACC8EBFBCC45358E0DA5FD5E5146E2B1,
    ),
    (
        6,
        0x693D165F453BD62871E5E53845F33E9E5B18B24D79C1F9102608AA7BA6F18AC24864012171D64C90B698F5CE5631CD02CEE4E4336B1AD88C,
    ),
    (
        9,
        0xB970D576E7D9AA427DBF7CB9B7DD65170721D04EE060C9EA8D499DC361D4CFDE1CEB19068EAE853BAC8F5D92827BDBF3D94C22DE2FB42DAE,
    ),
    (
        129,
        0x9FBDB50A1450438FE656AA32AA1BB2548D077D5C3A5D327689093A2996A4F94EACD1FB4F90315EDB2AFE41908A759F0D6DB83FA791DF80DB,
    ),
    (
        255,
        0x31BC3E9385DFD12E1238927061EB0C911466DA394E459BF058BA3B08260A258A3C392B0F85DDBD23828657137B88577A85B83774139FAB9E,
    ),
    (
        256,
        0x735C7F30E6872E5E4215C0147C8A112D697F668C9BD0F92F5F1E4E6BADC128A0B654E697CD4BAE2144D54E726B54C1FA63A09B00DD3C17F,
    ),
    (
        257,
        0x95C1B0CE01286DC047AEB5922A5E62B3EFFB5B9296273A5004EB456F592728DD494A6FB5996A2EA7011AE6423874A48C2927BFA62D8CE8B0,
    ),
    (
        0x10101,
        0x113BB172C9DC52AB45BD665DD9751ED44E33B8596F943C6CB2F8DD329160ECE802960B3EB0D2C21EF3A3AC12C20FCCBC2A271FC2F061C1B2,
    ),
    (
        0xAA55CC,
        0xCF42585D2E0B1E45C0BFD601C91AF4B137D7FAF139FC761178C7DED432417C307EE1759AF2DEEC6A14DBAF6B868EB13A6039FBDDE4B61898,
    ),
    (
        0x1B29A0E579E0A000567,
        0x7BD9EC9775A664F4D860D82D6BE60895113A7C36F92DB25583DBBA5DC17F09C136EC27E14857BFD6A705311327030AA657DD036325FAD330,
    ),
    (CURVE448_ORDER + 1, 5),
]


class TestEccPoint_Curve448:
    v1 = 0x09FA78B39B00A72930BCD8039BE789A0997830BB99F79AEEB93493715390B4E8
    v2 = 0x15210F12786811D3F4B7959D0538AE2C31DBE7106FC03C3EFC4CD549C715A493

    def test_init(self):
        EccXPoint(5, "curve448")
        EccXPoint(CURVE448_P - 5, "curve448")

    def test_curve_attribute(self):
        point = EccXPoint(5, "curve448")
        assert point.curve == "Curve448"

    def test_init_fail(self):
        with pytest.raises(ValueError):
            EccXPoint(3 * CURVE448_P, "curve448")
        with pytest.raises(ValueError):
            EccXPoint(3, "curve449")

    def test_equal_set(self):
        point1 = EccXPoint(self.v1, "curve448")
        point2 = EccXPoint(self.v2, "curve448")

        assert point1 == point1
        assert point1 != point2

        point2.set(point1)
        assert point1.x == point2.x

    def test_copy(self):
        point1 = EccXPoint(self.v1, "curve448")
        point2 = point1.copy()
        assert point1.x == point2.x

    def test_pai(self):
        point1 = EccXPoint(self.v1, "curve448")
        pai = point1.point_at_infinity()
        assert pai.point_at_infinity()

        point2 = EccXPoint(None, "curve448")
        assert point2.point_at_infinity()

    def test_scalar_multiply(self):
        base = EccXPoint(5, "curve448")

        pointH = 0 * base
        assert pointH.point_at_infinity()

        pointH = CURVE448_ORDER * base
        assert pointH.point_at_infinity()

        pointH = base * 1
        assert pointH.x == 5

        for d, result in scalar_base5_test:
            pointH = d * base
            assert pointH.x == result

    def test_sizes(self):
        point = EccXPoint(5, "curve448")
        assert point.size_in_bits() == 448
        assert point.size_in_bytes() == 56


class TestEccKey_Curve448:
    def test_private_key(self):
        # RFC7748 Section 6.2 - Alice
        alice_priv = unhexlify(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        )
        alice_pub = unhexlify(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        )
        alice_pub_x = Integer.from_bytes(alice_pub, byteorder="little")

        key = EccKey(curve="Curve448", seed=alice_priv)
        assert key.seed == alice_priv
        assert key.has_private()
        assert key.pointQ.x == alice_pub_x

        # RFC7748 Section 6.2 - Bob
        bob_priv = unhexlify(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        )
        bob_pub = unhexlify(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        )
        bob_pub_x = Integer.from_bytes(bob_pub, byteorder="little")

        key = EccKey(curve="Curve448", seed=bob_priv)
        assert key.seed == bob_priv
        assert key.has_private()
        assert key.pointQ.x == bob_pub_x

        # Other names
        key = EccKey(curve="curve448", seed=alice_priv)

        # Must not accept d parameter
        with pytest.raises(ValueError):
            EccKey(curve="curve448", d=1)

    def test_public_key(self):
        point = EccXPoint(_curves["curve448"].Gx, curve="curve448")
        key = EccKey(curve="curve448", point=point)
        assert not key.has_private()
        assert key.pointQ == point

    def test_public_key_derived(self):
        priv_key = EccKey(curve="curve448", seed=b"H" * 56)
        pub_key = priv_key.public_key()
        assert not pub_key.has_private()
        assert priv_key.pointQ == pub_key.pointQ

    def test_invalid_seed(self):
        with pytest.raises(ValueError):
            EccKey(curve="curve448", seed=b"H" * 55)

    def test_equality(self):
        private_key = ECC.construct(seed=b"H" * 56, curve="Curve448")
        private_key2 = ECC.construct(seed=b"H" * 56, curve="curve448")
        private_key3 = ECC.construct(seed=b"C" * 56, curve="Curve448")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        assert private_key == private_key2
        assert private_key != private_key3

        assert public_key == public_key2
        assert public_key != public_key3

        assert public_key != private_key

    def test_name_consistency(self):
        key = ECC.generate(curve="curve448")
        assert "curve='Curve448'" in repr(key)
        assert key.curve == "Curve448"
        assert key.public_key().curve == "Curve448"


class TestEccModule_Curve448:
    def test_generate(self):
        key = ECC.generate(curve="Curve448")
        assert key.has_private()
        point = EccXPoint(_curves["Curve448"].Gx, curve="Curve448") * key.d
        assert key.pointQ == point

        # Always random
        key2 = ECC.generate(curve="Curve448")
        assert key != key2

        # Other names
        ECC.generate(curve="curve448")

        # Random source
        key1 = ECC.generate(curve="Curve448", randfunc=SHAKE128.new().read)
        key2 = ECC.generate(curve="Curve448", randfunc=SHAKE128.new().read)
        assert key1 == key2

    def test_construct(self):
        seed = unhexlify(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        )
        point_hex = unhexlify(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        )
        Px = Integer.from_bytes(point_hex, byteorder="little")
        point = EccXPoint(Px, curve="Curve448")

        # Private key only
        key = ECC.construct(curve="Curve448", seed=seed)
        assert key.pointQ == point
        assert key.has_private()

        # Public key only
        key = ECC.construct(curve="Curve448", point_x=Px)
        assert key.pointQ == point
        assert not key.has_private()

        # Private and public key
        key = ECC.construct(curve="Curve448", seed=seed, point_x=Px)
        assert key.pointQ == point
        assert key.has_private()

        # Other names
        key = ECC.construct(curve="curve448", seed=seed)

    def test_negative_construct(self):
        coordG = {"point_x": _curves["curve448"].Gx}

        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", d=2, **coordG)
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", seed=b"H" * 55)

        # Verify you cannot construct weak keys (small-order points)
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", point_x=0)
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", point_x=1)
        p = 2**448 - 2**224 - 1
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", point_x=p - 1)
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", point_x=p)
        with pytest.raises(ValueError):
            ECC.construct(curve="Curve448", point_x=p + 1)
