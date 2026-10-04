# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
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

from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey, EccPoint, _curves
from Crypto.SelfTest.loader import load_test_vectors
from Crypto.SelfTest.st_common import list_test_cases


class TestEccPoint(unittest.TestCase):
    def test_mix(self):

        p1 = ECC.generate(curve="P-256").pointQ
        p2 = ECC.generate(curve="P-384").pointQ

        try:
            p1 + p2
            raise AssertionError()
        except ValueError as e:
            assert "not on the same curve" in str(e)

        try:
            p1 += p2
            raise AssertionError()
        except ValueError as e:
            assert "not on the same curve" in str(e)

        class OtherKeyType:
            pass

        self.assertFalse(p1 == OtherKeyType())
        self.assertTrue(p1 != OtherKeyType())

    def test_repr(self):
        p1 = ECC.construct(
            curve="P-256",
            d=75467964919405407085864614198393977741148485328036093939970922195112333446269,
            point_x=20573031766139722500939782666697015100983491952082159880539639074939225934381,
            point_y=108863130203210779921520632367477406025152638284581252625277850513266505911389,
        )
        self.assertEqual(
            repr(p1),
            "EccKey(curve='NIST P-256', point_x=20573031766139722500939782666697015100983491952082159880539639074939225934381, point_y=108863130203210779921520632367477406025152638284581252625277850513266505911389, d=75467964919405407085864614198393977741148485328036093939970922195112333446269)",
        )


class TestEccPoint_NIST_P192(unittest.TestCase):
    """Tests defined in section 4.1 of https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf"""

    pointS = EccPoint(
        0xD458E7D127AE671B0C330266D246769353A012073E97ACF8,
        0x325930500D851F336BDDC050CF7FB11B5673A1645086DF3B,
        curve="p192",
    )

    pointT = EccPoint(
        0xF22C4395213E9EBE67DDECDD87FDBD01BE16FB059B9753A4,
        0x264424096AF2B3597796DB48F8DFB41FA9CECC97691A9C79,
        curve="p192",
    )

    def test_curve_attribute(self):
        self.assertEqual(self.pointS.curve, "NIST P-192")

    def test_set(self):
        pointW = EccPoint(0, 0)
        pointW.set(self.pointS)
        self.assertEqual(pointW, self.pointS)

    def test_copy(self):
        pointW = self.pointS.copy()
        self.assertEqual(pointW, self.pointS)
        pointW.set(self.pointT)
        self.assertEqual(pointW, self.pointT)
        self.assertNotEqual(self.pointS, self.pointT)

    def test_negate(self):
        negS = -self.pointS
        sum = self.pointS + negS
        self.assertEqual(sum, self.pointS.point_at_infinity())

    def test_addition(self):
        pointRx = 0x48E1E4096B9B8E5CA9D0F1F077B8ABF58E843894DE4D0290
        pointRy = 0x408FA77C797CD7DBFB16AA48A3648D3D63C94117D7B6AA4B

        pointR = self.pointS + self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS + pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai + self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai + pai
        self.assertEqual(pointR, pai)

    def test_inplace_addition(self):
        pointRx = 0x48E1E4096B9B8E5CA9D0F1F077B8ABF58E843894DE4D0290
        pointRy = 0x408FA77C797CD7DBFB16AA48A3648D3D63C94117D7B6AA4B

        pointR = self.pointS.copy()
        pointR += self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS.copy()
        pointR += pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.copy()
        pointR += self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.copy()
        pointR += pai
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = 0x30C5BC6B8C7DA25354B373DC14DD8A0EBA42D25A3F6E6962
        pointRy = 0x0DDE14BC4249A721C407AEDBF011E2DDBBCB2968C9D889CF

        pointR = self.pointS.copy()
        pointR.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

        # S + S
        pointR = self.pointS.copy()
        pointR += pointR
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0xA78A236D60BAEC0C5DD41B33A542463A8255391AF64C74EE
        pointRx = 0x1FAEE4205A4F669D2D0A8F25E3BCEC9A62A6952965BF6D31
        pointRy = 0x5FF2CDFA508A2581892367087C696F179E7A4D7E8260FB06

        pointR = self.pointS * d
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS * 0
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, lambda: self.pointS * -1)

        # Reverse order
        pointR = d * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pointR = Integer(d) * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_joint_scalar_multiply(self):
        d = 0xA78A236D60BAEC0C5DD41B33A542463A8255391AF64C74EE
        e = 0xC4BE3D53EC3089E71E4DE8CEAB7CCE889BC393CD85B972BC
        pointRx = 0x019F64EED8FA9B72B7DFEA82C17C9BFA60ECB9E1778B5BDE
        pointRy = 0x16590C5FCD8655FA4CED33FB800E2A7E3C61F35D83503644

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_sizes(self):
        self.assertEqual(self.pointS.size_in_bits(), 192)
        self.assertEqual(self.pointS.size_in_bytes(), 24)


class TestEccPoint_NIST_P224(unittest.TestCase):
    """Tests defined in section 4.2 of https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf"""

    pointS = EccPoint(
        0x6ECA814BA59A930843DC814EDD6C97DA95518DF3C6FDF16E9A10BB5B,
        0xEF4B497F0963BC8B6AEC0CA0F259B89CD80994147E05DC6B64D7BF22,
        curve="p224",
    )

    pointT = EccPoint(
        0xB72B25AEA5CB03FB88D7E842002969648E6EF23C5D39AC903826BD6D,
        0xC42A8A4D34984F0B71B5B4091AF7DCEB33EA729C1A2DC8B434F10C34,
        curve="p224",
    )

    def test_curve_attribute(self):
        self.assertEqual(self.pointS.curve, "NIST P-224")

    def test_set(self):
        pointW = EccPoint(0, 0)
        pointW.set(self.pointS)
        self.assertEqual(pointW, self.pointS)

    def test_copy(self):
        pointW = self.pointS.copy()
        self.assertEqual(pointW, self.pointS)
        pointW.set(self.pointT)
        self.assertEqual(pointW, self.pointT)
        self.assertNotEqual(self.pointS, self.pointT)

    def test_negate(self):
        negS = -self.pointS
        sum = self.pointS + negS
        self.assertEqual(sum, self.pointS.point_at_infinity())

    def test_addition(self):
        pointRx = 0x236F26D9E84C2F7D776B107BD478EE0A6D2BCFCAA2162AFAE8D2FD15
        pointRy = 0xE53CC0A7904CE6C3746F6A97471297A0B7D5CDF8D536AE25BB0FDA70

        pointR = self.pointS + self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS + pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai + self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai + pai
        self.assertEqual(pointR, pai)

    def test_inplace_addition(self):
        pointRx = 0x236F26D9E84C2F7D776B107BD478EE0A6D2BCFCAA2162AFAE8D2FD15
        pointRy = 0xE53CC0A7904CE6C3746F6A97471297A0B7D5CDF8D536AE25BB0FDA70

        pointR = self.pointS.copy()
        pointR += self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS.copy()
        pointR += pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.copy()
        pointR += self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.copy()
        pointR += pai
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = 0xA9C96F2117DEE0F27CA56850EBB46EFAD8EE26852F165E29CB5CDFC7
        pointRy = 0xADF18C84CF77CED4D76D4930417D9579207840BF49BFBF5837DFDD7D

        pointR = self.pointS.copy()
        pointR.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

        # S + S
        pointR = self.pointS.copy()
        pointR += pointR
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0xA78CCC30EACA0FCC8E36B2DD6FBB03DF06D37F52711E6363AAF1D73B
        pointRx = 0x96A7625E92A8D72BFF1113ABDB95777E736A14C6FDAACC392702BCA4
        pointRy = 0x0F8E5702942A3C5E13CD2FD5801915258B43DFADC70D15DBADA3ED10

        pointR = self.pointS * d
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS * 0
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, lambda: self.pointS * -1)

        # Reverse order
        pointR = d * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pointR = Integer(d) * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_joing_scalar_multiply(self):
        d = 0xA78CCC30EACA0FCC8E36B2DD6FBB03DF06D37F52711E6363AAF1D73B
        e = 0x54D549FFC08C96592519D73E71E8E0703FC8177FA88AA77A6ED35736
        pointRx = 0xDBFE2958C7B2CDA1302A67EA3FFD94C918C5B350AB838D52E288C83E
        pointRy = 0x2F521B83AC3B0549FF4895ABCC7F0C5A861AACB87ACBC5B8147BB18B

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_sizes(self):
        self.assertEqual(self.pointS.size_in_bits(), 224)
        self.assertEqual(self.pointS.size_in_bytes(), 28)


class TestEccPoint_NIST_P256(unittest.TestCase):
    """Tests defined in section 4.3 of https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf"""

    pointS = EccPoint(
        0xDE2444BEBC8D36E682EDD27E0F271508617519B3221A8FA0B77CAB3989DA97C9,
        0xC093AE7FF36E5380FC01A5AAD1E66659702DE80F53CEC576B6350B243042A256,
    )

    pointT = EccPoint(
        0x55A8B00F8DA1D44E62F6B3B25316212E39540DC861C89575BB8CF92E35E0986B,
        0x5421C3209C2D6C704835D82AC4C3DD90F61A8A52598B9E7AB656E9D8C8B24316,
    )

    def test_curve_attribute(self):
        self.assertEqual(self.pointS.curve, "NIST P-256")

    def test_set(self):
        pointW = EccPoint(0, 0)
        pointW.set(self.pointS)
        self.assertEqual(pointW, self.pointS)

    def test_copy(self):
        pointW = self.pointS.copy()
        self.assertEqual(pointW, self.pointS)
        pointW.set(self.pointT)
        self.assertEqual(pointW, self.pointT)
        self.assertNotEqual(self.pointS, self.pointT)

    def test_negate(self):
        negS = -self.pointS
        sum = self.pointS + negS
        self.assertEqual(sum, self.pointS.point_at_infinity())

    def test_addition(self):
        pointRx = 0x72B13DD4354B6B81745195E98CC5BA6970349191AC476BD4553CF35A545A067E
        pointRy = 0x8D585CBB2E1327D75241A8A122D7620DC33B13315AA5C9D46D013011744AC264

        pointR = self.pointS + self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS + pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai + self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai + pai
        self.assertEqual(pointR, pai)

    def test_inplace_addition(self):
        pointRx = 0x72B13DD4354B6B81745195E98CC5BA6970349191AC476BD4553CF35A545A067E
        pointRy = 0x8D585CBB2E1327D75241A8A122D7620DC33B13315AA5C9D46D013011744AC264

        pointR = self.pointS.copy()
        pointR += self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS.copy()
        pointR += pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.copy()
        pointR += self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.copy()
        pointR += pai
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = 0x7669E6901606EE3BA1A8EEF1E0024C33DF6C22F3B17481B82A860FFCDB6127B0
        pointRy = 0xFA878162187A54F6C39F6EE0072F33DE389EF3EECD03023DE10CA2C1DB61D0C7

        pointR = self.pointS.copy()
        pointR.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

        # S + S
        pointR = self.pointS.copy()
        pointR += pointR
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0xC51E4753AFDEC1E6B6C6A5B992F43F8DD0C7A8933072708B6522468B2FFB06FD
        pointRx = 0x51D08D5F2D4278882946D88D83C97D11E62BECC3CFC18BEDACC89BA34EECA03F
        pointRy = 0x75EE68EB8BF626AA5B673AB51F6E744E06F8FCF8A6C0CF3035BECA956A7B41D5

        pointR = self.pointS * d
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS * 0
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, lambda: self.pointS * -1)

        # Reverse order
        pointR = d * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pointR = Integer(d) * self.pointS
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_joing_scalar_multiply(self):
        d = 0xC51E4753AFDEC1E6B6C6A5B992F43F8DD0C7A8933072708B6522468B2FFB06FD
        e = 0xD37F628ECE72A462F0145CBEFE3F0B355EE8332D37ACDD83A358016AEA029DB7
        pointRx = 0xD867B4679221009234939221B8046245EFCF58413DAACBEFF857B8588341F6B8
        pointRy = 0xF2504055C03CEDE12D22720DAD69C745106B6607EC7E50DD35D54BD80F615275

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_sizes(self):
        self.assertEqual(self.pointS.size_in_bits(), 256)
        self.assertEqual(self.pointS.size_in_bytes(), 32)


class TestEccPoint_NIST_P384(unittest.TestCase):
    """Tests defined in section 4.4 of https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf"""

    pointS = EccPoint(
        0xFBA203B81BBD23F2B3BE971CC23997E1AE4D89E69CB6F92385DDA82768ADA415EBAB4167459DA98E62B1332D1E73CB0E,
        0x5FFEDBAEFDEBA603E7923E06CDB5D0C65B22301429293376D5C6944E3FA6259F162B4788DE6987FD59AED5E4B5285E45,
        "p384",
    )

    pointT = EccPoint(
        0xAACC05202E7FDA6FC73D82F0A66220527DA8117EE8F8330EAD7D20EE6F255F582D8BD38C5A7F2B40BCDB68BA13D81051,
        0x84009A263FEFBA7C2C57CFFA5DB3634D286131AFC0FCA8D25AFA22A7B5DCE0D9470DA89233CEE178592F49B6FECB5092,
        "p384",
    )

    def test_curve_attribute(self):
        self.assertEqual(self.pointS.curve, "NIST P-384")

    def test_set(self):
        pointW = EccPoint(0, 0, "p384")
        pointW.set(self.pointS)
        self.assertEqual(pointW, self.pointS)

    def test_copy(self):
        pointW = self.pointS.copy()
        self.assertEqual(pointW, self.pointS)
        pointW.set(self.pointT)
        self.assertEqual(pointW, self.pointT)
        self.assertNotEqual(self.pointS, self.pointT)

    def test_negate(self):
        negS = -self.pointS
        sum = self.pointS + negS
        self.assertEqual(sum, self.pointS.point_at_infinity())

    def test_addition(self):
        pointRx = (
            0x12DC5CE7ACDFC5844D939F40B4DF012E68F865B89C3213BA97090A247A2FC009075CF471CD2E85C489979B65EE0B5EED
        )
        pointRy = (
            0x167312E58FE0C0AFA248F2854E3CDDCB557F983B3189B67F21EEE01341E7E9FE67F6EE81B36988EFA406945C8804A4B0
        )

        pointR = self.pointS + self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS + pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai + self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai + pai
        self.assertEqual(pointR, pai)

    def _test_inplace_addition(self):
        pointRx = 0x72B13DD4354B6B81745195E98CC5BA6970349191AC476BD4553CF35A545A067E
        pointRy = 0x8D585CBB2E1327D75241A8A122D7620DC33B13315AA5C9D46D013011744AC264

        pointR = self.pointS.copy()
        pointR += self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS.copy()
        pointR += pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.copy()
        pointR += self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.copy()
        pointR += pai
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = (
            0x2A2111B1E0AA8B2FC5A1975516BC4D58017FF96B25E1BDFF3C229D5FAC3BACC319DCBEC29F9478F42DEE597B4641504C
        )
        pointRy = (
            0xFA2E3D9DC84DB8954CE8085EF28D7184FDDFD1344B4D4797343AF9B5F9D837520B450F726443E4114BD4E5BDB2F65DDD
        )

        pointR = self.pointS.copy()
        pointR.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

        # S + S
        pointR = self.pointS.copy()
        pointR += pointR
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0xA4EBCAE5A665983493AB3E626085A24C104311A761B5A8FDAC052ED1F111A5C44F76F45659D2D111A61B5FDD97583480
        pointRx = (
            0xE4F77E7FFEB7F0958910E3A680D677A477191DF166160FF7EF6BB5261F791AA7B45E3E653D151B95DAD3D93CA0290EF2
        )
        pointRy = (
            0xAC7DEE41D8C5F4A7D5836960A773CFC1376289D3373F8CF7417B0C6207AC32E913856612FC9FF2E357EB2EE05CF9667F
        )

        pointR = self.pointS * d
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS * 0
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, lambda: self.pointS * -1)

    def test_joing_scalar_multiply(self):
        d = 0xA4EBCAE5A665983493AB3E626085A24C104311A761B5A8FDAC052ED1F111A5C44F76F45659D2D111A61B5FDD97583480
        e = 0xAFCF88119A3A76C87ACBD6008E1349B29F4BA9AA0E12CE89BCFCAE2180B38D81AB8CF15095301A182AFBC6893E75385D
        pointRx = (
            0x917EA28BCD641741AE5D18C2F1BD917BA68D34F0F0577387DC81260462AEA60E2417B8BDC5D954FC729D211DB23A02DC
        )
        pointRy = (
            0x1A29F7CE6D074654D77B40888C73E92546C8F16A5FF6BCBD307F758D4AEE684BEFF26F6742F597E2585C86DA908F7186
        )

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_sizes(self):
        self.assertEqual(self.pointS.size_in_bits(), 384)
        self.assertEqual(self.pointS.size_in_bytes(), 48)


class TestEccPoint_NIST_P521(unittest.TestCase):
    """Tests defined in section 4.5 of https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.204.9073&rep=rep1&type=pdf"""

    pointS = EccPoint(
        0x000001D5C693F66C08ED03AD0F031F937443458F601FD098D3D0227B4BF62873AF50740B0BB84AA157FC847BCF8DC16A8B2B8BFD8E2D0A7D39AF04B089930EF6DAD5C1B4,
        0x00000144B7770963C63A39248865FF36B074151EAC33549B224AF5C8664C54012B818ED037B2B7C1A63AC89EBAA11E07DB89FCEE5B556E49764EE3FA66EA7AE61AC01823,
        "p521",
    )

    pointT = EccPoint(
        0x000000F411F2AC2EB971A267B80297BA67C322DBA4BB21CEC8B70073BF88FC1CA5FDE3BA09E5DF6D39ACB2C0762C03D7BC224A3E197FEAF760D6324006FE3BE9A548C7D5,
        0x000001FDF842769C707C93C630DF6D02EFF399A06F1B36FB9684F0B373ED064889629ABB92B1AE328FDB45534268384943F0E9222AFE03259B32274D35D1B9584C65E305,
        "p521",
    )

    def test_curve_attribute(self):
        self.assertEqual(self.pointS.curve, "NIST P-521")

    def test_set(self):
        pointW = EccPoint(0, 0)
        pointW.set(self.pointS)
        self.assertEqual(pointW, self.pointS)

    def test_copy(self):
        pointW = self.pointS.copy()
        self.assertEqual(pointW, self.pointS)
        pointW.set(self.pointT)
        self.assertEqual(pointW, self.pointT)
        self.assertNotEqual(self.pointS, self.pointT)

    def test_negate(self):
        negS = -self.pointS
        sum = self.pointS + negS
        self.assertEqual(sum, self.pointS.point_at_infinity())

    def test_addition(self):
        pointRx = 0x000001264AE115BA9CBC2EE56E6F0059E24B52C8046321602C59A339CFB757C89A59C358A9A8E1F86D384B3F3B255EA3F73670C6DC9F45D46B6A196DC37BBE0F6B2DD9E9
        pointRy = 0x00000062A9C72B8F9F88A271690BFA017A6466C31B9CADC2FC544744AEB817072349CFDDC5AD0E81B03F1897BD9C8C6EFBDF68237DC3BB00445979FB373B20C9A967AC55

        pointR = self.pointS + self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS + pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai + self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai + pai
        self.assertEqual(pointR, pai)

    def test_inplace_addition(self):
        pointRx = 0x000001264AE115BA9CBC2EE56E6F0059E24B52C8046321602C59A339CFB757C89A59C358A9A8E1F86D384B3F3B255EA3F73670C6DC9F45D46B6A196DC37BBE0F6B2DD9E9
        pointRy = 0x00000062A9C72B8F9F88A271690BFA017A6466C31B9CADC2FC544744AEB817072349CFDDC5AD0E81B03F1897BD9C8C6EFBDF68237DC3BB00445979FB373B20C9A967AC55

        pointR = self.pointS.copy()
        pointR += self.pointT
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = pointR.point_at_infinity()

        # S + 0
        pointR = self.pointS.copy()
        pointR += pai
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.copy()
        pointR += self.pointS
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.copy()
        pointR += pai
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = 0x0000012879442F2450C119E7119A5F738BE1F1EBA9E9D7C6CF41B325D9CE6D643106E9D61124A91A96BCF201305A9DEE55FA79136DC700831E54C3CA4FF2646BD3C36BC6
        pointRy = 0x0000019864A8B8855C2479CBEFE375AE553E2393271ED36FADFC4494FC0583F6BD03598896F39854ABEAE5F9A6515A021E2C0EEF139E71DE610143F53382F4104DCCB543

        pointR = self.pointS.copy()
        pointR.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

        # S + S
        pointR = self.pointS.copy()
        pointR += pointR
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0x000001EB7F81785C9629F136A7E8F8C674957109735554111A2A866FA5A166699419BFA9936C78B62653964DF0D6DA940A695C7294D41B2D6600DE6DFCF0EDCFC89FDCB1
        pointRx = 0x00000091B15D09D0CA0353F8F96B93CDB13497B0A4BB582AE9EBEFA35EEE61BF7B7D041B8EC34C6C00C0C0671C4AE063318FB75BE87AF4FE859608C95F0AB4774F8C95BB
        pointRy = 0x00000130F8F8B5E1ABB4DD94F6BAAF654A2D5810411E77B7423965E0C7FD79EC1AE563C207BD255EE9828EB7A03FED565240D2CC80DDD2CECBB2EB50F0951F75AD87977F

        pointR = self.pointS * d
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS * 0
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, lambda: self.pointS * -1)

    def test_joing_scalar_multiply(self):
        d = 0x000001EB7F81785C9629F136A7E8F8C674957109735554111A2A866FA5A166699419BFA9936C78B62653964DF0D6DA940A695C7294D41B2D6600DE6DFCF0EDCFC89FDCB1
        e = 0x00000137E6B73D38F153C3A7575615812608F2BAB3229C92E21C0D1C83CFAD9261DBB17BB77A63682000031B9122C2F0CDAB2AF72314BE95254DE4291A8F85F7C70412E3
        pointRx = 0x0000009D3802642B3BEA152BEB9E05FBA247790F7FC168072D363340133402F2585588DC1385D40EBCB8552F8DB02B23D687CAE46185B27528ADB1BF9729716E4EBA653D
        pointRy = 0x0000000FE44344E79DA6F49D87C1063744E5957D9AC0A505BAFA8281C9CE9FF25AD53F8DA084A2DEB0923E46501DE5797850C61B229023DD9CF7FC7F04CD35EBB026D89D

        pointR = self.pointS * d
        pointR += self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_sizes(self):
        self.assertEqual(self.pointS.size_in_bits(), 521)
        self.assertEqual(self.pointS.size_in_bytes(), 66)


class TestEccPoint_PAI_P192(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves["p192"]
    pointG = EccPoint(curve.Gx, curve.Gy, "p192")


tv_pai = (
    load_test_vectors(
        ("PublicKey", "ECC"),
        "point-at-infinity.org-P192.txt",
        "P-192 tests from point-at-infinity.org",
        {"k": lambda k: int(k), "x": lambda x: int(x, 16), "y": lambda y: int(y, 16)},
    )
    or []
)
for tv in tv_pai:

    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)

    setattr(TestEccPoint_PAI_P192, "test_%d" % tv.count, new_test)


class TestEccPoint_PAI_P224(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves["p224"]
    pointG = EccPoint(curve.Gx, curve.Gy, "p224")


tv_pai = (
    load_test_vectors(
        ("PublicKey", "ECC"),
        "point-at-infinity.org-P224.txt",
        "P-224 tests from point-at-infinity.org",
        {"k": lambda k: int(k), "x": lambda x: int(x, 16), "y": lambda y: int(y, 16)},
    )
    or []
)
for tv in tv_pai:

    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)

    setattr(TestEccPoint_PAI_P224, "test_%d" % tv.count, new_test)


class TestEccPoint_PAI_P256(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves["p256"]
    pointG = EccPoint(curve.Gx, curve.Gy, "p256")


tv_pai = (
    load_test_vectors(
        ("PublicKey", "ECC"),
        "point-at-infinity.org-P256.txt",
        "P-256 tests from point-at-infinity.org",
        {"k": lambda k: int(k), "x": lambda x: int(x, 16), "y": lambda y: int(y, 16)},
    )
    or []
)
for tv in tv_pai:

    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)

    setattr(TestEccPoint_PAI_P256, "test_%d" % tv.count, new_test)


class TestEccPoint_PAI_P384(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves["p384"]
    pointG = EccPoint(curve.Gx, curve.Gy, "p384")


tv_pai = (
    load_test_vectors(
        ("PublicKey", "ECC"),
        "point-at-infinity.org-P384.txt",
        "P-384 tests from point-at-infinity.org",
        {"k": lambda k: int(k), "x": lambda x: int(x, 16), "y": lambda y: int(y, 16)},
    )
    or []
)
for tv in tv_pai:

    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)

    setattr(TestEccPoint_PAI_P384, "test_%d" % tv.count, new_test)


class TestEccPoint_PAI_P521(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves["p521"]
    pointG = EccPoint(curve.Gx, curve.Gy, "p521")


tv_pai = (
    load_test_vectors(
        ("PublicKey", "ECC"),
        "point-at-infinity.org-P521.txt",
        "P-521 tests from point-at-infinity.org",
        {"k": lambda k: int(k), "x": lambda x: int(x, 16), "y": lambda y: int(y, 16)},
    )
    or []
)
for tv in tv_pai:

    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)

    setattr(TestEccPoint_PAI_P521, "test_%d" % tv.count, new_test)


class TestEccKey_P192(unittest.TestCase):
    def test_private_key(self):

        key = EccKey(curve="P-192", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, _curves["p192"].Gx)
        self.assertEqual(key.pointQ.y, _curves["p192"].Gy)

        point = EccPoint(_curves["p192"].Gx, _curves["p192"].Gy, curve="P-192")
        key = EccKey(curve="P-192", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="secp192r1", d=1)
        key = EccKey(curve="prime192v1", d=1)

    def test_public_key(self):

        point = EccPoint(_curves["p192"].Gx, _curves["p192"].Gy, curve="P-192")
        key = EccKey(curve="P-192", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-192", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-193", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-192", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-192", d=_curves["p192"].order))

    def test_equality(self):

        private_key = ECC.construct(d=3, curve="P-192")
        private_key2 = ECC.construct(d=3, curve="P-192")
        private_key3 = ECC.construct(d=4, curve="P-192")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="p192")
        self.assertIn("curve='NIST P-192'", repr(key))
        self.assertEqual(key.curve, "NIST P-192")
        self.assertEqual(key.public_key().curve, "NIST P-192")


class TestEccKey_P224(unittest.TestCase):
    def test_private_key(self):

        key = EccKey(curve="P-224", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, _curves["p224"].Gx)
        self.assertEqual(key.pointQ.y, _curves["p224"].Gy)

        point = EccPoint(_curves["p224"].Gx, _curves["p224"].Gy, curve="P-224")
        key = EccKey(curve="P-224", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="secp224r1", d=1)
        key = EccKey(curve="prime224v1", d=1)

    def test_public_key(self):

        point = EccPoint(_curves["p224"].Gx, _curves["p224"].Gy, curve="P-224")
        key = EccKey(curve="P-224", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-224", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-225", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-224", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-224", d=_curves["p224"].order))

    def test_equality(self):

        private_key = ECC.construct(d=3, curve="P-224")
        private_key2 = ECC.construct(d=3, curve="P-224")
        private_key3 = ECC.construct(d=4, curve="P-224")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="p224")
        self.assertIn("curve='NIST P-224'", repr(key))
        self.assertEqual(key.curve, "NIST P-224")
        self.assertEqual(key.public_key().curve, "NIST P-224")


class TestEccKey_P256(unittest.TestCase):
    def test_private_key(self):

        key = EccKey(curve="P-256", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, _curves["p256"].Gx)
        self.assertEqual(key.pointQ.y, _curves["p256"].Gy)

        point = EccPoint(_curves["p256"].Gx, _curves["p256"].Gy)
        key = EccKey(curve="P-256", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="secp256r1", d=1)
        key = EccKey(curve="prime256v1", d=1)

        # Must not accept d parameter
        self.assertRaises(ValueError, EccKey, curve="p256", seed=b"H" * 32)

    def test_public_key(self):

        point = EccPoint(_curves["p256"].Gx, _curves["p256"].Gy)
        key = EccKey(curve="P-256", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-256", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-257", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=_curves["p256"].order))

    def test_equality(self):

        private_key = ECC.construct(d=3, curve="P-256")
        private_key2 = ECC.construct(d=3, curve="P-256")
        private_key3 = ECC.construct(d=4, curve="P-256")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="p256")
        self.assertIn("curve='NIST P-256'", repr(key))
        self.assertEqual(key.curve, "NIST P-256")
        self.assertEqual(key.public_key().curve, "NIST P-256")


class TestEccKey_P384(unittest.TestCase):
    def test_private_key(self):

        p384 = _curves["p384"]

        key = EccKey(curve="P-384", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, p384.Gx)
        self.assertEqual(key.pointQ.y, p384.Gy)

        point = EccPoint(p384.Gx, p384.Gy, "p384")
        key = EccKey(curve="P-384", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="p384", d=1)
        key = EccKey(curve="secp384r1", d=1)
        key = EccKey(curve="prime384v1", d=1)

    def test_public_key(self):

        p384 = _curves["p384"]
        point = EccPoint(p384.Gx, p384.Gy, "p384")
        key = EccKey(curve="P-384", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-384", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-385", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-384", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-384", d=_curves["p384"].order))

    def test_equality(self):

        private_key = ECC.construct(d=3, curve="P-384")
        private_key2 = ECC.construct(d=3, curve="P-384")
        private_key3 = ECC.construct(d=4, curve="P-384")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="p384")
        self.assertIn("curve='NIST P-384'", repr(key))
        self.assertEqual(key.curve, "NIST P-384")
        self.assertEqual(key.public_key().curve, "NIST P-384")


class TestEccKey_P521(unittest.TestCase):
    def test_private_key(self):

        p521 = _curves["p521"]

        key = EccKey(curve="P-521", d=1)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, p521.Gx)
        self.assertEqual(key.pointQ.y, p521.Gy)

        point = EccPoint(p521.Gx, p521.Gy, "p521")
        key = EccKey(curve="P-521", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="p521", d=1)
        key = EccKey(curve="secp521r1", d=1)
        key = EccKey(curve="prime521v1", d=1)

    def test_public_key(self):

        p521 = _curves["p521"]
        point = EccPoint(p521.Gx, p521.Gy, "p521")
        key = EccKey(curve="P-384", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-521", d=3)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-522", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-521", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-521", d=_curves["p521"].order))

    def test_equality(self):

        private_key = ECC.construct(d=3, curve="P-521")
        private_key2 = ECC.construct(d=3, curve="P-521")
        private_key3 = ECC.construct(d=4, curve="P-521")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="p521")
        self.assertIn("curve='NIST P-521'", repr(key))
        self.assertEqual(key.curve, "NIST P-521")
        self.assertEqual(key.public_key().curve, "NIST P-521")


class TestEccModule_P192(unittest.TestCase):
    def test_generate(self):

        key = ECC.generate(curve="P-192")
        self.assertTrue(key.has_private())
        self.assertEqual(
            key.pointQ, EccPoint(_curves["p192"].Gx, _curves["p192"].Gy, "P-192") * key.d, "p192"
        )

        # Other names
        ECC.generate(curve="secp192r1")
        ECC.generate(curve="prime192v1")

    def test_construct(self):

        key = ECC.construct(curve="P-192", d=1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, _curves["p192"].G)

        key = ECC.construct(curve="P-192", point_x=_curves["p192"].Gx, point_y=_curves["p192"].Gy)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, _curves["p192"].G)

        # Other names
        ECC.construct(curve="p192", d=1)
        ECC.construct(curve="secp192r1", d=1)
        ECC.construct(curve="prime192v1", d=1)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["p192"].Gx, "point_y": _curves["p192"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="P-192", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-192", d=2, **coordG)


class TestEccModule_P224(unittest.TestCase):
    def test_generate(self):

        key = ECC.generate(curve="P-224")
        self.assertTrue(key.has_private())
        self.assertEqual(
            key.pointQ, EccPoint(_curves["p224"].Gx, _curves["p224"].Gy, "P-224") * key.d, "p224"
        )

        # Other names
        ECC.generate(curve="secp224r1")
        ECC.generate(curve="prime224v1")

    def test_construct(self):

        key = ECC.construct(curve="P-224", d=1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, _curves["p224"].G)

        key = ECC.construct(curve="P-224", point_x=_curves["p224"].Gx, point_y=_curves["p224"].Gy)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, _curves["p224"].G)

        # Other names
        ECC.construct(curve="p224", d=1)
        ECC.construct(curve="secp224r1", d=1)
        ECC.construct(curve="prime224v1", d=1)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["p224"].Gx, "point_y": _curves["p224"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="P-224", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-224", d=2, **coordG)


class TestEccModule_P256(unittest.TestCase):
    def test_generate(self):

        key = ECC.generate(curve="P-256")
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(_curves["p256"].Gx, _curves["p256"].Gy) * key.d, "p256")

        # Other names
        ECC.generate(curve="secp256r1")
        ECC.generate(curve="prime256v1")

    def test_construct(self):

        key = ECC.construct(curve="P-256", d=1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, _curves["p256"].G)

        key = ECC.construct(curve="P-256", point_x=_curves["p256"].Gx, point_y=_curves["p256"].Gy)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, _curves["p256"].G)

        # Other names
        ECC.construct(curve="p256", d=1)
        ECC.construct(curve="secp256r1", d=1)
        ECC.construct(curve="prime256v1", d=1)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["p256"].Gx, "point_y": _curves["p256"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="P-256", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-256", d=2, **coordG)


class TestEccModule_P384(unittest.TestCase):
    def test_generate(self):

        curve = _curves["p384"]
        key = ECC.generate(curve="P-384")
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(curve.Gx, curve.Gy, "p384") * key.d)

        # Other names
        ECC.generate(curve="secp384r1")
        ECC.generate(curve="prime384v1")

    def test_construct(self):

        curve = _curves["p384"]
        key = ECC.construct(curve="P-384", d=1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, _curves["p384"].G)

        key = ECC.construct(curve="P-384", point_x=curve.Gx, point_y=curve.Gy)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, curve.G)

        # Other names
        ECC.construct(curve="p384", d=1)
        ECC.construct(curve="secp384r1", d=1)
        ECC.construct(curve="prime384v1", d=1)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["p384"].Gx, "point_y": _curves["p384"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="P-384", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-384", d=2, **coordG)


class TestEccModule_P521(unittest.TestCase):
    def test_generate(self):

        curve = _curves["p521"]
        key = ECC.generate(curve="P-521")
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(curve.Gx, curve.Gy, "p521") * key.d)

        # Other names
        ECC.generate(curve="secp521r1")
        ECC.generate(curve="prime521v1")

    def test_construct(self):

        curve = _curves["p521"]
        key = ECC.construct(curve="P-521", d=1)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, _curves["p521"].G)

        key = ECC.construct(curve="P-521", point_x=curve.Gx, point_y=curve.Gy)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, curve.G)

        # Other names
        ECC.construct(curve="p521", d=1)
        ECC.construct(curve="secp521r1", d=1)
        ECC.construct(curve="prime521v1", d=1)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["p521"].Gx, "point_y": _curves["p521"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="P-521", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-521", d=2, **coordG)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestEccPoint)
    tests += list_test_cases(TestEccPoint_NIST_P192)
    tests += list_test_cases(TestEccPoint_NIST_P224)
    tests += list_test_cases(TestEccPoint_NIST_P256)
    tests += list_test_cases(TestEccPoint_NIST_P384)
    tests += list_test_cases(TestEccPoint_NIST_P521)
    tests += list_test_cases(TestEccPoint_PAI_P192)
    tests += list_test_cases(TestEccPoint_PAI_P224)
    tests += list_test_cases(TestEccPoint_PAI_P256)
    tests += list_test_cases(TestEccPoint_PAI_P384)
    tests += list_test_cases(TestEccPoint_PAI_P521)
    tests += list_test_cases(TestEccKey_P192)
    tests += list_test_cases(TestEccKey_P224)
    tests += list_test_cases(TestEccKey_P256)
    tests += list_test_cases(TestEccKey_P384)
    tests += list_test_cases(TestEccKey_P521)
    tests += list_test_cases(TestEccModule_P192)
    tests += list_test_cases(TestEccModule_P224)
    tests += list_test_cases(TestEccModule_P256)
    tests += list_test_cases(TestEccModule_P384)
    tests += list_test_cases(TestEccModule_P521)
    return tests


if __name__ == "__main__":
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest="suite")
