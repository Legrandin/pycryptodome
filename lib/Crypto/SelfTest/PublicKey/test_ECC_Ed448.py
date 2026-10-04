# ===================================================================
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

from Crypto.Hash import SHAKE128
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey, EccPoint, _curves
from Crypto.SelfTest.st_common import list_test_cases


class TestEccPoint_Ed448(unittest.TestCase):
    Gxy = {
        "x": 0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E,
        "y": 0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14,
    }

    G2xy = {
        "x": 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA955555555555555555555555555555555555555555555555555555555,
        "y": 0xAE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D728AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED,
    }

    G3xy = {
        "x": 0x865886B9108AF6455BD64316CB6943332241B8B8CDA82C7E2BA077A4A3FCFE8DAA9CBF7F6271FD6E862B769465DA8575728173286FF2F8F,
        "y": 0xE005A8DBD5125CF706CBDA7AD43AA6449A4A8D952356C3B9FCE43C82EC4E1D58BB3A331BDB6767F0BFFA9A68FED02DAFB822AC13588ED6FC,
    }

    pointG = EccPoint(Gxy["x"], Gxy["y"], curve="ed448")
    pointG2 = EccPoint(G2xy["x"], G2xy["y"], curve="ed448")
    pointG3 = EccPoint(G3xy["x"], G3xy["y"], curve="ed448")

    def test_curve_attribute(self):
        self.assertEqual(self.pointG.curve, "Ed448")

    def test_init_xy(self):
        EccPoint(self.Gxy["x"], self.Gxy["y"], curve="Ed448")

        # Neutral point
        pai = EccPoint(0, 1, curve="Ed448")
        self.assertEqual(pai.x, 0)
        self.assertEqual(pai.y, 1)
        self.assertEqual(pai.xy, (0, 1))

        # G
        bp = self.pointG.copy()
        self.assertEqual(
            bp.x,
            0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E,
        )
        self.assertEqual(
            bp.y,
            0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14,
        )
        self.assertEqual(bp.xy, (bp.x, bp.y))

        # 2G
        bp2 = self.pointG2.copy()
        self.assertEqual(
            bp2.x,
            0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA955555555555555555555555555555555555555555555555555555555,
        )
        self.assertEqual(
            bp2.y,
            0xAE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D728AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED,
        )
        self.assertEqual(bp2.xy, (bp2.x, bp2.y))

        # 5G
        EccPoint(
            x=0x7A9F9335A48DCB0E2BA7601EEDB50DEF80CBCF728562ADA756D761E8958812808BC0D57A920C3C96F07B2D8CEFC6F950D0A99D1092030034,
            y=0xADFD751A2517EDD3B9109CE4FD580ADE260CA1823AB18FCED86551F7B698017127D7A4EE59D2B33C58405512881F225443B4731472F435EB,
            curve="Ed448",
        )

        # Catch if point is not on the curve
        self.assertRaises(ValueError, EccPoint, 34, 35, curve="Ed448")

    def test_set(self):
        pointW = EccPoint(0, 1, curve="Ed448")
        pointW.set(self.pointG)
        self.assertEqual(pointW.x, self.pointG.x)
        self.assertEqual(pointW.y, self.pointG.y)

    def test_copy(self):
        pointW = self.pointG.copy()
        self.assertEqual(pointW.x, self.pointG.x)
        self.assertEqual(pointW.y, self.pointG.y)

    def test_equal(self):
        pointH = self.pointG.copy()
        pointI = self.pointG2.copy()
        self.assertEqual(self.pointG, pointH)
        self.assertNotEqual(self.pointG, pointI)

    def test_pai(self):
        pai = EccPoint(0, 1, curve="Ed448")
        self.assertTrue(pai.is_point_at_infinity())
        self.assertEqual(pai, pai.point_at_infinity())

    def test_negate(self):
        negG = -self.pointG
        sum = self.pointG + negG
        self.assertTrue(sum.is_point_at_infinity())

    def test_addition(self):
        self.assertEqual(self.pointG + self.pointG2, self.pointG3)
        self.assertEqual(self.pointG2 + self.pointG, self.pointG3)
        self.assertEqual(self.pointG2 + self.pointG.point_at_infinity(), self.pointG2)
        self.assertEqual(self.pointG.point_at_infinity() + self.pointG2, self.pointG2)

        G5 = self.pointG2 + self.pointG3
        self.assertEqual(
            G5.x,
            0x7A9F9335A48DCB0E2BA7601EEDB50DEF80CBCF728562ADA756D761E8958812808BC0D57A920C3C96F07B2D8CEFC6F950D0A99D1092030034,
        )
        self.assertEqual(
            G5.y,
            0xADFD751A2517EDD3B9109CE4FD580ADE260CA1823AB18FCED86551F7B698017127D7A4EE59D2B33C58405512881F225443B4731472F435EB,
        )

    def test_inplace_addition(self):
        pointH = self.pointG.copy()
        pointH += self.pointG
        self.assertEqual(pointH, self.pointG2)
        pointH += self.pointG
        self.assertEqual(pointH, self.pointG3)
        pointH += self.pointG.point_at_infinity()
        self.assertEqual(pointH, self.pointG3)

    def test_doubling(self):
        pointH = self.pointG.copy()
        pointH.double()
        self.assertEqual(pointH.x, self.pointG2.x)
        self.assertEqual(pointH.y, self.pointG2.y)

        # 2*0
        pai = self.pointG.point_at_infinity()
        pointR = pai.copy()
        pointR.double()
        self.assertEqual(pointR, pai)

    def test_scalar_multiply(self):
        d = 0
        pointH = d * self.pointG
        self.assertEqual(pointH.x, 0)
        self.assertEqual(pointH.y, 1)

        d = 1
        pointH = d * self.pointG
        self.assertEqual(pointH.x, self.pointG.x)
        self.assertEqual(pointH.y, self.pointG.y)

        d = 2
        pointH = d * self.pointG
        self.assertEqual(pointH.x, self.pointG2.x)
        self.assertEqual(pointH.y, self.pointG2.y)

        d = 3
        pointH = d * self.pointG
        self.assertEqual(pointH.x, self.pointG3.x)
        self.assertEqual(pointH.y, self.pointG3.y)

        d = 4
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0x49DCBC5C6C0CCE2C1419A17226F929EA255A09CF4E0891C693FDA4BE70C74CC301B7BDF1515DD8BA21AEE1798949E120E2CE42AC48BA7F30,
        )
        self.assertEqual(
            pointH.y,
            0xD49077E4ACCDE527164B33A5DE021B979CB7C02F0457D845C90DC3227B8A5BC1C0D8F97EA1CA9472B5D444285D0D4F5B32E236F86DE51839,
        )

        d = 5
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0x7A9F9335A48DCB0E2BA7601EEDB50DEF80CBCF728562ADA756D761E8958812808BC0D57A920C3C96F07B2D8CEFC6F950D0A99D1092030034,
        )
        self.assertEqual(
            pointH.y,
            0xADFD751A2517EDD3B9109CE4FD580ADE260CA1823AB18FCED86551F7B698017127D7A4EE59D2B33C58405512881F225443B4731472F435EB,
        )

        d = 10
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0x77486F9D19F6411CDD35D30D1C3235F71936452C787E5C034134D3E8172278ACA61622BC805761CE3DAB65118A0122D73B403165D0ED303D,
        )
        self.assertEqual(
            pointH.y,
            0x4D2FEA0B026BE11024F1F0FE7E94E618E8AC17381ADA1D1BF7EE293A68FF5D0BF93C1997DC1AABDC0C7E6381428D85B6B1954A89E4CDDF67,
        )

        d = 20
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0x3C236422354600FE6763DEFCC1503737E4ED89E262D0DE3EC1E552020F2A56FE3B9E1E012D021072598C3C2821E18268BB8FB8339C0D1216,
        )
        self.assertEqual(
            pointH.y,
            0xB555B9721F630CCB05FC466DE4C74D3D2781E69ECA88E1B040844F04CAB39FD946F91C688FA42402BB38FB9C3E61231017020B219B4396E1,
        )

        d = 255
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0xBEB7F8388B05CD9C1AA2E3C0DCF31E2B563659361826225390E7748654F627D5C36CBE627E9019936B56D15D4DAD7C337C09BAC64FF4197F,
        )
        self.assertEqual(
            pointH.y,
            0x1E37312B2DD4E9440C43C6E7725FC4FA3D11E582D4863F1D018E28F50C0EFDB1F53F9B01ADA7C87FA162B1F0D72401015D57613D25F1AD53,
        )

        d = 256
        pointH = d * self.pointG
        self.assertEqual(
            pointH.x,
            0xF19C34FEB56730E3E2BE761AC0A2A2B24853B281DDA019FC35A5AB58E3696BEB39609AE756B0D20FB7CCF0D79AAF5F3BCA2E4FDB25BFAC1C,
        )
        self.assertEqual(
            pointH.y,
            0x3BEB69CC9111BFFCADDC61D363CE6FE5DD44DA4AADCE78F52E92E985D5442344CED72C4611ED0DAAC9F4F5661EAB73D7A12D25CE8A30241E,
        )

    def test_sizes(self):
        self.assertEqual(self.pointG.size_in_bits(), 448)
        self.assertEqual(self.pointG.size_in_bytes(), 56)


class TestEccKey_Ed448(unittest.TestCase):
    def test_private_key(self):
        seed = unhexlify(
            "4adf5d37ac6785e83e99a924f92676d366a78690af59c92b6bdf14f9cdbcf26fdad478109607583d633b60078d61d51d81b7509c5433b0d4c9"
        )
        Px = 0x72A01EEA003A35F9AC44231DC4AAE2A382F351D80BF32508175B0855EDCF389AA2BBF308DD961CE361A6E7C2091BC78957F6EBCF3002A617
        Py = 0x9E0D08D84586E9AEEFECACB41D049B831F1A3EE0C3EADA63E34557B30702B50AB59FB372FEFF7C30B8CBB7DD51AFBE88444EC56238722EC1

        key = EccKey(curve="Ed448", seed=seed)
        self.assertEqual(key.seed, seed)
        self.assertEqual(
            key.d,
            0xB07CF179604F83433186E5178760C759C15125EE54FF6F8DCDE46E872B709AC82ED0BD0A4E036D774034DCB18A9FB11894657A1485895F80,
        )
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, Px)
        self.assertEqual(key.pointQ.y, Py)

        point = EccPoint(Px, Py, "ed448")
        key = EccKey(curve="Ed448", seed=seed, point=point)
        self.assertEqual(
            key.d,
            0xB07CF179604F83433186E5178760C759C15125EE54FF6F8DCDE46E872B709AC82ED0BD0A4E036D774034DCB18A9FB11894657A1485895F80,
        )
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="ed448", seed=seed)

        # Must not accept d parameter
        self.assertRaises(ValueError, EccKey, curve="ed448", d=1)

    def test_public_key(self):
        point = EccPoint(_curves["ed448"].Gx, _curves["ed448"].Gy, curve="ed448")
        key = EccKey(curve="ed448", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):
        priv_key = EccKey(curve="ed448", seed=b"H" * 57)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_seed(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="ed448", seed=b"H" * 56))

    def test_equality(self):
        private_key = ECC.construct(seed=b"H" * 57, curve="Ed448")
        private_key2 = ECC.construct(seed=b"H" * 57, curve="ed448")
        private_key3 = ECC.construct(seed=b"C" * 57, curve="Ed448")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="ed448")
        self.assertIn("curve='Ed448'", repr(key))
        self.assertEqual(key.curve, "Ed448")
        self.assertEqual(key.public_key().curve, "Ed448")


class TestEccModule_Ed448(unittest.TestCase):
    def test_generate(self):
        key = ECC.generate(curve="Ed448")
        self.assertTrue(key.has_private())
        point = EccPoint(_curves["Ed448"].Gx, _curves["Ed448"].Gy, curve="Ed448") * key.d
        self.assertEqual(key.pointQ, point)

        # Always random
        key2 = ECC.generate(curve="Ed448")
        self.assertNotEqual(key, key2)

        # Other names
        ECC.generate(curve="Ed448")

        # Random source
        key1 = ECC.generate(curve="Ed448", randfunc=SHAKE128.new().read)
        key2 = ECC.generate(curve="Ed448", randfunc=SHAKE128.new().read)
        self.assertEqual(key1, key2)

    def test_construct(self):
        seed = unhexlify(
            "4adf5d37ac6785e83e99a924f92676d366a78690af59c92b6bdf14f9cdbcf26fdad478109607583d633b60078d61d51d81b7509c5433b0d4c9"
        )
        Px = 0x72A01EEA003A35F9AC44231DC4AAE2A382F351D80BF32508175B0855EDCF389AA2BBF308DD961CE361A6E7C2091BC78957F6EBCF3002A617
        Py = 0x9E0D08D84586E9AEEFECACB41D049B831F1A3EE0C3EADA63E34557B30702B50AB59FB372FEFF7C30B8CBB7DD51AFBE88444EC56238722EC1
        point = EccPoint(Px, Py, curve="Ed448")

        # Private key only
        key = ECC.construct(curve="Ed448", seed=seed)
        self.assertEqual(key.pointQ, point)
        self.assertTrue(key.has_private())

        # Public key only
        key = ECC.construct(curve="Ed448", point_x=Px, point_y=Py)
        self.assertEqual(key.pointQ, point)
        self.assertFalse(key.has_private())

        # Private and public key
        key = ECC.construct(curve="Ed448", seed=seed, point_x=Px, point_y=Py)
        self.assertEqual(key.pointQ, point)
        self.assertTrue(key.has_private())

        # Other names
        key = ECC.construct(curve="ed448", seed=seed)

    def test_negative_construct(self):
        coord = {"point_x": 10, "point_y": 4}
        coordG = {"point_x": _curves["ed448"].Gx, "point_y": _curves["ed448"].Gy}

        self.assertRaises(ValueError, ECC.construct, curve="Ed448", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="Ed448", d=2, **coordG)
        self.assertRaises(ValueError, ECC.construct, curve="Ed448", seed=b"H" * 58)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestEccPoint_Ed448)
    tests += list_test_cases(TestEccKey_Ed448)
    tests += list_test_cases(TestEccModule_Ed448)
    return tests


if __name__ == "__main__":

    def suite():
        return unittest.TestSuite(get_tests())

    unittest.main(defaultTest="suite")
