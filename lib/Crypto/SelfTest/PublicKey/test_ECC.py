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
import time
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.loader import load_tests

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint, _curves, EccKey

class TestEccPoint_NIST_P256(unittest.TestCase):
    """Tests defined in section 4.3 of https://www.nsa.gov/ia/_files/nist-routines.pdf"""

    pointS = EccPoint(
                0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9,
                0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256)

    pointT = EccPoint(
                0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b,
                0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316)

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

    def test_addition(self):
        pointRx = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        pointRy = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

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
        pointRx = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        pointRy = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

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
        pointRx = 0x7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0
        pointRy = 0xfa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7

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
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        pointRx = 0x51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f
        pointRy = 0x75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5

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
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        e = 0xd37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7
        pointRx = 0xd867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8
        pointRy = 0xf2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275

        t = self.pointS * d

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)


class TestEccPoint_NIST_P384(unittest.TestCase):
    """Tests defined in section 4.4 of https://www.nsa.gov/ia/_files/nist-routines.pdf"""

    pointS = EccPoint(
                0xfba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f92385dda82768ada415ebab4167459da98e62b1332d1e73cb0e,
                0x5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45,
                "p384")

    pointT = EccPoint(
                0xaacc05202e7fda6fc73d82f0a66220527da8117ee8f8330ead7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051,
                0x84009a263fefba7c2c57cffa5db3634d286131afc0fca8d25afa22a7b5dce0d9470da89233cee178592f49b6fecb5092,
                "p384")

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

    def test_addition(self):
        pointRx = 0x12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed
        pointRy = 0x167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0

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
        pointRx = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        pointRy = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

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
        pointRx = 0x2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c
        pointRy = 0xfa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd

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
        d = 0xa4ebcae5a665983493ab3e626085a24c104311a761b5a8fdac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480
        pointRx = 0xe4f77e7ffeb7f0958910e3a680d677a477191df166160ff7ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2
        pointRy = 0xac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f

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
        d = 0xa4ebcae5a665983493ab3e626085a24c104311a761b5a8fdac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480
        e = 0xafcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d
        pointRx = 0x917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc
        pointRy = 0x1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd307f758d4aee684beff26f6742f597e2585c86da908f7186

        t = self.pointS * d

        pointR = self.pointS * d + self.pointT * e
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)


class TestEccPoint_PAI_P256(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves['p256']
    pointG = EccPoint(curve.Gx, curve.Gy, "p256")


tv_pai = load_tests(("Crypto", "SelfTest", "PublicKey", "test_vectors", "ECC"),
                    "point-at-infinity.org-P256.txt",
                    "P-256 tests from point-at-infinity.org",
                    { "k" : lambda k: int(k),
                      "x" : lambda x: int(x, 16),
                      "y" : lambda y: int(y, 16)} )
assert(tv_pai)
for tv in tv_pai:
    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)
    setattr(TestEccPoint_PAI_P256, "test_%d" % tv.count, new_test)


class TestEccPoint_PAI_P384(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    curve = _curves['p384']
    pointG = EccPoint(curve.Gx, curve.Gy, "p384")


tv_pai = load_tests(("Crypto", "SelfTest", "PublicKey", "test_vectors", "ECC"),
                    "point-at-infinity.org-P384.txt",
                    "P-384 tests from point-at-infinity.org",
                    { "k" : lambda k: int(k),
                      "x" : lambda x: int(x, 16),
                      "y" : lambda y: int(y, 16)} )
assert(tv_pai)
for tv in tv_pai:
    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG * scalar
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)
    setattr(TestEccPoint_PAI_P384, "test_%d" % tv.count, new_test)


class TestEccKey_P256(unittest.TestCase):

    def test_private_key(self):

        key = EccKey(curve="P-256", d=1)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ.x, _curves['p256'].Gx)
        self.assertEqual(key.pointQ.y, _curves['p256'].Gy)

        point = EccPoint(_curves['p256'].Gx, _curves['p256'].Gy)
        key = EccKey(curve="P-256", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="secp256r1", d=1)
        key = EccKey(curve="prime256v1", d=1)

    def test_public_key(self):

        point = EccPoint(_curves['p256'].Gx, _curves['p256'].Gy)
        key = EccKey(curve="P-256", point=point)
        self.failIf(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-256", d=3)
        pub_key = priv_key.public_key()
        self.failIf(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-257", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=_curves['p256'].order))

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


class TestEccKey_P384(unittest.TestCase):

    def test_private_key(self):

        p384 = _curves['p384']

        key = EccKey(curve="P-384", d=1)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ.x, p384.Gx)
        self.assertEqual(key.pointQ.y, p384.Gy)

        point = EccPoint(p384.Gx, p384.Gy, "p384")
        key = EccKey(curve="P-384", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, point)

        # Other names
        key = EccKey(curve="p384", d=1)
        key = EccKey(curve="secp384r1", d=1)
        key = EccKey(curve="prime384v1", d=1)

    def test_public_key(self):

        p384 = _curves['p384']
        point = EccPoint(p384.Gx, p384.Gy, 'p384')
        key = EccKey(curve="P-384", point=point)
        self.failIf(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):

        priv_key = EccKey(curve="P-384", d=3)
        pub_key = priv_key.public_key()
        self.failIf(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-385", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-384", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-384",
                                                     d=_curves['p384'].order))

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


class TestEccModule_P256(unittest.TestCase):

    def test_generate(self):

        key = ECC.generate(curve="P-256")
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(_curves['p256'].Gx, _curves['p256'].Gy) * key.d)

        # Other names
        ECC.generate(curve="secp256r1")
        ECC.generate(curve="prime256v1")

    def test_construct(self):

        key = ECC.construct(curve="P-256", d=1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, _curves['p256'].G)

        key = ECC.construct(curve="P-256", point_x=_curves['p256'].Gx, point_y=_curves['p256'].Gy)
        self.failIf(key.has_private())
        self.assertEqual(key.pointQ, _curves['p256'].G)

        # Other names
        ECC.construct(curve="p256", d=1)
        ECC.construct(curve="secp256r1", d=1)
        ECC.construct(curve="prime256v1", d=1)

    def test_negative_construct(self):
        coord = dict(point_x=10, point_y=4)
        coordG = dict(point_x=_curves['p256'].Gx, point_y=_curves['p256'].Gy)

        self.assertRaises(ValueError, ECC.construct, curve="P-256", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-256", d=2, **coordG)


class TestEccModule_P384(unittest.TestCase):

    def test_generate(self):

        curve = _curves['p384']
        key = ECC.generate(curve="P-384")
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(curve.Gx, curve.Gy, "p384") * key.d)

        # Other names
        ECC.generate(curve="secp384r1")
        ECC.generate(curve="prime384v1")

    def test_construct(self):

        curve = _curves['p384']
        key = ECC.construct(curve="P-384", d=1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, _curves['p384'].G)

        key = ECC.construct(curve="P-384", point_x=curve.Gx, point_y=curve.Gy)
        self.failIf(key.has_private())
        self.assertEqual(key.pointQ, curve.G)

        # Other names
        ECC.construct(curve="p384", d=1)
        ECC.construct(curve="secp384r1", d=1)
        ECC.construct(curve="prime384v1", d=1)

    def test_negative_construct(self):
        coord = dict(point_x=10, point_y=4)
        coordG = dict(point_x=_curves['p384'].Gx, point_y=_curves['p384'].Gy)

        self.assertRaises(ValueError, ECC.construct, curve="P-384", **coord)
        self.assertRaises(ValueError, ECC.construct, curve="P-384", d=2, **coordG)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestEccPoint_NIST_P256)
    tests += list_test_cases(TestEccPoint_NIST_P384)
    tests += list_test_cases(TestEccPoint_PAI_P256)
    tests += list_test_cases(TestEccPoint_PAI_P384)
    tests += list_test_cases(TestEccKey_P256)
    tests += list_test_cases(TestEccKey_P384)
    tests += list_test_cases(TestEccModule_P256)
    tests += list_test_cases(TestEccModule_P384)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
