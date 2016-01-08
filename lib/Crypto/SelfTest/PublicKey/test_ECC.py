import unittest
import time
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.loader import load_tests

from Crypto.PublicKey.ECC import EccPoint, _curve, EccKey, generate

class TestEccPoint_NIST(unittest.TestCase):
    """Tests defined in section 4.3 of https://www.nsa.gov/ia/_files/nist-routines.pdf"""

    pointS = EccPoint(
                0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9,
                0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256)

    pointT = EccPoint(
                0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b,
                0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316)

    def test_addition(self):
        pointRx = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        pointRy = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

        pointR = self.pointS.add(self.pointT)
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        pai = self.pointS.point_at_infinity()

        # S + 0
        pointR = self.pointS.add(pai)
        self.assertEqual(pointR, self.pointS)

        # 0 + S
        pointR = pai.add(self.pointS)
        self.assertEqual(pointR, self.pointS)

        # 0 + 0
        pointR = pai.add(pai)
        self.assertEqual(pointR, pai)

    def test_doubling(self):
        pointRx = 0x7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0
        pointRy = 0xfa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7

        pointR = self.pointS.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 2*0
        pai = self.pointS.point_at_infinity()
        pointR = pai.double()
        self.assertEqual(pointR, pai)

    def test_scalar_multiply(self):
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        pointRx = 0x51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f
        pointRy = 0x75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5

        pointR = self.pointS.multiply(d)
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

        # 0*S
        pai = self.pointS.point_at_infinity()
        pointR = self.pointS.multiply(0)
        self.assertEqual(pointR, pai)

        # -1*S
        self.assertRaises(ValueError, self.pointS.multiply, -1)

    def test_joing_scalar_multiply(self):
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        e = 0xd37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7
        pointRx = 0xd867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8
        pointRy = 0xf2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275

        pointR = self.pointS.multiply(d).add(self.pointT.multiply(e))
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)


class TestEccPoint_PAI(unittest.TestCase):
    """Test vectors from http://point-at-infinity.org/ecc/nisttv"""

    pointG = EccPoint(_curve.Gx, _curve.Gy)


tv_pai = load_tests(("Crypto", "SelfTest", "PublicKey", "test_vectors", "ECC"),
                    "point-at-infinity.org-P256.txt",
                    "P-256 tests from point-at-infinity.org",
                    { "k" : lambda k: int(k),
                      "x" : lambda x: int(x, 16),
                      "y" : lambda y: int(y, 16)} )
assert(tv_pai)
for tv in tv_pai:
    def new_test(self, scalar=tv.k, x=tv.x, y=tv.y):
        result = self.pointG.multiply(scalar)
        self.assertEqual(result.x, x)
        self.assertEqual(result.y, y)
    setattr(TestEccPoint_PAI, "test_%d" % tv.count, new_test)


class TestEccKey(unittest.TestCase):

    def test_private_key(self):

        key = EccKey(curve="P-256", d=1)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ.x, _curve.Gx)
        self.assertEqual(key.pointQ.y, _curve.Gy)

        point = EccPoint(_curve.Gx, _curve.Gy)
        key = EccKey(curve="P-256", d=1, point=point)
        self.assertEqual(key.d, 1)
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key(self):

        point = EccPoint(_curve.Gx, _curve.Gy)
        key = EccKey(curve="P-256", point=point)
        self.failIf(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_invalid_curve(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-257", d=1))

    def test_invalid_d(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=0))
        self.assertRaises(ValueError, lambda: EccKey(curve="P-256", d=_curve.order))


class TestEccGenerate(unittest.TestCase):

    def test_new_key(self):

        key = generate("P-256")
        self.failUnless(key.has_private())
        self.assertEqual(key.pointQ, EccPoint(_curve.Gx, _curve.Gy).multiply(key.d))


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestEccPoint_NIST)
    tests += list_test_cases(TestEccPoint_PAI)
    tests += list_test_cases(TestEccKey)
    tests += list_test_cases(TestEccGenerate)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
