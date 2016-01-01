import unittest
import time
from Crypto.SelfTest.st_common import list_test_cases

from Crypto.PublicKey.ECC import ECPoint

class TestECPoint(unittest.TestCase):

    pointS = ECPoint(
                0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9,
                0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256)

    pointT = ECPoint(
                0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b,
                0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316)

    def test_addition(self):
        pointRx = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        pointRy = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264

        pointR = self.pointS.add(self.pointT)
        self.assertEqual(pointR.x, pointRx)

    def test_doubling(self):
        pointRx = 0x7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0
        pointRy = 0xfa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7

        pointR = self.pointS.double()
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_scalar_multiply(self):
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        pointRx = 0x51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f
        pointRy = 0x75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5

        pointR = self.pointS.multiply(d)
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def test_joing_scalar_multiply(self):
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        e = 0xd37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7
        pointRx = 0xd867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8
        pointRy = 0xf2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275

        pointR = self.pointS.multiply(d).add(self.pointT.multiply(e))
        self.assertEqual(pointR.x, pointRx)
        self.assertEqual(pointR.y, pointRy)

    def _test_bench(self):
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd

        start = time.time()
        count = 30
        for x in xrange(count):
            self.pointS.multiply(d)
        print (time.time() - start) / count * 1000, "ms"


def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestECPoint)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')


