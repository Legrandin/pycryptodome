import re
import unittest

from Crypto.Util.py3compat import bord

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof

from Crypto.Protocol.dh import key_agreement


class FIPS_ECDH_Tests_KAT(unittest.TestCase):
    pass


test_vectors_verify = load_test_vectors(("Protocol", ),
                                        "KAS_ECC_CDH_PrimitiveTest.txt",
                                        "ECC CDH Primitive (SP800-56A Section 5.7.1.2)",
                                        {
                                        'qcavsx': lambda x: int(x, 16),
                                        'qcavsy': lambda x: int(x, 16),
                                        'diut': lambda x: int(x, 16),
                                        'qiutx': lambda x: int(x, 16),
                                        'qiuty': lambda x: int(x, 16),
                                        }) or []

for idx, tv in enumerate(test_vectors_verify):

    # Stand-alone header with curve name
    if isinstance(tv, str):
        res = re.match(r"\[([A-Za-z0-9-]+)\]", tv)
        assert res
        curve_name = res.group(1)
        continue

    public_key = ECC.construct(curve=curve_name,
                               point_x=tv.qcavsx,
                               point_y=tv.qcavsy)

    private_key = ECC.construct(curve=curve_name,
                                d=tv.diut)

    exp_response = tv.ziut

    def ecdh_test(self,
                  public_key=public_key,
                  private_key=private_key,
                  exp_response=exp_response):
        z = key_agreement(
                static_pub=public_key,
                static_priv=private_key,
                kdf=lambda x: x)
        self.assertEqual(z, exp_response)

    def ecdh_test_rev(self,
                      public_key=public_key,
                      private_key=private_key,
                      exp_response=exp_response):
        z = key_agreement(
                static_pub=public_key,
                static_priv=private_key,
                kdf=lambda x: x)
        self.assertEqual(z, exp_response)

    setattr(FIPS_ECDH_Tests_KAT, "test_verify_positive_%d" % idx, ecdh_test)
    if idx == 1:
        setattr(FIPS_ECDH_Tests_KAT, "test_verify_positive_rev_%d" % idx, ecdh_test_rev)


class TestVectorsECDHWycheproof(unittest.TestCase):

    def add_tests(self, filename):

        def curve(g):
            return g['curve']

        def private(u):
            return int(u['private'], 16)

        result = load_test_vectors_wycheproof(("Protocol", "wycheproof"),
                                              filename,
                                              "Wycheproof ECDH (%s)"
                                              % filename,
                                              group_tag={'curve': curve},
                                              unit_tag={'private': private},
                                              )
        self.tv += result

    def setUp(self):
        self.tv = []
        self.desc = None

        self.add_tests("ecdh_secp224r1_ecpoint_test.json")
        self.add_tests("ecdh_secp256r1_ecpoint_test.json")
        self.add_tests("ecdh_secp384r1_ecpoint_test.json")
        self.add_tests("ecdh_secp521r1_ecpoint_test.json")

        self.add_tests("ecdh_secp224r1_test.json")
        self.add_tests("ecdh_secp256r1_test.json")
        self.add_tests("ecdh_secp384r1_test.json")
        self.add_tests("ecdh_secp521r1_test.json")

    def shortDescription(self):
        return self.desc

    def test_verify(self, tv):
        self._id = "Wycheproof ECDH Verify Test #%d (%s, %s)" % (tv.id, tv.comment, tv.filename)

        if len(tv.public) == 0:
            return

        try:
            if bord(tv.public[0]) == 4:     # SEC1
                public_key = ECC.import_key(tv.public, curve_name=tv.curve)
            else:
                public_key = ECC.import_key(tv.public)
        except ValueError:
            assert tv.warning or not tv.valid
            return

        private_key = ECC.construct(curve=tv.curve, d=tv.private)

        try:
            z = key_agreement(static_pub=public_key,
                              static_priv=private_key,
                              kdf=lambda x: x)
        except ValueError:
            assert not tv.valid
        except TypeError as e:
            assert not tv.valid
            assert "incompatible curve" in str(e)
        else:
            self.assertEqual(z, tv.shared)
            assert tv.valid

    def runTest(self):
        for tv in self.tv:
            self.desc = "Test #%d (%s) - %s" % (tv.id, tv.filename, tv.comment)
            self.test_verify(tv)


class ECDH_Tests(unittest.TestCase):

    static_pub = ECC.generate(curve='p256').public_key()
    static_priv = ECC.generate(curve='p256')
    eph_pub = ECC.generate(curve='p256').public_key()
    eph_priv = ECC.generate(curve='p256')

    def test_1(self):
        # C(0, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv)

    def test_2(self):
        # C(2e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)

    def test_3(self):
        # C(1e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_priv=self.eph_priv)

    def test_4(self):
        # C(1e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub)

    def test_5(self):
        # C(2e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)

    def test_6(self):
        # C(2e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_pub=self.static_pub,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)

    def test_7(self):
        # C(2e, 0)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)

    def test_8(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub)

    def test_9(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                eph_priv=self.eph_priv)

    def test_10(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_pub=self.static_pub,
                eph_pub=self.eph_pub)

    def test_11(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_priv=self.static_priv,
                eph_priv=self.eph_priv)


def get_tests(config={}):

    tests = []
    tests += list_test_cases(FIPS_ECDH_Tests_KAT)
    tests += [TestVectorsECDHWycheproof()]
    tests += list_test_cases(ECDH_Tests)

    slow_tests = config.get('slow_tests')
    if slow_tests:
        pass

    return tests


if __name__ == '__main__':
    def suite():
        return unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
