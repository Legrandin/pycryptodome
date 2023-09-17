import re
import unittest
from binascii import hexlify

from Crypto.Util.py3compat import bord

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof

from Crypto.Protocol.DH import key_agreement


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

    desc = "Wycheproof ECDH tests"

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
            self.desc = "Wycheproof ECDH Verify Test #%d (%s, %s)" % (tv.id, tv.comment, tv.filename)
            self.test_verify(tv)


class ECDH_Tests(unittest.TestCase):

    static_priv = ECC.import_key('-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9VHFVKh2a1aVFifH\n+BiyNaRa2kttEg3165Ye/dJxJ7KhRANCAARImIEXro5ZOcyWU2mq/+d79FEZXtTA\nbKkz1aICQXihQdCMzRNbeNtC9LFLzhu1slRKJ2xsDAlw9r6w6vwtkRzr\n-----END PRIVATE KEY-----')
    static_pub = ECC.import_key('-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHhmv8zmZ+Nw8fsZd\ns8tlZflyfw2NE1CRS9DWr3Y3O46hRANCAAS3hZVUCbk+uk3w4S/YOraEVGG+WYpk\nNO/vrwzufUUks2GV2OnBQESe0EBk4Jq8gn4ij8Lvs3rZX2yT+XfeATYd\n-----END PRIVATE KEY-----').public_key()

    eph_priv = ECC.import_key('-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGPdJmFFFKzLPspIr\nE1T2cEjeIf4ajS9CpneP0e2b3AyhRANCAAQBexAA5BYDcXHs2KOksTYUsst4HhPt\nkp0zkgI2virc3OGJFNGPaCCPfFCQJHwLRaEpiq3SoQlgoBwSc8ZPsl3y\n-----END PRIVATE KEY-----')

    eph_pub = ECC.import_key('-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghaVZXElSEGEojFKF\nOU0JCpxWUWHvWQUR81gwWrOp76ShRANCAATi1Ib2K+YR3AckD8wxypWef7pw5PRw\ntBaB3RDPyE7IjHZC6yu1DbcXoCdtaw+F5DM+4zpl59n5ZaIy/Yl1BdIy\n-----END PRIVATE KEY-----')

    def test_1(self):
        # C(0, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv)
        self.assertEqual(hexlify(z),
                        b"3960a1101d1193cbaffef4cc7202ebff783c22c6d2e0d5d530ffc66dc197ea9c")

    def test_2(self):
        # C(2e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)
        self.assertEqual(hexlify(z),
                         b"7447b733d40c8fab2c633b3dc61e4a8c742f3a6af7e16fb0cc486f5bdb5d6ba2")

    def test_3(self):
        # C(1e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_priv=self.eph_priv)
        self.assertEqual(hexlify(z),
                         b"9e977ae45f33bf67f285d064d83e6632bcafe3a7d33fe571233bab4794ace759")

    def test_4(self):
        # C(1e, 2s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub)
        self.assertEqual(hexlify(z),
                         b"c9532df6aa7e9dbe5fe85da31ee25ff19c179c88691ec4b8328cc2036dcdadf2")

    def test_5(self):
        # C(2e, 1s) is not supported
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub,
                eph_priv=self.eph_priv)

    def test_6(self):
        # C(2e, 1s) is not supported
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
        self.assertEqual(hexlify(z),
                         b"feb257ebe063078b1391aac07913283d7b642ad7df61b46dfc9cd6f420bb896a")

    def test_8(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_priv=self.static_priv,
                eph_pub=self.eph_pub)
        self.assertEqual(hexlify(z),
                         b"ee4dc995117476ed57fd17ff0ed44e9f0466d46b929443bc0db9380317583b04")

    def test_9(self):
        # C(1e, 1s)
        kdf = lambda x: SHA256.new(x).digest()
        z = key_agreement(
                kdf=kdf,
                static_pub=self.static_pub,
                eph_priv=self.eph_priv)
        self.assertEqual(hexlify(z),
                         b"2351cc2014f7c40468fa072b5d30f706eeaeef7507311cd8e59bab3b43f03c51")

    def test_10(self):
        # No private (local) keys
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_pub=self.static_pub,
                eph_pub=self.eph_pub)

    def test_11(self):
        # No public (peer) keys
        kdf = lambda x: SHA256.new(x).digest()
        self.assertRaises(ValueError,
                key_agreement,
                kdf=kdf,
                static_priv=self.static_priv,
                eph_priv=self.eph_priv)

    def test_12(self):
        # failure if kdf is missing
        self.assertRaises(ValueError,
                key_agreement,
                static_pub=self.static_pub,
                static_priv=self.static_priv)


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
