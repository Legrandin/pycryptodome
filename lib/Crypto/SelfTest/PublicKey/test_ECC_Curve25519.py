# ===================================================================
#
# Copyright (c) 2024, Helder Eijs <helderijs@gmail.com>
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
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey, EccXPoint, _curves

# Test vectors for scalar multiplication using point with X=9 as base
# generated with nickovs' Python-only code https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3
# The order is 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
# Each tuple is (exponent, X-coordinate)
scalar_base9_test = [
    (1, 9),
    (2, 0x20D342D51873F1B7D9750C687D1571148F3F5CED1E350B5C5CAE469CDD684EFB),
    (3, 0x1C12BC1A6D57ABE645534D91C21BBA64F8824E67621C0859C00A03AFFB713C12),
    (4, 0x79CE98B7E0689D7DE7D1D074A15B315FFE1805DFCD5D2A230FEE85E4550013EF),
    (6, 0x26954CCDC99EBF34F8F1DDE5E6BB080685FEC73640494C28F9FE0BFA8C794531),
    (9, 0x192B929197D07748DB44600DA41BAB7499B1C2E6E2F87C6F0E337980668164BA),
    (129, 0x7332096A738900085E721103FCE2CBF13AEE50FEF0788EA0D669008EB09CEAB7),
    (255, 0x1534582FC2B1CEA45E8CB776547E209DA4FD54A9E473B50C5B8C6B0AE023A9B3),
    (256, 0x4300017536976A742EC8747F7505CD6BC80E610D669ACAB1A1EED36F680D98E8),
    (257, 0x6C410611CB484C9016ADFB884D37A0E682E075DACA1D46F45BB7A4AFED10B125),
    (0x10101, 0xA679E9D7E043BF76C03362576E2C88ABE9093C5D4F6B4A202C64A8397467CF),
    (0xAA55CC, 0x2CC02F84C067E3586F4278326689BE163E606D69CCAE505BB09488E11F295887),
    (0x1B29A0E579E0A000567, 0x50C38A72D7BFD7864C8B9083FA123E8D359068E6B491A019A885036E073F6604),
    (0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED + 1, 9),
]


class TestEccPoint_Curve25519(unittest.TestCase):
    v1 = 0x09FA78B39B00A72930BCD8039BE789A0997830BB99F79AEEB93493715390B4E8
    v2 = 0x15210F12786811D3F4B7959D0538AE2C31DBE7106FC03C3EFC4CD549C715A493

    def test_init(self):
        EccXPoint(9, "curve25519")
        EccXPoint(2**255 - 19 + 5, "curve25519")

    def test_curve_attribute(self):
        point = EccXPoint(9, "curve25519")
        self.assertEqual(point.curve, "Curve25519")

    def test_init_fail(self):
        self.assertRaises(ValueError, EccXPoint, 3 * (2**255 - 19), "curve25519")
        self.assertRaises(ValueError, EccXPoint, 9, "curve25518")

    def test_equal_set(self):
        point1 = EccXPoint(self.v1, "curve25519")
        point2 = EccXPoint(self.v2, "curve25519")

        self.assertEqual(point1, point1)
        self.assertNotEqual(point1, point2)

        point2.set(point1)
        self.assertEqual(point1.x, point2.x)

    def test_copy(self):
        point1 = EccXPoint(self.v1, "curve25519")
        point2 = point1.copy()
        self.assertEqual(point1.x, point2.x)

    def test_pai(self):
        point1 = EccXPoint(self.v1, "curve25519")
        pai = point1.point_at_infinity()
        self.assertTrue(pai.point_at_infinity())

        point2 = EccXPoint(None, "curve25519")
        self.assertTrue(point2.point_at_infinity())

    def test_scalar_multiply(self):
        base = EccXPoint(9, "curve25519")

        pointH = 0 * base
        self.assertTrue(pointH.point_at_infinity())

        pointH = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED * base
        self.assertTrue(pointH.point_at_infinity())

        pointH = base * 1
        self.assertEqual(pointH.x, 9)

        for d, result in scalar_base9_test:
            pointH = d * base
            self.assertEqual(pointH.x, result)

    def test_sizes(self):
        point = EccXPoint(9, "curve25519")
        self.assertEqual(point.size_in_bits(), 255)
        self.assertEqual(point.size_in_bytes(), 32)


class TestEccKey_Curve25519(unittest.TestCase):
    def test_private_key(self):
        # RFC7748 Section 6.1 - Alice
        alice_priv = unhexlify("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        alice_pub = unhexlify("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        alice_pub_x = Integer.from_bytes(alice_pub, byteorder="little")

        key = EccKey(curve="Curve25519", seed=alice_priv)
        self.assertEqual(key.seed, alice_priv)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, alice_pub_x)

        # RFC7748 Section 6.1 - Bob
        bob_priv = unhexlify("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        bob_pub = unhexlify("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        bob_pub_x = Integer.from_bytes(bob_pub, byteorder="little")

        key = EccKey(curve="Curve25519", seed=bob_priv)
        self.assertEqual(key.seed, bob_priv)
        self.assertTrue(key.has_private())
        self.assertEqual(key.pointQ.x, bob_pub_x)

        # Other names
        key = EccKey(curve="curve25519", seed=alice_priv)

        # Must not accept d parameter
        self.assertRaises(ValueError, EccKey, curve="curve25519", d=1)

    def test_public_key(self):
        point = EccXPoint(_curves["curve25519"].Gx, curve="curve25519")
        key = EccKey(curve="curve25519", point=point)
        self.assertFalse(key.has_private())
        self.assertEqual(key.pointQ, point)

    def test_public_key_derived(self):
        priv_key = EccKey(curve="curve25519", seed=b"H" * 32)
        pub_key = priv_key.public_key()
        self.assertFalse(pub_key.has_private())
        self.assertEqual(priv_key.pointQ, pub_key.pointQ)

    def test_invalid_seed(self):
        self.assertRaises(ValueError, lambda: EccKey(curve="curve25519", seed=b"H" * 31))

    def test_equality(self):
        private_key = ECC.construct(seed=b"H" * 32, curve="Curve25519")
        private_key2 = ECC.construct(seed=b"H" * 32, curve="curve25519")
        private_key3 = ECC.construct(seed=b"C" * 32, curve="Curve25519")

        public_key = private_key.public_key()
        public_key2 = private_key2.public_key()
        public_key3 = private_key3.public_key()

        self.assertEqual(private_key, private_key2)
        self.assertNotEqual(private_key, private_key3)

        self.assertEqual(public_key, public_key2)
        self.assertNotEqual(public_key, public_key3)

        self.assertNotEqual(public_key, private_key)

    def test_name_consistency(self):
        key = ECC.generate(curve="curve25519")
        self.assertIn("curve='Curve25519'", repr(key))
        self.assertEqual(key.curve, "Curve25519")
        self.assertEqual(key.public_key().curve, "Curve25519")


class TestEccModule_Curve25519(unittest.TestCase):
    def test_generate(self):
        key = ECC.generate(curve="Curve25519")
        self.assertTrue(key.has_private())
        point = EccXPoint(_curves["Curve25519"].Gx, curve="Curve25519") * key.d
        self.assertEqual(key.pointQ, point)

        # Always random
        key2 = ECC.generate(curve="Curve25519")
        self.assertNotEqual(key, key2)

        # Other names
        ECC.generate(curve="curve25519")

        # Random source
        key1 = ECC.generate(curve="Curve25519", randfunc=SHAKE128.new().read)
        key2 = ECC.generate(curve="Curve25519", randfunc=SHAKE128.new().read)
        self.assertEqual(key1, key2)

    def test_construct(self):
        seed = unhexlify("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        point_hex = unhexlify("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        Px = Integer.from_bytes(point_hex, byteorder="little")
        point = EccXPoint(Px, curve="Curve25519")

        # Private key only
        key = ECC.construct(curve="Curve25519", seed=seed)
        self.assertEqual(key.pointQ, point)
        self.assertTrue(key.has_private())

        # Public key only
        key = ECC.construct(curve="Curve25519", point_x=Px)
        self.assertEqual(key.pointQ, point)
        self.assertFalse(key.has_private())

        # Private and public key
        key = ECC.construct(curve="Curve25519", seed=seed, point_x=Px)
        self.assertEqual(key.pointQ, point)
        self.assertTrue(key.has_private())

        # Other names
        key = ECC.construct(curve="curve25519", seed=seed)

    def test_negative_construct(self):
        coordG = {"point_x": _curves["curve25519"].Gx}

        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", d=2, **coordG)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", seed=b"H" * 31)

        # Verify you cannot construct weak keys (small-order points)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=0)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=1)
        self.assertRaises(
            ValueError,
            ECC.construct,
            curve="Curve25519",
            point_x=325606250916557431795983626356110631294008115727848805560023387167927233504,
        )
        self.assertRaises(
            ValueError,
            ECC.construct,
            curve="Curve25519",
            point_x=39382357235489614581723060781553021112529911719440698176882885853963445705823,
        )
        p = 2**255 - 19
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p - 1)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p + 1)
        self.assertRaises(
            ValueError,
            ECC.construct,
            curve="Curve25519",
            point_x=p + 325606250916557431795983626356110631294008115727848805560023387167927233504,
        )
        self.assertRaises(
            ValueError,
            ECC.construct,
            curve="Curve25519",
            point_x=p + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
        )
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p * 2 - 1)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p * 2)
        self.assertRaises(ValueError, ECC.construct, curve="Curve25519", point_x=p * 2 + 1)
