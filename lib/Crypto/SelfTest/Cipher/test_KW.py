import unittest

from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Cipher import AES


class KW_Tests(unittest.TestCase):

    # From RFC3394
    tvs = [
        ("000102030405060708090A0B0C0D0E0F",
         "00112233445566778899AABBCCDDEEFF",
         "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
        ("000102030405060708090A0B0C0D0E0F1011121314151617",
         "00112233445566778899AABBCCDDEEFF",
         "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
        ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
         "00112233445566778899AABBCCDDEEFF",
         "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
        ("000102030405060708090A0B0C0D0E0F1011121314151617",
         "00112233445566778899AABBCCDDEEFF0001020304050607",
         "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"),
        ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
         "00112233445566778899AABBCCDDEEFF0001020304050607",
         "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"),
        ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
         "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
         "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
    ]

    def test_rfc3394(self):
        for tv in self.tvs:
            kek, pt, ct = [bytes.fromhex(x) for x in tv]

            cipher = AES.new(kek, AES.MODE_KW)
            ct2 = cipher.seal(pt)

            self.assertEqual(ct, ct2)

            pt2 = cipher.unseal(ct)
            self.assertEqual(pt, pt2)

    def test_neg1(self):

        cipher = AES.new(b'-' * 16, AES.MODE_KW)

        with self.assertRaises(ValueError):
            cipher.seal(b'')

        with self.assertRaises(ValueError):
            cipher.seal(b'8' * 17)

    def test_neg2(self):

        cipher = AES.new(b'-' * 16, AES.MODE_KW)
        ct = bytearray(cipher.seal(b'7' * 16))
        cipher.unseal(ct)

        ct[0] ^= 0xFF
        with self.assertRaises(ValueError):
            cipher.unseal(ct)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(KW_Tests)
    return tests


if __name__ == '__main__':
    def suite():
        return unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
