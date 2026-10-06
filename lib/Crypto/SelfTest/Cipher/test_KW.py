import sys

import pytest

from Crypto.Cipher import AES
from Crypto.SelfTest.loader import load_test_vectors_wycheproof, wycheproof_id

pytestmark = pytest.mark.skipif(sys.version_info < (3, 9), reason="requires Python 3.9")


class TestKW:
    # From RFC3394
    tvs = [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ]

    @pytest.mark.parametrize("tv", tvs)
    def test_rfc3394(self, tv):
        kek, pt, ct = (bytes.fromhex(x) for x in tv)

        cipher = AES.new(kek, AES.MODE_KW)
        ct2 = cipher.seal(pt)

        assert ct == ct2

        cipher = AES.new(kek, AES.MODE_KW)
        pt2 = cipher.unseal(ct)
        assert pt == pt2

    def test_neg1(self):
        cipher = AES.new(b"-" * 16, AES.MODE_KW)

        with pytest.raises(ValueError):
            cipher.seal(b"")

        with pytest.raises(ValueError):
            cipher.seal(b"8" * 17)

    def test_neg2(self):
        cipher = AES.new(b"-" * 16, AES.MODE_KW)
        ct = bytearray(cipher.seal(b"7" * 16))

        cipher = AES.new(b"-" * 16, AES.MODE_KW)
        cipher.unseal(ct)

        cipher = AES.new(b"-" * 16, AES.MODE_KW)
        ct[0] ^= 0xFF
        with pytest.raises(ValueError):
            cipher.unseal(ct)


class TestKW_Wycheproof:
    @pytest.mark.parametrize(
        "vector",
        load_test_vectors_wycheproof(("Cipher", "wycheproof"), "kw_test.json", "Wycheproof tests for KW"),
        ids=wycheproof_id,
    )
    def test_wycheproof(self, vector):
        cipher = AES.new(vector.key, AES.MODE_KW)

        try:
            cipher.seal(vector.msg)
        except ValueError:
            if vector.valid:
                raise
            return

        cipher = AES.new(vector.key, AES.MODE_KW)
        try:
            pt = cipher.unseal(vector.ct)
        except ValueError:
            if vector.valid:
                raise
            return

        assert pt == vector.msg


class TestKWP:
    tvs = [
        (
            "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
            "c37b7e6492584340bed12207808941155068f738",
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
        ),
        (
            "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
            "466f7250617369",
            "afbeb0f07dfbf5419200f2ccb50bb24f",
        ),
    ]

    @pytest.mark.parametrize("tv", tvs)
    def test_rfc5649(self, tv):
        kek, pt, ct = (bytes.fromhex(x) for x in tv)

        cipher = AES.new(kek, AES.MODE_KWP)
        ct2 = cipher.seal(pt)

        assert ct == ct2

        cipher = AES.new(kek, AES.MODE_KWP)
        pt2 = cipher.unseal(ct)
        assert pt == pt2


class TestKWP_Wycheproof:
    @pytest.mark.parametrize(
        "vector",
        load_test_vectors_wycheproof(("Cipher", "wycheproof"), "kwp_test.json", "Wycheproof tests for KWP"),
        ids=wycheproof_id,
    )
    def test_wycheproof(self, vector):
        cipher = AES.new(vector.key, AES.MODE_KWP)

        try:
            cipher.seal(vector.msg)
        except ValueError:
            if vector.valid and not vector.warning:
                raise
            return

        cipher = AES.new(vector.key, AES.MODE_KWP)
        try:
            pt = cipher.unseal(vector.ct)
        except ValueError:
            if vector.valid and not vector.warning:
                raise
            return

        assert pt == vector.msg
