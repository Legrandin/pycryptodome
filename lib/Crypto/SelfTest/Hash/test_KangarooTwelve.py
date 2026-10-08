# SPDX-FileCopyrightText: 2021 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-test suite for Crypto.Hash.KangarooTwelve"""

from binascii import unhexlify

import pytest

from Crypto.Hash import KangarooTwelve as K12
from Crypto.Util._cpu_features import available_cores

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(K12._raw_k12_portable_lib, id="portable")]
if K12._raw_k12_avx2_bmi2_lib is not None:
    _implementations.append(pytest.param(K12._raw_k12_avx2_bmi2_lib, id="avx2_bmi2"))


@pytest.fixture(autouse=True, params=_implementations)
def k12_implementation(request, monkeypatch):
    monkeypatch.setattr(K12, "_raw_k12_lib", request.param)


class TestKangarooTwelve:
    def test_length_encode(self):
        assert K12._length_encode(0) == b"\x00"
        assert K12._length_encode(12) == b"\x0c\x01"
        assert K12._length_encode(65538) == b"\x01\x00\x02\x03"

    def test_new_positive(self):
        xof1 = K12.new()
        xof2 = K12.new(data=b"90")
        xof3 = K12.new().update(b"90")

        assert xof1.read(10) != xof2.read(10)
        xof3.read(10)
        assert xof2.read(10) == xof3.read(10)

        xof1 = K12.new()
        ref = xof1.read(10)
        xof2 = K12.new(custom=b"")
        xof3 = K12.new(custom=b"foo")

        assert ref == xof2.read(10)
        assert ref != xof3.read(10)

        xof1 = K12.new(custom=b"foo")
        xof2 = K12.new(custom=b"foo", data=b"90")
        xof3 = K12.new(custom=b"foo").update(b"90")

        assert xof1.read(10) != xof2.read(10)
        xof3.read(10)
        assert xof2.read(10) == xof3.read(10)

    def test_update(self):
        pieces = [bytes([10]) * 200, bytes([20]) * 300]
        h = K12.new()
        h.update(pieces[0]).update(pieces[1])
        digest = h.read(10)
        h = K12.new()
        h.update(pieces[0] + pieces[1])
        assert h.read(10) == digest

    def test_update_negative(self):
        h = K12.new()
        with pytest.raises(TypeError):
            h.update("string")

    def test_digest(self):
        h = K12.new()
        digest = h.read(90)

        # read returns a byte string of the right length
        assert isinstance(digest, bytes)
        assert len(digest) == 90

    def test_read_negative(self):
        xof = K12.new()
        for bad in (True, False, 1.0, "1", None):
            with pytest.raises(TypeError):
                xof.read(bad)
        with pytest.raises(ValueError):
            xof.read(-1)

        # A rejected read() does not start squeezing
        xof.update(b"abc")
        assert xof.read(10) == K12.new(data=b"abc").read(10)

    def test_update_after_read(self):
        mac = K12.new()
        mac.update(b"rrrr")
        mac.read(90)
        with pytest.raises(TypeError):
            mac.update(b"ttt")


def txt2bin(txt):
    clean = txt.replace(" ", "").replace("\n", "").replace("\r", "")
    return unhexlify(clean)


def ptn(n):
    res = bytearray(n)
    pattern = b"".join([bytes([x]) for x in range(0xFB)])
    for base in range(0, n - 0xFB, 0xFB):
        res[base : base + 0xFB] = pattern
    remain = n % 0xFB
    if remain:
        base = (n // 0xFB) * 0xFB
        res[base:] = pattern[:remain]
    assert len(res) == n
    return res


def chunked(source, size):
    for i in range(0, len(source), size):
        yield source[i : i + size]


class TestKangarooTwelveTV:
    # https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KangarooTwelve.txt

    def test_zero_1(self):
        tv = """1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
             3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5"""

        btv = txt2bin(tv)
        res = K12.new().read(32)
        assert res == btv

    def test_zero_2(self):
        tv = """1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
        3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5
        42 69 C0 56 B8 C8 2E 48 27 60 38 B6 D2 92 96 6C
        C0 7A 3D 46 45 27 2E 31 FF 38 50 81 39 EB 0A 71"""

        btv = txt2bin(tv)
        res = K12.new().read(64)
        assert res == btv

    def test_zero_3(self):
        tv = """E8 DC 56 36 42 F7 22 8C 84 68 4C 89 84 05 D3 A8
        34 79 91 58 C0 79 B1 28 80 27 7A 1D 28 E2 FF 6D"""

        btv = txt2bin(tv)
        res = K12.new().read(10032)
        assert res[-32:] == btv

    def test_ptn_1(self):
        tv = """2B DA 92 45 0E 8B 14 7F 8A 7C B6 29 E7 84 A0 58
        EF CA 7C F7 D8 21 8E 02 D3 45 DF AA 65 24 4A 1F"""

        btv = txt2bin(tv)
        res = K12.new(data=ptn(1)).read(32)
        assert res == btv

    def test_ptn_17(self):
        tv = """6B F7 5F A2 23 91 98 DB 47 72 E3 64 78 F8 E1 9B
        0F 37 12 05 F6 A9 A9 3A 27 3F 51 DF 37 12 28 88"""

        btv = txt2bin(tv)
        res = K12.new(data=ptn(17)).read(32)
        assert res == btv

    def test_ptn_17_2(self):
        tv = """0C 31 5E BC DE DB F6 14 26 DE 7D CF 8F B7 25 D1
        E7 46 75 D7 F5 32 7A 50 67 F3 67 B1 08 EC B6 7C"""

        btv = txt2bin(tv)
        res = K12.new(data=ptn(17**2)).read(32)
        assert res == btv

    def test_ptn_17_3(self):
        tv = """CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77
        2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0"""

        btv = txt2bin(tv)
        res = K12.new(data=ptn(17**3)).read(32)
        assert res == btv

    def test_ptn_17_4(self):
        tv = """87 01 04 5E 22 20 53 45 FF 4D DA 05 55 5C BB 5C
        3A F1 A7 71 C2 B8 9B AE F3 7D B4 3D 99 98 B9 FE"""

        btv = txt2bin(tv)
        data = ptn(17**4)

        # All at once
        res = K12.new(data=data).read(32)
        assert res == btv

        # Byte by byte
        k12 = K12.new()
        for x in data:
            k12.update(bytes([x]))
        res = k12.read(32)
        assert res == btv

        # Chunks of various prime sizes
        for chunk_size in (13, 17, 19, 23, 31):
            k12 = K12.new()
            for x in chunked(data, chunk_size):
                k12.update(x)
            res = k12.read(32)
            assert res == btv

    def test_ptn_17_5(self):
        tv = """84 4D 61 09 33 B1 B9 96 3C BD EB 5A E3 B6 B0 5C
        C7 CB D6 7C EE DF 88 3E B6 78 A0 A8 E0 37 16 82"""

        btv = txt2bin(tv)
        data = ptn(17**5)

        # All at once
        res = K12.new(data=data).read(32)
        assert res == btv

        # Chunks
        k12 = K12.new()
        for chunk in chunked(data, 8192):
            k12.update(chunk)
        res = k12.read(32)
        assert res == btv

    def test_ptn_17_6(self):
        tv = """3C 39 07 82 A8 A4 E8 9F A6 36 7F 72 FE AA F1 32
        55 C8 D9 58 78 48 1D 3C D8 CE 85 F5 8E 88 0A F8"""

        btv = txt2bin(tv)
        data = ptn(17**6)

        # All at once
        res = K12.new(data=data).read(32)
        assert res == btv

    def test_ptn_c_1(self):
        tv = """FA B6 58 DB 63 E9 4A 24 61 88 BF 7A F6 9A 13 30
        45 F4 6E E9 84 C5 6E 3C 33 28 CA AF 1A A1 A5 83"""

        btv = txt2bin(tv)
        custom = ptn(1)

        # All at once
        res = K12.new(custom=custom).read(32)
        assert res == btv

    def test_ptn_c_41(self):
        tv = """D8 48 C5 06 8C ED 73 6F 44 62 15 9B 98 67 FD 4C
        20 B8 08 AC C3 D5 BC 48 E0 B0 6B A0 A3 76 2E C4"""

        btv = txt2bin(tv)
        custom = ptn(41)

        # All at once
        res = K12.new(data=b"\xff", custom=custom).read(32)
        assert res == btv

    def test_ptn_c_41_2(self):
        tv = """C3 89 E5 00 9A E5 71 20 85 4C 2E 8C 64 67 0A C0
        13 58 CF 4C 1B AF 89 44 7A 72 42 34 DC 7C ED 74"""

        btv = txt2bin(tv)
        custom = ptn(41**2)

        # All at once
        res = K12.new(data=b"\xff" * 3, custom=custom).read(32)
        assert res == btv

    def test_ptn_c_41_3(self):
        tv = """75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9
        DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF"""

        btv = txt2bin(tv)
        custom = ptn(41**3)

        # All at once
        res = K12.new(data=b"\xff" * 7, custom=custom).read(32)
        assert res == btv

    # https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/

    def test_ptn_8191(self):
        tv = """1B 57 76 36 F7 23 64 3E 99 0C C7 D6 A6 59 83 74
        36 FD 6A 10 36 26 60 0E B8 30 1C D1 DB E5 53 D6"""

        btv = txt2bin(tv)

        # All at once
        res = K12.new(data=ptn(8191)).read(32)
        assert res == btv

    def test_ptn_8192(self):
        tv = """48 F2 56 F6 77 2F 9E DF B6 A8 B6 61 EC 92 DC 93
        B9 5E BD 05 A0 8A 17 B3 9A E3 49 08 70 C9 26 C3"""

        btv = txt2bin(tv)

        # All at once
        res = K12.new(data=ptn(8192)).read(32)
        assert res == btv

    def test_ptn_8192_8189(self):
        tv = """3E D1 2F 70 FB 05 DD B5 86 89 51 0A B3 E4 D2 3C
        6C 60 33 84 9A A0 1E 1D 8C 22 0A 29 7F ED CD 0B"""

        btv = txt2bin(tv)

        # All at once
        res = K12.new(data=ptn(8192), custom=ptn(8189)).read(32)
        assert res == btv

    def test_ptn_8192_8190(self):
        tv = """6A 7C 1B 6A 5C D0 D8 C9 CA 94 3A 4A 21 6C C6 46
        04 55 9A 2E A4 5F 78 57 0A 15 25 3D 67 BA 00 AE"""

        btv = txt2bin(tv)

        # All at once
        res = K12.new(data=ptn(8192), custom=ptn(8190)).read(32)
        assert res == btv

    ###

    def test_1(self):
        tv = "fd608f91d81904a9916e78a18f65c157a78d63f93d8f6367db0524526a5ea2bb"

        btv = txt2bin(tv)
        res = K12.new(data=b"", custom=ptn(100)).read(32)
        assert res == btv

    def test_2(self):
        tv4 = "5a4ec9a649f81916d4ce1553492962f7868abf8dd1ceb2f0cb3682ea95cda6a6"
        tv3 = "441688fe4fe4ae9425eb3105eb445eb2b3a6f67b66eff8e74ebfbc49371f6d4c"
        tv2 = "17269a57759af0214c84a0fd9bc851f4d95f80554cfed4e7da8a6ee1ff080131"
        tv1 = "33826990c09dc712ba7224f0d9be319e2720de95a4c1afbd2211507dae1c703a"
        tv0 = "9f4d3aba908ddc096e4d3a71da954f917b9752f05052b9d26d916a6fbc75bf3e"

        res = K12.new(data=b"A" * (8192 - 4), custom=b"B").read(32)
        assert res == txt2bin(tv4)

        res = K12.new(data=b"A" * (8192 - 3), custom=b"B").read(32)
        assert res == txt2bin(tv3)

        res = K12.new(data=b"A" * (8192 - 2), custom=b"B").read(32)
        assert res == txt2bin(tv2)

        res = K12.new(data=b"A" * (8192 - 1), custom=b"B").read(32)
        assert res == txt2bin(tv1)

        res = K12.new(data=b"A" * (8192 - 0), custom=b"B").read(32)
        assert res == txt2bin(tv0)

    def test_3(self):
        # Empty message, but the customization string alone
        # requires tree hashing (beyond 8189 bytes)
        tvs = {
            8189: "09a027af9433a3ccf1db41362cf0250d79e8c91e53435052769ea5972919d8f3",
            8190: "fbf556103724ead0bcb39332fffbbda57d9fda4e164e891fb78e0c918115a543",
            8191: "3257c0ba48058cc45e904c01575b9526a06c89043715ff75bde9c37dcb9ee791",
            8192: "6b56092a169ad94d287490bb7fd007ab852779cab8ffc94572beb7e602cdcb56",
            8193: "7ac1320051e97411e03f585ab06afb812d505a5f5c0f042c8676656acd49f22d",
        }

        for length, tv in tvs.items():
            custom = b"B" * length

            res = K12.new(custom=custom).read(32)
            assert res == txt2bin(tv)

            res = K12.new(data=b"", custom=custom).read(32)
            assert res == txt2bin(tv)

            res = K12.new(custom=custom).update(b"").read(32)
            assert res == txt2bin(tv)

    def test_mixed_leaves(self):
        # Mix partial and whole leaves across several update() calls
        data = ptn(8192 * 12 + 1000)
        custom = b"C" * 20
        ref = K12.new(data=data, custom=custom).read(32)

        chunk_lists = [
            [100, 8192 * 3, 5000, 3192 + 8192 * 2, 8192, 1, 8191],
            [8192, 8192 * 4, 4096, 4096, 8192 * 3 + 7],
            [8191, 1, 1, 8192 * 5 + 8191, 8192, 8192, 8192],
            [12345, 8192 * 2 - 1, 8192 * 2 + 1, 33333],
        ]
        for chunks in chunk_lists:
            h = K12.new(custom=custom)
            index = 0
            for size in chunks:
                h.update(data[index : index + size])
                index += size
            h.update(data[index:])
            assert h.read(32) == ref

        # Same as above, with memoryview and bytearray inputs
        h = K12.new(custom=custom)
        h.update(memoryview(data)[: 8192 * 7 + 3])
        h.update(bytearray(data[8192 * 7 + 3 :]))
        assert h.read(32) == ref

    def test_hash_leaves(self):
        from Crypto.Hash import TurboSHAKE128

        # Every combination of groups of 4 leaves and leftovers
        for n in range(1, 10):
            data = ptn(8192 * n)
            cvs = bytearray(32 * n)
            K12._hash_leaves(memoryview(data), memoryview(cvs))

            for i in range(n):
                leaf = data[i * 8192 : (i + 1) * 8192]
                cv = TurboSHAKE128.new(data=leaf, domain=0x0B).read(32)
                assert cvs[i * 32 : (i + 1) * 32] == cv

        # A range of leaves into a slice of a common buffer
        cvs2 = bytearray(32 * 5)
        K12._hash_leaves(memoryview(data)[8192 * 2 : 8192 * 4], memoryview(cvs2)[32 * 2 : 32 * 4])
        assert cvs2[32 * 2 : 32 * 4] == cvs[32 * 2 : 32 * 4]
        assert cvs2[: 32 * 2] == bytearray(32 * 2)
        assert cvs2[32 * 4 :] == bytearray(32)


class TestKangarooTwelveThreads:
    def test_threads_negative(self):
        for threads in (1.0, "2", None, True):
            with pytest.raises(TypeError):
                K12.new(threads=threads)
        for threads in (-1, -8):
            with pytest.raises(ValueError):
                K12.new(threads=threads)

        xof = K12.new()
        with pytest.raises(TypeError):
            xof.new(threads=2.0)
        with pytest.raises(ValueError):
            xof.new(threads=-1)

    def test_threads_all_cores(self):
        cores = available_cores()
        assert cores >= 1
        assert K12.new(threads=0)._threads == cores
        assert K12.new().new(threads=0)._threads == cores

        data = ptn(1024 * 1024 + 8192 * 3 + 5)
        ref = K12.new(data=data).read(32)
        assert K12.new(data=data, threads=0).read(32) == ref

    def test_leaf_boundaries(self):
        # Let each thread hash even a single leaf
        saved = K12._MIN_LEAVES_PER_THREAD
        K12._MIN_LEAVES_PER_THREAD = 1
        try:
            data = ptn(8192 * 20 + 1)
            for length in (
                8192 * 2 - 1,
                8192 * 2,
                8192 * 2 + 1,
                8192 * 3,
                8192 * 9,
                8192 * 9 + 1,
                8192 * 10 - 1,
                8192 * 17,
                8192 * 20 + 1,
            ):
                ref = K12.new(data=data[:length], custom=b"C").read(32)
                for threads in range(2, 9):
                    res = K12.new(data=data[:length], custom=b"C", threads=threads).read(32)
                    assert res == ref

                    xof = K12.new(custom=b"C", threads=threads)
                    xof.update(data[:100]).update(data[100:length])
                    assert xof.read(32) == ref
        finally:
            K12._MIN_LEAVES_PER_THREAD = saved

    def test_long_random_chunks(self):
        import random

        rng = random.Random(42)

        data = ptn(3 * 1024 * 1024 + 4567)
        ref = K12.new(data=data).read(32)

        for threads in (0, 2, 3, 4, 8):
            assert K12.new(data=data, threads=threads).read(32) == ref

            xof = K12.new(threads=threads)
            index = 0
            while index < len(data):
                size = rng.randint(1, 2 * 1024 * 1024)
                xof.update(memoryview(data)[index : index + size])
                index += size
            assert xof.read(32) == ref


def k12_reference(message, custom, length):
    """Straightforward KangarooTwelve, on top of TurboSHAKE128"""
    from Crypto.Hash import TurboSHAKE128

    s = bytes(message) + bytes(custom) + K12._length_encode(len(custom))
    if len(s) <= 8192:
        return TurboSHAKE128.new(data=s, domain=0x07).read(length)

    final_node = s[:8192] + b"\x03" + b"\x00" * 7
    leaves = [s[i : i + 8192] for i in range(8192, len(s), 8192)]
    for leaf in leaves:
        final_node += TurboSHAKE128.new(data=leaf, domain=0x0B).read(32)
    final_node += K12._length_encode(len(leaves)) + b"\xff\xff"
    return TurboSHAKE128.new(data=final_node, domain=0x06).read(length)


class TestKangarooTwelveDigest:
    def test_vs_reference(self):
        # fmt: off
        sizes = (0, 1, 100, 167, 168, 169, 4096, 8000, 8189, 8190, 8191, 8192, 8193,
                 8192 * 2, 8192 * 3 + 1, 100000)
        # fmt: on
        customs = (b"", b"C", b"C" * 300, b"C" * 8189, b"C" * 8192, b"C" * 9000)
        for size in sizes:
            data = ptn(size)
            for custom in customs:
                for length in (0, 1, 32, 200):
                    ref = k12_reference(data, custom, length)
                    assert K12.digest(data, length=length, custom=custom) == ref
                    assert K12.new(data=data, custom=custom).read(length) == ref

    def test_test_vectors(self):
        # Same as test_ptn_17_3 and test_ptn_c_41_3
        tv = """CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77
        2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0"""
        assert K12.digest(ptn(17**3), length=32) == txt2bin(tv)
        tv = """75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9
        DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF"""
        assert K12.digest(b"\xff" * 7, length=32, custom=ptn(41**3)) == txt2bin(tv)

    def test_types(self):
        ref = K12.digest(b"abc", length=32)
        assert K12.digest(bytearray(b"abc"), length=32) == ref
        assert K12.digest(memoryview(b"abc"), length=32) == ref
        assert K12.digest(b"abc", length=32, custom=None) == ref
        assert K12.digest(b"abc", length=32, custom=b"") == ref
        assert K12.digest(data=b"abc", length=32) == ref
        assert K12.digest(custom=b"", length=32, data=b"abc") == ref
        assert isinstance(ref, bytes)

    def test_negative(self):
        for bad in ("string", 5, None):
            with pytest.raises(TypeError):
                K12.digest(bad, length=32)
        with pytest.raises(TypeError):
            K12.digest(b"abc", length=32, custom="string")
        for bad in (32.0, "32", None, True):
            with pytest.raises(TypeError):
                K12.digest(b"abc", length=bad)
        with pytest.raises(ValueError):
            K12.digest(b"abc", length=-1)

    def test_keyword_only(self):
        # Only the message can be passed by position
        with pytest.raises(TypeError):
            K12.digest(b"abc", 32)
        with pytest.raises(TypeError):
            K12.digest(b"abc", 32, b"custom")
        with pytest.raises(TypeError):
            K12.digest(length=32)
