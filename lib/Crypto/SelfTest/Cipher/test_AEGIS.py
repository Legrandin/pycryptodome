# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-test for AEGIS-128L and AEGIS-256 (RFC 10032)"""

import random

import pytest

from Crypto.Cipher import AEGIS
from Crypto.Cipher.AEGIS import AEGIS_128L, AEGIS_256
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof, wycheproof_id
from Crypto.SelfTest.st_common import wycheproof_warnings
from Crypto.Util.strxor import strxor

# All the implementations available on this CPU
BACKENDS = list(AEGIS._backends)

KEY_SIZE = {AEGIS_128L: 16, AEGIS_256: 32}


def make(key, variant, nonce, mac_len=16, backend=None):
    """A cipher object with a given implementation"""
    return AEGIS.AegisCipher(key, variant, nonce, mac_len, backend or AEGIS._default_backend)


# (variant, valid, key, nonce, ad, msg, ct, tag128, tag256), from Appendix A
_rfc_vectors = [
    # RFC 10032, AEGIS-128L, test vector 1
    (
        AEGIS_128L,
        True,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "c1c0e58bd913006feba00f4b3cc3594e",
        "abe0ece80c24868a226a35d16bdae37a",
        "25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4",
    ),
    # RFC 10032, AEGIS-128L, test vector 2
    (
        AEGIS_128L,
        True,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "",
        "",
        "",
        "c2b879a67def9d74e6c14f708bbcc9b4",
        "1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d",
    ),
    # RFC 10032, AEGIS-128L, test vector 3
    (
        AEGIS_128L,
        True,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "0001020304050607",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
        "cc6f3372f6aa1bb82388d695c3962d9a",
        "022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3",
    ),
    # RFC 10032, AEGIS-128L, test vector 4
    (
        AEGIS_128L,
        True,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "0001020304050607",
        "000102030405060708090a0b0c0d",
        "79d94593d8c2119d7e8fd9b8fc77",
        "5c04b3dba849b2701effbe32c7f0fab7",
        "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
    ),
    # RFC 10032, AEGIS-128L, test vector 5
    (
        AEGIS_128L,
        True,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
        "7542a745733014f9474417b337399507",
        "b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98",
    ),
    # RFC 10032, AEGIS-128L, test vector 6
    (
        AEGIS_128L,
        False,
        "10000200000000000000000000000000",
        "10010000000000000000000000000000",
        "0001020304050607",
        None,
        "79d94593d8c2119d7e8fd9b8fc77",
        "5c04b3dba849b2701effbe32c7f0fab7",
        "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
    ),
    # RFC 10032, AEGIS-128L, test vector 7
    (
        AEGIS_128L,
        False,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "0001020304050607",
        None,
        "79d94593d8c2119d7e8fd9b8fc78",
        "5c04b3dba849b2701effbe32c7f0fab7",
        "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
    ),
    # RFC 10032, AEGIS-128L, test vector 8
    (
        AEGIS_128L,
        False,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "0001020304050608",
        None,
        "79d94593d8c2119d7e8fd9b8fc77",
        "5c04b3dba849b2701effbe32c7f0fab7",
        "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
    ),
    # RFC 10032, AEGIS-128L, test vector 9
    (
        AEGIS_128L,
        False,
        "10010000000000000000000000000000",
        "10000200000000000000000000000000",
        "0001020304050607",
        None,
        "79d94593d8c2119d7e8fd9b8fc77",
        "6c04b3dba849b2701effbe32c7f0fab8",
        "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad",
    ),
    # RFC 10032, AEGIS-256, test vector 1
    (
        AEGIS_256,
        True,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "754fc3d8c973246dcc6d741412a4b236",
        "3fe91994768b332ed7f570a19ec5896e",
        "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
    ),
    # RFC 10032, AEGIS-256, test vector 2
    (
        AEGIS_256,
        True,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "",
        "",
        "",
        "e3def978a0f054afd1e761d7553afba3",
        "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
    ),
    # RFC 10032, AEGIS-256, test vector 3
    (
        AEGIS_256,
        True,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "0001020304050607",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
        "8d86f91ee606e9ff26a01b64ccbdd91d",
        "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
    ),
    # RFC 10032, AEGIS-256, test vector 4
    (
        AEGIS_256,
        True,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "0001020304050607",
        "000102030405060708090a0b0c0d",
        "f373079ed84b2709faee37358458",
        "c60b9c2d33ceb058f96e6dd03c215652",
        "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    ),
    # RFC 10032, AEGIS-256, test vector 5
    (
        AEGIS_256,
        True,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
        "ab8a7d53fd0e98d727accca94925e128",
        "a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734",
    ),
    # RFC 10032, AEGIS-256, test vector 6
    (
        AEGIS_256,
        False,
        "1000020000000000000000000000000000000000000000000000000000000000",
        "1001000000000000000000000000000000000000000000000000000000000000",
        "0001020304050607",
        None,
        "f373079ed84b2709faee37358458",
        "c60b9c2d33ceb058f96e6dd03c215652",
        "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    ),
    # RFC 10032, AEGIS-256, test vector 7
    (
        AEGIS_256,
        False,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "0001020304050607",
        None,
        "f373079ed84b2709faee37358459",
        "c60b9c2d33ceb058f96e6dd03c215652",
        "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    ),
    # RFC 10032, AEGIS-256, test vector 8
    (
        AEGIS_256,
        False,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "0001020304050608",
        None,
        "f373079ed84b2709faee37358458",
        "c60b9c2d33ceb058f96e6dd03c215652",
        "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    ),
    # RFC 10032, AEGIS-256, test vector 9
    (
        AEGIS_256,
        False,
        "1001000000000000000000000000000000000000000000000000000000000000",
        "1000020000000000000000000000000000000000000000000000000000000000",
        "0001020304050607",
        None,
        "f373079ed84b2709faee37358458",
        "c60b9c2d33ceb058f96e6dd03c215653",
        "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da",
    ),
]


class TestVectorsRFC:
    @pytest.mark.parametrize("backend", BACKENDS)
    @pytest.mark.parametrize("tag_len", [16, 32])
    @pytest.mark.parametrize("vector", _rfc_vectors)
    def test(self, vector, tag_len, backend):
        variant, valid, key, nonce, ad, msg, ct, tag128, tag256 = [
            bytes.fromhex(x) if isinstance(x, str) else x for x in vector
        ]
        tag = tag128 if tag_len == 16 else tag256

        if valid:
            cipher = make(key, variant, nonce, tag_len, backend)
            cipher.update(ad)
            assert cipher.encrypt_and_digest(msg) == (ct, tag)

            cipher = make(key, variant, nonce, tag_len, backend)
            cipher.update(ad)
            assert cipher.decrypt_and_verify(ct, tag) == msg
        else:
            cipher = make(key, variant, nonce, tag_len, backend)
            cipher.update(ad)
            with pytest.raises(ValueError, match="MAC check failed"):
                cipher.decrypt_and_verify(ct, tag)


def load_wycheproof_vectors():
    vectors = []
    for variant, filename in ((AEGIS_128L, "aegis128L_test.json"), (AEGIS_256, "aegis256_test.json")):
        vectors += load_test_vectors_wycheproof(
            ("Cipher", "wycheproof"),
            filename,
            "Wycheproof " + filename,
            root_tag={"variant": lambda root, variant=variant: variant},
        )
    return vectors


class TestVectorsWycheproof:
    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    @pytest.mark.parametrize("backend", BACKENDS)
    def test(self, tv, backend):
        if tv.valid:
            cipher = make(tv.key, tv.variant, tv.iv, len(tv.tag), backend)
            cipher.update(tv.aad)
            assert cipher.encrypt_and_digest(tv.msg) == (tv.ct, tv.tag)
            if tv.warning and wycheproof_warnings():
                import warnings

                warnings.warn("Wycheproof warning: %s (%s)" % (tv.id, tv.comment))

        cipher = make(tv.key, tv.variant, tv.iv, len(tv.tag), backend)
        cipher.update(tv.aad)
        try:
            pt = cipher.decrypt_and_verify(tv.ct, tv.tag)
        except ValueError:
            assert not tv.valid
        else:
            assert tv.valid
            assert pt == tv.msg

        # Any change to the ciphertext is detected
        if tv.valid and tv.ct:
            cipher = make(tv.key, tv.variant, tv.iv, len(tv.tag), backend)
            cipher.update(tv.aad)
            with pytest.raises(ValueError):
                cipher.decrypt_and_verify(strxor(tv.ct, b"\x00" * (len(tv.ct) - 1) + b"\x01"), tv.tag)


def load_external_vectors():
    """The vectors of libsodium (32-byte tags) and libaegis (16-byte tags),
    see the files for their origin"""
    vectors = []
    for variant, filename in ((AEGIS_128L, "aegis128l_test.txt"), (AEGIS_256, "aegis256_test.txt")):
        tvs = load_test_vectors(("Cipher", "AEGIS"), filename, filename, {"count": int}) or []
        for tv in tvs:
            tv.variant = variant
            tv.desc = "%s-%d" % (filename, tv.count)
        vectors += tvs
    return vectors


class TestVectorsExternal:
    @pytest.mark.parametrize("backend", BACKENDS)
    @pytest.mark.parametrize("tag_len", [16, 32])
    @pytest.mark.parametrize("tv", load_external_vectors(), ids=lambda tv: tv.desc)
    def test(self, tv, tag_len, backend):
        tag = tv.tag128 if tag_len == 16 else tv.tag256

        cipher = make(tv.key, tv.variant, tv.nonce, tag_len, backend)
        cipher.update(tv.ad)
        assert cipher.encrypt_and_digest(tv.msg) == (tv.ct, tag)

        cipher = make(tv.key, tv.variant, tv.nonce, tag_len, backend)
        cipher.update(tv.ad)
        assert cipher.decrypt_and_verify(tv.ct, tag) == tv.msg


@pytest.mark.parametrize("variant", [AEGIS_128L, AEGIS_256])
class TestChunks:
    """The associated data and the message can be split in any way"""

    @pytest.mark.parametrize("backend", BACKENDS)
    def test_chunks(self, variant, backend):
        rng = random.Random(variant)
        key = rng.randbytes(KEY_SIZE[variant])
        nonce = rng.randbytes(KEY_SIZE[variant])

        for _ in range(100):
            ad = rng.randbytes(rng.randrange(0, 150))
            msg = rng.randbytes(rng.randrange(0, 150))

            cipher = make(key, variant, nonce, 32, backend)
            cipher.update(ad)
            ct, tag = cipher.encrypt_and_digest(msg)

            def pieces(data):
                result, pos = [], 0
                while pos < len(data):
                    size = rng.randrange(0, 40)
                    result.append(data[pos : pos + size])
                    pos += size
                return result

            cipher = make(key, variant, nonce, 32, backend)
            for piece in pieces(ad):
                cipher.update(piece)
            assert b"".join(cipher.encrypt(piece) for piece in pieces(msg)) == ct
            assert cipher.digest() == tag

            cipher = make(key, variant, nonce, 32, backend)
            for piece in pieces(ad):
                cipher.update(piece)
            assert b"".join(cipher.decrypt(piece) for piece in pieces(ct)) == msg
            cipher.verify(tag)

    @pytest.mark.skipif(len(BACKENDS) < 2, reason="Only one implementation")
    def test_backends_agree(self, variant):
        rng = random.Random(10 + variant)
        for size in list(range(70)) + [1000, 4096 + 7]:
            key = rng.randbytes(KEY_SIZE[variant])
            nonce = rng.randbytes(KEY_SIZE[variant])
            ad = rng.randbytes(size // 2)
            msg = rng.randbytes(size)
            results = set()
            for backend in BACKENDS:
                cipher = make(key, variant, nonce, 32, backend)
                cipher.update(ad)
                results.add(cipher.encrypt_and_digest(msg))
            assert len(results) == 1


@pytest.mark.parametrize("variant", [AEGIS_128L, AEGIS_256])
class TestAPI:
    def key(self, variant):
        return b"K" * KEY_SIZE[variant]

    def nonce(self, variant):
        return b"N" * KEY_SIZE[variant]

    def test_loopback(self, variant):
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"header")
        ct, tag = cipher.encrypt_and_digest(b"message" * 10)
        assert len(ct) == 70 and len(tag) == 16

        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"header")
        assert cipher.decrypt_and_verify(ct, tag) == b"message" * 10

    def test_key_length(self, variant):
        for size in (0, 15, 16, 24, 31, 32, 33):
            if size == KEY_SIZE[variant]:
                continue
            with pytest.raises(ValueError, match="key of"):
                AEGIS.new(b"K" * size, variant, nonce=b"N" * size)

    def test_nonce_length(self, variant):
        for size in (0, 12, 15, 16, 24, 32, 33):
            if size == KEY_SIZE[variant]:
                continue
            with pytest.raises(ValueError, match="nonce of"):
                AEGIS.new(self.key(variant), variant, nonce=b"N" * size)

    def test_random_nonce(self, variant):
        cipher1 = AEGIS.new(self.key(variant), variant)
        cipher2 = AEGIS.new(self.key(variant), variant)
        assert len(cipher1.nonce) == KEY_SIZE[variant]
        assert cipher1.nonce != cipher2.nonce

        # The nonce attribute is the one used
        ct, tag = cipher1.encrypt_and_digest(b"data")
        cipher = AEGIS.new(self.key(variant), variant, nonce=cipher1.nonce)
        assert cipher.decrypt_and_verify(ct, tag) == b"data"

    def test_nonce_attribute(self, variant):
        nonce = bytearray(self.nonce(variant))
        cipher = AEGIS.new(self.key(variant), variant, nonce=nonce)
        assert cipher.nonce == bytes(nonce) and isinstance(cipher.nonce, bytes)

    def test_types(self, variant):
        with pytest.raises(TypeError):
            AEGIS.new("K" * KEY_SIZE[variant], variant)
        with pytest.raises(TypeError):
            AEGIS.new(self.key(variant), variant, nonce="N" * KEY_SIZE[variant])
        cipher = AEGIS.new(self.key(variant), variant)
        with pytest.raises(TypeError):
            cipher.update("text")
        with pytest.raises(TypeError):
            cipher.encrypt("text")

    def test_mac_len(self, variant):
        for mac_len in (0, 8, 12, 15, 17, 31, 33):
            with pytest.raises(ValueError, match="16 or 32"):
                AEGIS.new(self.key(variant), variant, mac_len=mac_len)
        for mac_len in (16, 32):
            cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant), mac_len=mac_len)
            assert len(cipher.digest()) == mac_len

        # A 16-byte tag is not the first half of the 32-byte tag
        tag16 = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).digest()
        tag32 = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant), mac_len=32).digest()
        assert tag32[:16] != tag16

    def test_invalid_mac(self, variant):
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        ct, tag = cipher.encrypt_and_digest(b"data")
        for bad_tag in (tag[:-1] + bytes([tag[-1] ^ 1]), tag[:15], tag + b"\x00", b""):
            cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
            with pytest.raises(ValueError, match="MAC check failed"):
                cipher.decrypt_and_verify(ct, bad_tag)

    def test_hex_mac(self, variant):
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.encrypt(b"data")
        hex_tag = cipher.hexdigest()
        assert bytes.fromhex(hex_tag) == cipher.digest()

        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.decrypt(AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).encrypt(b"data"))
        cipher.hexverify(hex_tag)

    def test_buffer_types(self, variant):
        msg = b"x" * 50
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"ad")
        ct, tag = cipher.encrypt_and_digest(msg)

        for conv in (bytearray, memoryview):
            cipher = AEGIS.new(conv(self.key(variant)), variant, nonce=conv(self.nonce(variant)))
            cipher.update(conv(b"ad"))
            assert cipher.encrypt_and_digest(conv(msg)) == (ct, tag)

            cipher = AEGIS.new(conv(self.key(variant)), variant, nonce=conv(self.nonce(variant)))
            cipher.update(conv(b"ad"))
            assert cipher.decrypt_and_verify(conv(ct), conv(tag)) == msg

    def test_output(self, variant):
        msg = bytes(range(100))
        ct, tag = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).encrypt_and_digest(msg)

        output = bytearray(100)
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        assert cipher.encrypt(msg, output=output) is None
        assert output == ct and cipher.digest() == tag

        output = memoryview(bytearray(100))
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        assert cipher.decrypt(ct, output=output) is None
        assert output == msg
        cipher.verify(tag)

        # In place
        buf = bytearray(msg)
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.encrypt(buf, output=buf)
        assert buf == ct
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.decrypt(buf, output=buf)
        assert buf == msg

        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        with pytest.raises(TypeError):
            cipher.encrypt(msg, output=b"x" * 100)
        with pytest.raises(ValueError):
            cipher.encrypt(msg, output=bytearray(99))

    @pytest.mark.parametrize("wrap", [bytearray, memoryview])
    def test_output_one_step(self, variant, wrap):
        msg = bytes(range(100))
        ct, tag = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).encrypt_and_digest(msg)

        output = wrap(bytearray(100))
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        assert cipher.encrypt_and_digest(msg, output=output) == (None, tag)
        assert output == ct

        output = wrap(bytearray(100))
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        assert cipher.decrypt_and_verify(ct, tag, output=output) is None
        assert output == msg

    @pytest.mark.parametrize("wrap", [bytearray, memoryview])
    def test_no_unauthenticated_plaintext(self, variant, wrap):
        msg = bytes(range(100))
        ct, tag = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).encrypt_and_digest(msg)
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]

        output = wrap(bytearray(b"\xaa" * len(ct)))
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        with pytest.raises(ValueError):
            cipher.decrypt_and_verify(ct, bad_tag, output=output)
        assert bytes(output) == bytes(len(ct))

    def test_empty(self, variant):
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"")
        assert cipher.encrypt(b"") == b""
        tag = cipher.digest()
        assert tag == AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant)).digest()

    def test_ad_only(self, variant):
        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"ad")
        tag = cipher.digest()

        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"ad")
        cipher.verify(tag)

        cipher = AEGIS.new(self.key(variant), variant, nonce=self.nonce(variant))
        cipher.update(b"ae")
        with pytest.raises(ValueError):
            cipher.verify(tag)


@pytest.mark.parametrize("variant", [AEGIS_128L, AEGIS_256])
class TestFSM:
    """The order in which the methods can be called"""

    def new(self, variant):
        return AEGIS.new(b"K" * KEY_SIZE[variant], variant, nonce=b"N" * KEY_SIZE[variant])

    def test_unknown_mode(self, variant):
        with pytest.raises(ValueError, match="Unknown AEGIS variant"):
            AEGIS.new(b"K" * 16, 3)

    def test_update_after_encrypt_or_decrypt(self, variant):
        cipher = self.new(variant)
        cipher.encrypt(b"a")
        with pytest.raises(TypeError):
            cipher.update(b"b")
        cipher = self.new(variant)
        cipher.decrypt(b"a")
        with pytest.raises(TypeError):
            cipher.update(b"b")

    def test_mixing_encrypt_decrypt(self, variant):
        cipher = self.new(variant)
        cipher.encrypt(b"a")
        with pytest.raises(TypeError):
            cipher.decrypt(b"b")
        cipher = self.new(variant)
        cipher.decrypt(b"a")
        with pytest.raises(TypeError):
            cipher.encrypt(b"b")

    def test_digest_or_verify(self, variant):
        cipher = self.new(variant)
        cipher.encrypt(b"a")
        with pytest.raises(TypeError):
            cipher.verify(b"x" * 16)
        cipher = self.new(variant)
        cipher.decrypt(b"a")
        with pytest.raises(TypeError):
            cipher.digest()

    def test_after_digest(self, variant):
        cipher = self.new(variant)
        tag = cipher.digest()
        assert cipher.digest() == tag
        for method, arg in ((cipher.update, b"a"), (cipher.encrypt, b"a"), (cipher.decrypt, b"a")):
            with pytest.raises(TypeError):
                method(arg)

    def test_after_verify(self, variant):
        tag = self.new(variant).digest()
        cipher = self.new(variant)
        cipher.verify(tag)
        cipher.verify(tag)
        for method, arg in ((cipher.update, b"a"), (cipher.encrypt, b"a"), (cipher.decrypt, b"a")):
            with pytest.raises(TypeError):
                method(arg)
