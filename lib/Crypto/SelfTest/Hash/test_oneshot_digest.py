"""Self-test suite for the one-shot digest() function of the SHA-2 and SHA-3 modules"""

import hashlib

import pytest

from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA224, SHA256, SHA384, SHA512

# (module, extra parameters, name in hashlib)
_HASHES = [
    (SHA224, {}, "sha224"),
    (SHA256, {}, "sha256"),
    (SHA384, {}, "sha384"),
    (SHA512, {}, "sha512"),
    (SHA512, {"truncate": "224"}, "sha512_224"),
    (SHA512, {"truncate": "256"}, "sha512_256"),
    (SHA3_224, {}, "sha3_224"),
    (SHA3_256, {}, "sha3_256"),
    (SHA3_384, {}, "sha3_384"),
    (SHA3_512, {}, "sha3_512"),
]

_IDS = [name for _, _, name in _HASHES]


def _hashlib_has(name):
    try:
        hashlib.new(name)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("module, params, name", _HASHES, ids=_IDS)
class TestOneShotDigest:
    def test_all_lengths(self, module, params, name):
        # Every padding case, over up to three blocks (SHA-2: 64 or 128 bytes; SHA-3: 72 to 144 bytes)
        if not _hashlib_has(name):
            pytest.skip("%s not in hashlib" % name)
        data = bytes(range(256)) * 2
        for length in range(450):
            msg = data[:length]
            expected = hashlib.new(name, msg).digest()
            assert module.digest(msg, **params) == expected
            assert module.new(msg, **params).digest() == expected

    def test_long(self, module, params, name):
        msg = bytes(range(256)) * 4000 + b"\x01\x02\x03"
        assert module.digest(msg, **params) == module.new(msg, **params).digest()

    def test_types(self, module, params, name):
        ref = module.digest(b"abc", **params)
        assert isinstance(ref, bytes)
        assert len(ref) == module.new(**params).digest_size
        assert module.digest(bytearray(b"abc"), **params) == ref
        assert module.digest(memoryview(b"abc"), **params) == ref
        assert module.digest(memoryview(bytearray(b"xabc"))[1:], **params) == ref
        assert module.digest(data=b"abc", **params) == ref
        assert module.digest(b"", **params) == module.new(**params).digest()

    def test_negative(self, module, params, name):
        for bad in ("string", 5, None):
            with pytest.raises(TypeError):
                module.digest(bad, **params)
        with pytest.raises(TypeError):
            module.digest(b"abc", b"abc")
        with pytest.raises(TypeError):
            module.digest(b"abc", unknown=1)


class TestSHA512Truncate:
    def test_default(self):
        assert SHA512.digest(b"abc") == SHA512.digest(b"abc", truncate=None)

    def test_keyword_only(self):
        with pytest.raises(TypeError):
            SHA512.digest(b"abc", "256")

    def test_bad_truncate(self):
        for bad in ("384", "512", "", 256):
            with pytest.raises(ValueError):
                SHA512.digest(b"abc", truncate=bad)
