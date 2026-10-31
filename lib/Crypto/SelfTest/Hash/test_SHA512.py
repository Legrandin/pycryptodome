#
#  SelfTest/Hash/test_SHA512.py: Self-test for the SHA-512 hash function
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Self-test suite for Crypto.Hash.SHA512"""

import hashlib
from binascii import hexlify

import pytest

from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.SelfTest.Hash.common import make_hash_tests
from Crypto.SelfTest.loader import load_test_vectors
from Crypto.Util import _cpu_features

# Test vectors from various sources
# This is a list of (expected_result, input[, description]) tuples.
test_data_512_other = [
    # RFC 4634: Section Page 8.4, "Test 1"
    (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "abc",
    ),
    # RFC 4634: Section Page 8.4, "Test 2.1"
    (
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
    # RFC 4634: Section Page 8.4, "Test 3"
    (
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        "a" * 10**6,
        "'a' * 10**6",
    ),
    # Taken from http://de.wikipedia.org/wiki/Secure_Hash_Algorithm
    (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "",
    ),
    (
        "af9ed2de700433b803240a552b41b5a472a6ef3fe1431a722b2063c75e9f07451f67a28e37d09cde769424c96aea6f8971389db9e1993d6c565c3c71b855723c",
        "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern",
    ),
]


def _make_tests_SHA512():
    test_vectors = (
        load_test_vectors(("Hash", "SHA2"), "SHA512ShortMsg.rsp", "KAT SHA-512", {"len": lambda x: int(x)})
        or []
    )

    test_data = test_data_512_other[:]
    for tv in test_vectors:
        try:
            if tv.startswith("["):
                continue
        except AttributeError:
            pass
        if tv.len == 0:
            tv.msg = b""
        test_data.append((hexlify(tv.md), tv.msg, tv.desc))

    return make_hash_tests(SHA512, "SHA512", test_data, digest_size=64, oid="2.16.840.1.101.3.4.2.3")


def _make_tests_SHA512_224():
    test_vectors = (
        load_test_vectors(
            ("Hash", "SHA2"), "SHA512_224ShortMsg.rsp", "KAT SHA-512/224", {"len": lambda x: int(x)}
        )
        or []
    )

    test_data = []
    for tv in test_vectors:
        try:
            if tv.startswith("["):
                continue
        except AttributeError:
            pass
        if tv.len == 0:
            tv.msg = b""
        test_data.append((hexlify(tv.md), tv.msg, tv.desc))

    return make_hash_tests(
        SHA512,
        "SHA512/224",
        test_data,
        digest_size=28,
        oid="2.16.840.1.101.3.4.2.5",
        extra_params={"truncate": "224"},
    )


def _make_tests_SHA512_256():
    test_vectors = (
        load_test_vectors(
            ("Hash", "SHA2"), "SHA512_256ShortMsg.rsp", "KAT SHA-512/256", {"len": lambda x: int(x)}
        )
        or []
    )

    test_data = []
    for tv in test_vectors:
        try:
            if tv.startswith("["):
                continue
        except AttributeError:
            pass
        if tv.len == 0:
            tv.msg = b""
        test_data.append((hexlify(tv.md), tv.msg, tv.desc))

    return make_hash_tests(
        SHA512,
        "SHA512/256",
        test_data,
        digest_size=32,
        oid="2.16.840.1.101.3.4.2.6",
        extra_params={"truncate": "256"},
    )


TestSHA512 = _make_tests_SHA512()
TestSHA512_224 = _make_tests_SHA512_224()
TestSHA512_256 = _make_tests_SHA512_256()


# The implementation selected at import time (the fixture below replaces it)
_default_lib = SHA512._raw_sha512_lib

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(SHA512._raw_sha512_portable_lib, id="portable")]
if SHA512._raw_sha512_armv8_lib is not None:
    _implementations.append(pytest.param(SHA512._raw_sha512_armv8_lib, id="armv8"))


@pytest.fixture(autouse=True, params=_implementations)
def sha512_implementation(request, monkeypatch):
    monkeypatch.setattr(SHA512, "_raw_sha512_lib", request.param)


class TestImplementations:
    @pytest.mark.skipif(
        not _cpu_features.have_sha512_armv8(), reason="ARMv8 SHA-512 instructions not available"
    )
    def test_armv8_selected(self):
        assert SHA512._raw_sha512_armv8_lib is not None, "ARMv8 SHA-512 module not built"
        assert _default_lib is SHA512._raw_sha512_armv8_lib, "ARMv8 SHA-512 module not selected"

    def test_all_lengths(self):
        # Every padding case, over one and two blocks
        data = bytes(range(256)) * 2
        for length in range(2 * 128 + 20):
            assert SHA512.new(data[:length]).digest() == hashlib.sha512(data[:length]).digest()

    def test_chunks(self):
        # Partial and whole blocks, in any order
        data = bytes(range(256)) * 8
        for chunk_sizes in ((1, 127, 128, 129, 300), (128, 128, 1, 255, 600), (3, 1000, 7, 257)):
            h = SHA512.new()
            pos = 0
            for size in chunk_sizes:
                h.update(data[pos : pos + size])
                pos += size
            assert h.digest() == hashlib.sha512(data[:pos]).digest()

    def test_pbkdf2(self):
        expected = hashlib.pbkdf2_hmac("sha512", b"password", b"salt", 1000, 2 * 64 + 1)
        assert PBKDF2(b"password", b"salt", 2 * 64 + 1, 1000, hmac_hash_module=SHA512) == expected

    def test_truncated_all_lengths(self):
        data = bytes(range(256)) * 2
        for truncate, name in (("224", "sha512_224"), ("256", "sha512_256")):
            if name not in hashlib.algorithms_available:
                continue
            for length in range(0, 300, 7):
                expected = hashlib.new(name, data[:length]).digest()
                assert SHA512.new(data[:length], truncate=truncate).digest() == expected
