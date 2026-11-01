#
#  SelfTest/Hash/test_SHA.py: Self-test for the SHA-384 hash function
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

"""Self-test suite for Crypto.Hash.SHA384"""

import hashlib

import pytest

from Crypto.Hash import SHA384
from Crypto.Protocol.KDF import PBKDF2
from Crypto.SelfTest.Hash.common import make_hash_tests, sha512_armv8_required
from Crypto.Util import _cpu_features

# Test vectors from various sources
# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # RFC 4634: Section Page 8.4, "Test 1"
    (
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "abc",
    ),
    # RFC 4634: Section Page 8.4, "Test 2.2"
    (
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
    # RFC 4634: Section Page 8.4, "Test 3"
    (
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        "a" * 10**6,
        "'a' * 10**6",
    ),
    # Taken from http://de.wikipedia.org/wiki/Secure_Hash_Algorithm
    ("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""),
    # Example from http://de.wikipedia.org/wiki/Secure_Hash_Algorithm
    (
        "71e8383a4cea32d6fd6877495db2ee353542f46fa44bc23100bca48f3366b84e809f0708e81041f427c6d5219a286677",
        "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern",
    ),
]


TestVectors = make_hash_tests(SHA384, "SHA384", test_data, digest_size=48, oid="2.16.840.1.101.3.4.2.2")


# The implementation selected at import time (the fixture below replaces it)
_default_lib = SHA384._raw_sha384_lib

# Run every test with each C implementation available on this machine
_implementations = [pytest.param(SHA384._raw_sha384_portable_lib, id="portable")]
if SHA384._raw_sha384_armv8_lib is not None:
    _implementations.append(pytest.param(SHA384._raw_sha384_armv8_lib, id="armv8"))


@pytest.fixture(autouse=True, params=_implementations)
def sha384_implementation(request, monkeypatch):
    monkeypatch.setattr(SHA384, "_raw_sha384_lib", request.param)


class TestImplementations:
    # Required in CI on 64-bit ARM runners known to support the SHA-512 instructions,
    # so that a module that is not built, or a CPU feature that is not detected, fails
    @pytest.mark.skipif(
        not sha512_armv8_required(), reason="ARMv8 SHA-512 not required (see sha512_armv8_required)"
    )
    def test_sha512_armv8_available(self):
        assert _cpu_features.have_sha512_armv8(), "ARMv8 SHA-512 instructions not detected on this CPU"
        assert SHA384._raw_sha384_armv8_lib is not None, "ARMv8 SHA-512 module not built"
        assert _default_lib is SHA384._raw_sha384_armv8_lib, "ARMv8 SHA-512 module not selected"

    @pytest.mark.skipif(
        not _cpu_features.have_sha512_armv8(), reason="ARMv8 SHA-512 instructions not available"
    )
    def test_armv8_selected(self):
        assert SHA384._raw_sha384_armv8_lib is not None, "ARMv8 SHA-512 module not built"
        assert _default_lib is SHA384._raw_sha384_armv8_lib, "ARMv8 SHA-512 module not selected"

    def test_all_lengths(self):
        # Every padding case, over one and two blocks
        data = bytes(range(256)) * 2
        for length in range(2 * 128 + 20):
            assert SHA384.new(data[:length]).digest() == hashlib.sha384(data[:length]).digest()

    def test_chunks(self):
        # Partial and whole blocks, in any order
        data = bytes(range(256)) * 8
        for chunk_sizes in ((1, 127, 128, 129, 300), (128, 128, 1, 255, 600), (3, 1000, 7, 257)):
            h = SHA384.new()
            pos = 0
            for size in chunk_sizes:
                h.update(data[pos : pos + size])
                pos += size
            assert h.digest() == hashlib.sha384(data[:pos]).digest()

    def test_pbkdf2(self):
        expected = hashlib.pbkdf2_hmac("sha384", b"password", b"salt", 1000, 2 * 48 + 1)
        assert PBKDF2(b"password", b"salt", 2 * 48 + 1, 1000, hmac_hash_module=SHA384) == expected
