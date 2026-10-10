#
#  SelfTest/Hash/common.py: Common code for Crypto.SelfTest.Hash
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

"""Self-testing for PyCrypto hash modules"""

import binascii
import os
import platform
import re
import struct
from binascii import hexlify, unhexlify

import pytest

from Crypto.Util._bytes import tobytes
from Crypto.Util.strxor import strxor_c


def sha_ni_required():
    """Return True if the SHA-NI implementation must be in use.

    This is the case if the environment variable PYCRYPTODOME_REQUIRE_SHA_NI
    is set (in CI, for runners known to support SHA-NI) and Python runs
    as a 64-bit x86 process (x86_64, also called AMD64).
    """

    if not os.environ.get("PYCRYPTODOME_REQUIRE_SHA_NI"):
        return False
    is_64bit = struct.calcsize("P") == 8
    return is_64bit and platform.machine().lower() in ("x86_64", "amd64")


def t2b(hex_string):
    shorter = re.sub(rb"\s+", b"", tobytes(hex_string))
    return unhexlify(shorter)


def make_hash_tests(module, module_name, test_data, digest_size, oid=None, extra_params={}):
    """Return a pytest test class for a hash module,
    with one test for each (expected, input[, description]) row in test_data"""

    vectors = []
    ids = []
    for i, row in enumerate(test_data):
        (expected, data) = map(tobytes, row[0:2])
        if len(row) < 3:
            description = repr(data)
        else:
            description = row[2]
        vectors.append((expected.lower(), data))
        ids.append("%s #%d: %s" % (module_name, i + 1, description))

    class HashTests:
        @pytest.mark.parametrize("expected, data", vectors, ids=ids)
        def test_vector(self, expected, data):
            h = module.new(**extra_params)
            h.update(data)

            out1 = binascii.b2a_hex(h.digest())
            out2 = h.hexdigest()

            h = module.new(data, **extra_params)

            out3 = h.hexdigest()
            out4 = binascii.b2a_hex(h.digest())

            # hexdigest() should return str(), and digest() bytes
            assert expected == out1  # h = .new(); h.update(data); h.digest()
            assert expected.decode() == out2  # h = .new(); h.update(data); h.hexdigest()
            assert expected.decode() == out3  # h = .new(data); h.hexdigest()
            assert expected == out4  # h = .new(data); h.digest()

            # Verify that the .new() method produces a fresh hash object, except
            # for MD5 and SHA1, which are hashlib objects.  (But test any .new()
            # method that does exist.)
            if module.__name__ not in ("Crypto.Hash.MD5", "Crypto.Hash.SHA1") or hasattr(h, "new"):
                h2 = h.new()
                h2.update(data)
                out5 = binascii.b2a_hex(h2.digest())
                assert expected == out5

        def test_digest_size(self):
            if "truncate" not in extra_params:
                assert module.digest_size == digest_size
            h = module.new(**extra_params)
            assert h.digest_size == digest_size

        if oid is not None:

            def test_oid(self):
                h = module.new(**extra_params)
                assert h.oid == oid

        def test_bytearray(self):
            data = b"\x00\x01\x02"

            # Data can be a bytearray (during initialization)
            ba = bytearray(data)

            h1 = module.new(data, **extra_params)
            h2 = module.new(ba, **extra_params)
            ba[:1] = b"\xff"
            assert h1.digest() == h2.digest()

            # Data can be a bytearray (during operation)
            ba = bytearray(data)

            h1 = module.new(**extra_params)
            h2 = module.new(**extra_params)

            h1.update(data)
            h2.update(ba)

            ba[:1] = b"\xff"
            assert h1.digest() == h2.digest()

        @pytest.mark.parametrize(
            "get_mv", [memoryview, lambda data: memoryview(bytearray(data))], ids=["ro", "rw"]
        )
        def test_memoryview(self, get_mv):
            data = b"\x00\x01\x02"

            # Data can be a memoryview (during initialization)
            mv = get_mv(data)

            h1 = module.new(data, **extra_params)
            h2 = module.new(mv, **extra_params)
            if not mv.readonly:
                mv[:1] = b"\xff"
            assert h1.digest() == h2.digest()

            # Data can be a memoryview (during operation)
            mv = get_mv(data)

            h1 = module.new(**extra_params)
            h2 = module.new(**extra_params)
            h1.update(data)
            h2.update(mv)
            if not mv.readonly:
                mv[:1] = b"\xff"
            assert h1.digest() == h2.digest()

    return HashTests


def make_mac_tests(module, module_name, test_data):
    """Return a pytest test class for a MAC module,
    with one test for each (key, data, result, description[, params]) row in test_data"""

    vectors = []
    ids = []
    for i, row in enumerate(test_data):
        if len(row) == 4:
            (key, data, result, description, params) = list(row) + [{}]
        else:
            (key, data, result, description, params) = row
        vectors.append((t2b(key), t2b(data), t2b(result), params))
        ids.append("%s #%d: %s" % (module_name, i + 1, description))

    class MACTests:
        @pytest.mark.parametrize("key, data, result, params", vectors, ids=ids)
        def test_vector(self, key, data, result, params):
            result_hex = hexlify(result)

            # Verify result
            h = module.new(key, **params)
            h.update(data)
            assert result == h.digest()
            assert hexlify(result).decode("ascii") == h.hexdigest()

            # Verify that correct MAC does not raise any exception
            h.verify(result)
            h.hexverify(result_hex)

            # Verify that incorrect MAC does raise ValueError exception
            wrong_mac = strxor_c(result, 255)
            with pytest.raises(ValueError):
                h.verify(wrong_mac)
            with pytest.raises(ValueError):
                h.hexverify("4556")

            # Verify again, with data passed to new()
            h = module.new(key, data, **params)
            assert result == h.digest()
            assert hexlify(result).decode("ascii") == h.hexdigest()

            # Test .copy()
            try:
                h = module.new(key, data, **params)
                h2 = h.copy()
                h3 = h.copy()

                # Verify that changing the copy does not change the original
                h2.update(b"bla")
                assert h3.digest() == result

                # Verify that both can reach the same state
                h.update(b"bla")
                assert h.digest() == h2.digest()
            except NotImplementedError:
                pass

            # Check that hexdigest() returns str and digest() returns bytes
            assert isinstance(h.digest(), bytes)
            assert isinstance(h.hexdigest(), str)

            # Check that .hexverify() accepts bytes or str
            h.hexverify(h.hexdigest())
            h.hexverify(h.hexdigest().encode("ascii"))

    return MACTests
