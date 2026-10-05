#
#  SelfTest/Hash/MD5.py: Self-test for the MD5 hash function
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

"""Self-test suite for Crypto.Hash.MD5"""

import pytest

from Crypto.Hash import MD5
from Crypto.SelfTest.Hash.common import make_hash_tests

# This is a list of (expected_result, input[, description]) tuples.
test_data = [
    # Test vectors from RFC 1321
    ("d41d8cd98f00b204e9800998ecf8427e", "", "'' (empty string)"),
    ("0cc175b9c0f1b6a831c399e269772661", "a"),
    ("900150983cd24fb0d6963f7d28e17f72", "abc"),
    ("f96b697d7cb7938d525a2f31aaf161d0", "message digest"),
    ("c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz", "a-z"),
    (
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "A-Z, a-z, 0-9",
    ),
    (
        "57edf4a22be3c955ac49da2e2107b67a",
        "1234567890123456789012345678901234567890123456" + "7890123456789012345678901234567890",
        "'1234567890' * 8",
    ),
    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/md5/Md5-128.unverified.test-vectors
    ("57EDF4A22BE3C955AC49DA2E2107B67A", "1234567890" * 8, "Set 1, vector #7"),
    ("7707D6AE4E027C70EEA2A935C2296F21", "a" * 1000000, "Set 1, vector #8"),
]


@pytest.mark.slow
class TestMd5Iter:
    def test(self):
        message = b"\x00" * 16
        result1 = "4AE71336E44BF9BF79D2752E234818A5".lower()
        result2 = "1A83F51285E4D89403D00C46EF8508FE".lower()

        h = MD5.new(message)
        message = h.digest()
        assert h.hexdigest() == result1

        for _ in range(99999):
            h = MD5.new(message)
            message = h.digest()

        assert h.hexdigest() == result2


TestVectors = make_hash_tests(MD5, "MD5", test_data, digest_size=16, oid="1.2.840.113549.2.5")
