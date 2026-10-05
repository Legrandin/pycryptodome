#
# SelfTest/Hash/test_SHA3_224.py: Self-test for the SHA-3/224 hash function
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

"""Self-test suite for Crypto.Hash.SHA3_224"""

from binascii import hexlify

import pytest

from Crypto.Hash import SHA3_224 as SHA3
from Crypto.SelfTest.Hash.common import make_hash_tests
from Crypto.SelfTest.loader import load_test_vectors


class TestAPI:
    def test_update_after_digest(self):
        msg = b"rrrrttt"

        # Normally, update() cannot be done after digest()
        h = SHA3.new(data=msg[:4])
        dig1 = h.digest()
        with pytest.raises(TypeError):
            h.update(msg[4:])
        dig2 = SHA3.new(data=msg).digest()

        # With the proper flag, it is allowed
        h = SHA3.new(data=msg[:4], update_after_digest=True)
        assert h.digest() == dig1
        # ... and the subsequent digest applies to the entire message
        # up to that point
        h.update(msg[4:])
        assert h.digest() == dig2


def _load_test_data():
    test_vectors = (
        load_test_vectors(
            ("Hash", "SHA3"), "ShortMsgKAT_SHA3-224.txt", "KAT SHA-3 224", {"len": lambda x: int(x)}
        )
        or []
    )

    test_data = []
    for tv in test_vectors:
        if tv.len == 0:
            tv.msg = b""
        test_data.append((hexlify(tv.md), tv.msg, tv.desc))
    return test_data


TestVectors = make_hash_tests(
    SHA3, "SHA3_224", _load_test_data(), digest_size=SHA3.digest_size, oid="2.16.840.1.101.3.4.2.7"
)
