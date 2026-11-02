#
#  SelfTest/Cipher/test_pkcs1_15.py: Self-test for PKCS#1 v1.5 encryption
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


import warnings

import pytest

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA
from Crypto.SelfTest.loader import load_test_vectors, load_test_vectors_wycheproof, wycheproof_id
from Crypto.SelfTest.st_common import a2b_hex, mark_slow, wycheproof_warnings
from Crypto.Util.number import bytes_to_long, long_to_bytes


def rws(t):
    """Remove white spaces, tabs, and new lines from a string"""
    for c in ["\n", "\t", " "]:
        t = t.replace(c, "")
    return t


def t2b(t):
    """Convert a text string with bytes in hex form to a byte string"""
    clean = rws(t).encode("latin-1")
    if len(clean) % 2 == 1:
        raise ValueError("Even number of characters expected")
    return a2b_hex(clean)


class TestPKCS1_15:
    def setup_method(self):
        self.rng = Random.new().read
        self.key1024 = RSA.generate(1024, self.rng)

    # List of tuples with test data for PKCS#1 v1.5.
    # Each tuple is made up by:
    #       Item #0: dictionary with RSA key component, or key to import
    #       Item #1: plaintext
    #       Item #2: ciphertext
    #       Item #3: random data

    _testData = (
        #
        # Generated with openssl 0.9.8o
        #
        (
            # Private key
            """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDAiAnvIAOvqVwJTaYzsKnefZftgtXGE2hPJppGsWl78yz9jeXY
W/FxX/gTPURArNhdnhP6n3p2ZaDIBrO2zizbgIXs0IsljTTcr4vnI8fMXzyNUOjA
zP3nzMqZDZK6757XQAobOssMkBFqRWwilT/3DsBhRpl3iMUhF+wvpTSHewIDAQAB
AoGAC4HV/inOrpgTvSab8Wj0riyZgQOZ3U3ZpSlsfR8ra9Ib9Uee3jCYnKscu6Gk
y6zI/cdt8EPJ4PuwAWSNJzbpbVaDvUq25OD+CX8/uRT08yBS4J8TzBitZJTD4lS7
atdTnKT0Wmwk+u8tDbhvMKwnUHdJLcuIsycts9rwJVapUtkCQQDvDpx2JMun0YKG
uUttjmL8oJ3U0m3ZvMdVwBecA0eebZb1l2J5PvI3EJD97eKe91Nsw8T3lwpoN40k
IocSVDklAkEAzi1HLHE6EzVPOe5+Y0kGvrIYRRhncOb72vCvBZvD6wLZpQgqo6c4
d3XHFBBQWA6xcvQb5w+VVEJZzw64y25sHwJBAMYReRl6SzL0qA0wIYrYWrOt8JeQ
8mthulcWHXmqTgC6FEXP9Es5GD7/fuKl4wqLKZgIbH4nqvvGay7xXLCXD/ECQH9a
1JYNMtRen5unSAbIOxRcKkWz92F0LKpm9ZW/S9vFHO+mBcClMGoKJHiuQxLBsLbT
NtEZfSJZAeS2sUtn3/0CQDb2M2zNBTF8LlM0nxmh0k9VGm5TVIyBEMcipmvOgqIs
HKukWBcq9f/UOmS0oEhai/6g+Uf7VHJdWaeO5LzuvwU=
-----END RSA PRIVATE KEY-----""",
            # Plaintext
            """THIS IS PLAINTEXT\x0a""",
            # Ciphertext
            """3f dc fd 3c cd 5c 9b 12  af 65 32 e3 f7 d0 da 36
                8f 8f d9 e3 13 1c 7f c8  b3 f9 c1 08 e4 eb 79 9c
                91 89 1f 96 3b 94 77 61  99 a4 b1 ee 5d e6 17 c9
                5d 0a b5 63 52 0a eb 00  45 38 2a fb b0 71 3d 11
                f7 a1 9e a7 69 b3 af 61  c0 bb 04 5b 5d 4b 27 44
                1f 5b 97 89 ba 6a 08 95  ee 4f a2 eb 56 64 e5 0f
                da 7c f9 9a 61 61 06 62  ed a0 bc 5f aa 6c 31 78
                70 28 1a bb 98 3c e3 6a  60 3c d1 0b 0f 5a f4 75""",
            # Random data
            """eb d7 7d 86 a4 35 23 a3 54 7e 02 0b 42 1d
                61 6c af 67 b8 4e 17 56 80 66 36 04 64 34 26 8a
                47 dd 44 b3 1a b2 17 60 f4 91 2e e2 b5 95 64 cc
                f9 da c8 70 94 54 86 4c ef 5b 08 7d 18 c4 ab 8d
                04 06 33 8f ca 15 5f 52 60 8a a1 0c f5 08 b5 4c
                bb 99 b8 94 25 04 9c e6 01 75 e6 f9 63 7a 65 61
                13 8a a7 47 77 81 ae 0d b8 2c 4d 50 a5""",
        ),
    )

    def testEncrypt1(self):
        for test in self._testData:
            # Build the key
            key = RSA.importKey(test[0])

            # RNG that takes its random numbers from a pool given
            # at initialization
            class randGen:
                def __init__(self, data):
                    self.data = data
                    self.idx = 0

                def __call__(self, N):
                    r = self.data[self.idx : self.idx + N]
                    self.idx += N
                    return r

            # The real test
            cipher = PKCS.new(key, randfunc=randGen(t2b(test[3])))
            ct = cipher.encrypt(test[1].encode("latin-1"))
            assert ct == t2b(test[2])

    def testEncrypt2(self):
        # Verify that encryption fail if plaintext is too long
        pt = "\x00" * (128 - 11 + 1)
        cipher = PKCS.new(self.key1024)
        with pytest.raises(ValueError):
            cipher.encrypt(pt)

    def testVerify1(self):
        for test in self._testData:
            key = RSA.importKey(test[0])
            expected_pt = test[1].encode("latin-1")
            ct = t2b(test[2])
            cipher = PKCS.new(key)

            # The real test
            pt = cipher.decrypt(ct)
            assert pt == expected_pt

            pt = cipher.decrypt(ct, expected_pt_len=len(expected_pt))
            assert pt == expected_pt

    def testVerify2(self):
        # Verify that decryption fails if ciphertext is not as long as
        # RSA modulus
        cipher = PKCS.new(self.key1024)
        with pytest.raises(ValueError):
            cipher.decrypt(b"\x00" * 127)
        with pytest.raises(ValueError):
            cipher.decrypt(b"\x00" * 129)

        # Verify that decryption fails if the ciphertext is not smaller
        # than the modulus
        with pytest.raises(ValueError):
            cipher.decrypt(b"\xff" * 128)

        # Verify that decryption fails if there are less then 8 non-zero padding
        # bytes: a pseudo-random message is returned instead
        pt = b"\x00\x02" + b"\xff" * 7 + b"\x00" + b"\x45" * 118
        ct = long_to_bytes(self.key1024._encrypt(bytes_to_long(pt)), 128)
        pt2 = cipher.decrypt(ct)
        assert pt2 != pt[10:]
        assert len(pt2) <= 128 - 11

    def test_decrypt_public_key(self):
        cipher = PKCS.new(self.key1024.public_key())
        ct = cipher.encrypt(b"XYZ")
        with pytest.raises(TypeError):
            cipher.decrypt(ct)

    def testEncryptVerify1(self):
        # Encrypt/Verify messages of length [0..RSAlen-11]
        # and therefore padding [8..117]
        for pt_len in range(128 - 11 + 1):
            pt = self.rng(pt_len)
            cipher = PKCS.new(self.key1024)
            ct = cipher.encrypt(pt)
            pt2 = cipher.decrypt(ct)
            assert pt == pt2

    def test_encrypt_verify_exp_pt_len(self):
        cipher = PKCS.new(self.key1024)
        pt = b"5" * 16
        ct = cipher.encrypt(pt)

        pt_A = cipher.decrypt(ct, expected_pt_len=16)
        assert pt == pt_A

        # With an unexpected length, the result is a pseudo-random message
        # of the expected length, always the same for the same ciphertext
        pt_B = cipher.decrypt(ct, expected_pt_len=15)
        assert len(pt_B) == 15
        assert pt_B != pt[:15]
        assert pt_B == PKCS.new(self.key1024).decrypt(ct, expected_pt_len=15)

        pt_C = cipher.decrypt(ct, expected_pt_len=17)
        assert len(pt_C) == 17
        assert pt_C == cipher.decrypt(ct, expected_pt_len=17)

        # The expected length is too long
        with pytest.raises(ValueError):
            cipher.decrypt(ct, expected_pt_len=128 - 10)

    def testByteArray(self):
        pt = b"XER"
        cipher = PKCS.new(self.key1024)
        ct = cipher.encrypt(bytearray(pt))
        pt2 = cipher.decrypt(bytearray(ct))
        assert pt == pt2

    def testMemoryview(self):
        pt = b"XER"
        cipher = PKCS.new(self.key1024)
        ct = cipher.encrypt(memoryview(bytearray(pt)))
        pt2 = cipher.decrypt(memoryview(bytearray(ct)))
        assert pt == pt2

    def test_return_type(self):
        pt = b"XYZ"
        cipher = PKCS.new(self.key1024)
        ct = cipher.encrypt(pt)
        assert isinstance(ct, bytes)
        pt2 = cipher.decrypt(ct)
        assert isinstance(pt2, bytes)

        # Invalid padding
        em = b"\x00\x01" + b"\xff" * 100 + b"\x00" + b"A" * 25
        ct = long_to_bytes(self.key1024._encrypt(bytes_to_long(em)), 128)
        pt3 = cipher.decrypt(ct)
        assert isinstance(pt3, bytes)


class TestImplicitRejection:
    """Implicit rejection (draft-irtf-cfrg-rsa-guidance)"""

    def setup_method(self):
        self.key = RSA.generate(1024)
        self.cipher = PKCS.new(self.key)

    def _encrypt_raw(self, em):
        return long_to_bytes(self.key._encrypt(bytes_to_long(em)), 128)

    def test_deterministic(self):
        em = b"\x00\x02" + b"\xff" * 100 + b"\x01" + b"A" * 25  # no separator
        ct = self._encrypt_raw(em)
        pt1 = self.cipher.decrypt(ct)
        pt2 = self.cipher.decrypt(ct)
        pt3 = PKCS.new(RSA.construct((self.key.n, self.key.e, self.key.d))).decrypt(ct)
        assert pt1 == pt2 == pt3

    def test_depends_on_key_and_ciphertext(self):
        em = b"\x00\x01" + b"\xff" * 100 + b"\x00" + b"A" * 25
        ct1 = self._encrypt_raw(em)
        ct2 = self._encrypt_raw(em[:-1] + b"B")
        results = {self.cipher.decrypt(ct1), self.cipher.decrypt(ct2)}

        key2 = RSA.generate(1024)
        ct3 = long_to_bytes(key2._encrypt(bytes_to_long(em)), 128)
        results.add(PKCS.new(key2).decrypt(ct3))
        assert len(results) == 3

    def test_no_warning(self):
        ct = self.cipher.encrypt(b"XYZ")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert self.cipher.decrypt(ct) == b"XYZ"

    def test_draft_example(self):
        # B.1 in draft-irtf-cfrg-rsa-guidance-10
        cipher = PKCS.new(RSA.import_key(_draft_key_2048))

        # B.1.2: Valid
        assert cipher.decrypt(t2b(_draft_ct_valid)) == b"lorem ipsum dolor sit amet"

        # B.1.8: Invalid with second to last length
        assert cipher.decrypt(t2b(_draft_ct_invalid)) == b"\x0f\x9b"


_draft_key_2048 = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIzIOXFAmNpWyq
I2QPk9yJl8FjcpaPwbDG31ETwclOiyHkitIpfmVBkBG05tj15zsbeLJXQAMh0e9r
YC1OyM6NFByUkF60rTBmOaSSBlNLbn8mB0I+l9/9EzyI1yE5ne+8fpbM3L1/Oq4f
6JJxK/tJKYF9URZmRAofrLeiCPXqFlkQrdij8tSXICNgzLYyAk8NBxacGRjzFveU
sUOu9U7IdSKkwCl4+WiZgL/79knDB+gYGb/4hAljjUi9lL4VK1n/ZJ+gvWKdD/oY
E8Or9LVr08LqVGXf+hRYkpKp2KJK0mvn7gUQdBtjgtQ8g9W/pApGYT0GK+RFUX28
rwy04adpAgMBAAECggEAFFUBDg8tWHZjpmam/xzNu/Dt2BAGRtAqAjkikImSxK05
5VZZKXJu9lCMOnEVjvC2/3UdOdB1gLstLwYyEEQtBgP/UNu9ezX+LJuxmkehr4Wk
wkkB4CyotYt5GbIO3zKqz79RrbS8S2G5t+loyqTVcPcO8Y2AYyKIk+R9Q578p5Ml
m88s0Qij2GiM3weOeseZlp8jOdLB9SK5aWhGKakzuq7CaBYl6rhPTlb0RH6diPua
GZz3ECPg4lexREGzPITTvGfKgDHSYSYYEDp6CkCEQmL3XYiQzWFuUfkDVIj9bgmd
6P9tZaT/EYJUgHyfWNL7uouhUdyMaL40nJd6IE4EwQKBgQD49a1rqCiTG+pFm4o/
bcBB0jSCQJwlcelj8x90hgKiVjcbOIPtRZ7PlwUmRZ7dFuBVIvWkXZR1Gy7C2vJy
x/iBalLADRgIAXFjTaiZ15cyIvUbk3YwVIaWqffYwkpZSXwe/NRVz7l+6G0rbTSX
KzMv2jA/BJmbTra1zAuzPndh3QKBgQDOei47SakLljMKEtxoK9+9+66N1twDthR6
771XV0Pw9tpNhiNQYbca/ZytLTQCXlashrD3dD6zXhrLyiN4lUJEZbcG7SIXXlcY
yMcLZwPqj2tRD5Rb5I5aNrs8PJFzK1id/AXXLYCQMZRFK9ohNIZH7HKUPxGoRuYv
rr6OtTaw/QKBgHb+FfGK4jnN8d9rRFykvGu5aNeIwhkzpPXc0oADPWcSBizAim3y
BMH70L5GMHRD5t1KZFY3VCnU4DjKJW+vHJvekcaxe3b4GZX5HEjLvrx78ONJTAg1
nk6M1qWH17ltYiH9fg+1xVdfCC7ld2l5gHGyu7SjIjgVG0cxS7ZUeQMRAoGBAJmI
SLBVSZoQCcvH0pSzax/98gIObnNkBT6U3hoADck0BYf34nJ29ozfYI11O2M3ewO2
9AhNLAJ8SziWCmIzup7Zc4t28Q6nW+RWB4v3AfZ8xrPz/cGG5kM2x2s3LoCRDsgL
CtzCPQL7muEEhqKCSAdbTqflbd/POILkUVYUcaKRAoGAZDv3RkKffYNmegZTAhNH
77/AXmNR+CGp3rtg4OzN5QBa2ensMeVY9+ksKTKOdFadfO98dMq8KzVe1AGhoJFL
Tjy7BkhOWBlgURae0UyqLvpuoETgVNJhRMwWKcVQEFWKBOEz9Et8JE2sJb+RPFe4
kO5J9UglnNY0BP72hZ3Pl1o=
-----END PRIVATE KEY-----"""

_draft_ct_valid = """
8bfe264e85d3bdeaa6b8851b8e3b956ee3d226fd3f69063a86880173a273d9f2
83b2eebdd1ed35f7e02d91c571981b6737d5320bd8396b0f3ad5b019daec1b0a
ab3cbbc026395f4fd14f13673f2dfc81f9b660ec26ac381e6db3299b4e460b43
fab9955df2b3cfaa20e900e19c856238fd371899c2bf2ce8c868b76754e5db3b
036533fd603746be13c10d4e3e6022ebc905d20c2a7f32b215a4cd53b3f44ca1
c327d2c2b651145821c08396c89071f665349c25e44d2733cd9305985ceef643
0c3cf57af5fa224089221218fa34737c79c446d28a94c41c96e4e92ac53fbcf3
84dea8419ea089f8784445a492c812eb0d409467f75afd7d4d1078886205a066
"""

_draft_ct_invalid = """
1439e08c3f84c1a7fec74ce07614b20e01f6fa4e8c2a6cffdc3520d8889e5d9a
950c6425798f85d4be38d300ea5695f13ecd4cb389d1ff5b82484b494d6280ab
7fa78e645933981cb934cce8bfcd114cc0e6811eefa47aae20af638a1cd163d2
d3366186d0a07df0c81f6c9f3171cf3561472e98a6006bf75ddb457bed036dcc
e199369de7d94ef2c68e8467ee0604eea2b3009479162a7891ba5c40cab17f49
e1c438cb6eaea4f76ce23cce0e483ff0e96fa790ea15be67671814342d0a23f4
a20262b6182e72f3a67cd289711503c85516a9ed225422f98b116f1ab080a80a
bd6f0216df88d8cfd67c139243be8dd78502a7aaf6bc99d7da71bcdf627e7354
"""


def load_draft_vectors():
    """All the test vectors in Appendix B of draft-irtf-cfrg-rsa-guidance-10"""

    entries = load_test_vectors(
        ("Cipher", "PKCS1_v1_5"),
        "implicit_rejection.txt",
        "PKCS#1 v1.5 implicit rejection",
        {"comment": lambda x: x},
    )
    if entries is None:
        return []

    vectors = []
    key = None
    for entry in entries:
        if isinstance(entry, str):
            continue
        if hasattr(entry, "key"):
            key = RSA.import_key(entry.key)
            continue
        entry.rsa_key = key
        entry.desc = "%d bits, %s" % (key.size_in_bits(), entry.comment)
        vectors.append(entry)
    return vectors


@pytest.mark.parametrize("tv", load_draft_vectors(), ids=lambda tv: tv.desc)
def test_draft_vectors(tv):
    assert PKCS.new(tv.rsa_key).decrypt(tv.ct) == tv.msg


class TestSentinel:
    """Decryption with a sentinel (no implicit rejection)"""

    def setup_method(self):
        self.key1024 = RSA.generate(1024)

    def _encrypt_raw(self, em):
        return long_to_bytes(self.key1024._encrypt(bytes_to_long(em)), 128)

    def test_no_warning(self):
        cipher = PKCS.new(self.key1024)
        ct = cipher.encrypt(b"XYZ")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert cipher.decrypt(ct, b"---") == b"XYZ"
            assert cipher.decrypt(ct, sentinel=None) == b"XYZ"

    def test_incorrect_length(self):
        cipher = PKCS.new(self.key1024)
        with pytest.raises(ValueError):
            cipher.decrypt(b"\x00" * 127, "---")
        with pytest.raises(ValueError):
            cipher.decrypt(b"\x00" * 129, "---")

    def test_short_padding(self):
        # Less then 8 non-zero padding bytes
        cipher = PKCS.new(self.key1024)
        ct = self._encrypt_raw(b"\x00\x02" + b"\xff" * 7 + b"\x00" + b"\x45" * 118)
        assert cipher.decrypt(ct, b"---") == b"---"

    def test_non_bytes_sentinel(self):
        cipher = PKCS.new(self.key1024)
        marker = object()
        long_sentinel = b"\xaa" * 129  # longer than the modulus

        # Incorrect padding (no separator, wrong first bytes, short PS)
        for em in (
            b"\x00\x02" + b"\xff" * 126,
            b"\x00\x01" + b"\xff" * 100 + b"\x00" + b"A" * 25,
            b"\x00\x02" + b"\xff" * 7 + b"\x00" + b"\x45" * 118,
        ):
            ct = self._encrypt_raw(em)
            assert cipher.decrypt(ct, None) is None
            assert cipher.decrypt(ct, 42) == 42
            assert cipher.decrypt(ct, marker) is marker
            assert cipher.decrypt(ct, long_sentinel) is long_sentinel

        # Correct padding, including the empty and the longest message
        for pt in (b"", b"Z", b"XYZ", b"\x00" * 117):
            ct = cipher.encrypt(pt)
            assert cipher.decrypt(ct, None) == pt
            assert cipher.decrypt(ct, 42) == pt
            assert cipher.decrypt(ct, long_sentinel) == pt

        # Wrong expected length
        ct = cipher.encrypt(b"XYZ")
        assert cipher.decrypt(ct, None, 3) == b"XYZ"
        assert cipher.decrypt(ct, None, 4) is None

    def test_bad_expected_length(self):
        cipher = PKCS.new(self.key1024)
        ct = cipher.encrypt(b"XYZ")
        for sentinel in (None, b"---"):
            with pytest.raises(ValueError):
                cipher.decrypt(ct, sentinel, 128 - 10)

    def test_encrypt_verify(self):
        rng = Random.new().read
        cipher = PKCS.new(self.key1024)
        for pt_len in (0, 1, 16, 117):
            pt = rng(pt_len)
            ct = cipher.encrypt(pt)
            assert cipher.decrypt(ct, b"\xaa" * pt_len) == pt
            assert cipher.decrypt(ct, None) == pt

    def test_exp_pt_len(self):
        cipher = PKCS.new(self.key1024)
        pt = b"5" * 16
        ct = cipher.encrypt(pt)
        sentinel = b"\xaa" * 16

        assert cipher.decrypt(ct, sentinel, 16) == pt
        assert cipher.decrypt(ct, sentinel, 15) == sentinel
        assert cipher.decrypt(ct, sentinel, 17) == sentinel


def _load_tests(filename):
    def filter_rsa(group):
        return RSA.import_key(group["privateKeyPem"])

    result = load_test_vectors_wycheproof(
        ("Cipher", "wycheproof"),
        filename,
        "Wycheproof PKCS#1v1.5 (%s)" % filename,
        group_tag={"rsa_key": filter_rsa},
    )
    return result


def load_wycheproof_vectors():
    vectors = []
    vectors += _load_tests("rsa_pkcs1_2048_test.json")
    vectors += mark_slow(_load_tests("rsa_pkcs1_3072_test.json"))
    vectors += mark_slow(_load_tests("rsa_pkcs1_4096_test.json"))
    return vectors


class TestVectorsWycheproof:
    _id = "None"

    def warn(self, tv):
        if tv.warning and wycheproof_warnings():
            import warnings

            warnings.warn("Wycheproof warning: %s (%s)" % (self._id, tv.comment))

    def check_decrypt(self, tv):
        self._id = "Wycheproof Decrypt PKCS#1v1.5 Test #%s" % tv.id
        cipher = PKCS.new(tv.rsa_key)

        # The padding check, with a sentinel
        sentinel = b"\xaa" * max(3, len(tv.msg))
        try:
            pt = cipher.decrypt(tv.ct, sentinel=sentinel)
        except ValueError:
            assert not tv.valid
            with pytest.raises(ValueError):
                cipher.decrypt(tv.ct)
            return

        if pt == sentinel:
            assert not tv.valid
        else:
            assert tv.valid
            assert pt == tv.msg
            self.warn(tv)

        # Implicit rejection
        pt = cipher.decrypt(tv.ct)
        if tv.valid:
            assert pt == tv.msg
        else:
            assert pt == cipher.decrypt(tv.ct)
            assert len(pt) <= tv.rsa_key.size_in_bytes() - 11

    @pytest.mark.parametrize("tv", load_wycheproof_vectors(), ids=wycheproof_id)
    def test(self, tv):
        self.check_decrypt(tv)
