# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

import os
import re
import unittest
from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import b, tobytes, bchr
from Crypto.Util.strxor import strxor_c
from Crypto.Util.number import long_to_bytes
from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Cipher import AES


class OcbRfc7253Test(unittest.TestCase):

    # Tuple with
    # - nonce
    # - authenticated data
    # - plaintext
    # - ciphertext and 16 byte MAC tag
    tv1_key = "000102030405060708090A0B0C0D0E0F"
    tv1 = (
            (
                "BBAA99887766554433221100",
                "",
                "",
                "785407BFFFC8AD9EDCC5520AC9111EE6"
            ),
            (
                "BBAA99887766554433221101",
                "0001020304050607",
                "0001020304050607",
                "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"
            ),
            (
                "BBAA99887766554433221102",
                "0001020304050607",
                "",
                "81017F8203F081277152FADE694A0A00"
            ),
            (
                "BBAA99887766554433221103",
                "",
                "0001020304050607",
                "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"
            ),
            (
                "BBAA99887766554433221104",
                "000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B0C0D0E0F",
                "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5"
                "701C1CCEC8FC3358"
            ),
            (
                "BBAA99887766554433221105",
                "000102030405060708090A0B0C0D0E0F",
                "",
                "8CF761B6902EF764462AD86498CA6B97"
            ),
            (
                "BBAA99887766554433221106",
                "",
                "000102030405060708090A0B0C0D0E0F",
                "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436B"
                "DF06D8FA1ECA343D"
            ),
            (
                "BBAA99887766554433221107",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "1CA2207308C87C010756104D8840CE1952F09673A448A122"
                "C92C62241051F57356D7F3C90BB0E07F"
            ),
            (
                "BBAA99887766554433221108",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "",
                "6DC225A071FC1B9F7C69F93B0F1E10DE"
            ),
            (
                "BBAA99887766554433221109",
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3C"
                "E725F32494B9F914D85C0B1EB38357FF"
            ),
            (
                "BBAA9988776655443322110A",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F",
                "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DE"
                "AFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240"
            ),
            (
                "BBAA9988776655443322110B",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F",
                "",
                "FE80690BEE8A485D11F32965BC9D2A32"
            ),
            (
                "BBAA9988776655443322110C",
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F",
                "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF4"
                "6040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF"
            ),
            (
                "BBAA9988776655443322110D",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F2021222324252627",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F2021222324252627",
                "D5CA91748410C1751FF8A2F618255B68A0A12E093FF45460"
                "6E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483"
                "A7035490C5769E60"
            ),
            (
                "BBAA9988776655443322110E",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F2021222324252627",
                "",
                "C5CD9D1850C141E358649994EE701B68"
            ),
            (
                "BBAA9988776655443322110F",
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617"
                "18191A1B1C1D1E1F2021222324252627",
                "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15"
                "A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95"
                "A98CA5F3000B1479"
            )
        )

    # Tuple with
    # - key
    # - nonce
    # - authenticated data
    # - plaintext
    # - ciphertext and 12 byte MAC tag
    tv2 = (
        "0F0E0D0C0B0A09080706050403020100",
        "BBAA9988776655443322110D",
        "000102030405060708090A0B0C0D0E0F1011121314151617"
        "18191A1B1C1D1E1F2021222324252627",
        "000102030405060708090A0B0C0D0E0F1011121314151617"
        "18191A1B1C1D1E1F2021222324252627",
        "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1"
        "A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FD"
        "AC4F02AA"
        )

    # Tuple with
    # - key length
    # - MAC tag length
    # - Expected output
    tv3 = (
        (128, 128, "67E944D23256C5E0B6C61FA22FDF1EA2"),
        (192, 128, "F673F2C3E7174AAE7BAE986CA9F29E17"),
        (256, 128, "D90EB8E9C977C88B79DD793D7FFA161C"),
        (128, 96,  "77A3D8E73589158D25D01209"),
        (192, 96,  "05D56EAD2752C86BE6932C5E"),
        (256, 96,  "5458359AC23B0CBA9E6330DD"),
        (128, 64,  "192C9B7BD90BA06A"),
        (192, 64,  "0066BC6E0EF34E24"),
        (256, 64,  "7D4EA5D445501CBE"),
    )

    def test1(self):
        key = unhexlify(self.tv1_key)
        for tv in self.tv1:
            nonce, aad, pt, ct = [ unhexlify(x) for x in tv ]
            ct, mac_tag = ct[:-16], ct[-16:]

            cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
            cipher.update(aad)
            ct2 = cipher.encrypt(pt) + cipher.encrypt()
            self.assertEquals(ct, ct2)
            self.assertEquals(mac_tag, cipher.digest())

            cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
            cipher.update(aad)
            pt2 = cipher.decrypt(ct) + cipher.decrypt()
            self.assertEquals(pt, pt2)
            self.assertEquals(mac_tag, cipher.digest())

    def test2(self):

        key, nonce, aad, pt, ct = [ unhexlify(x) for x in self.tv2 ]
        ct, mac_tag = ct[:-12], ct[-12:]

        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=12)
        cipher.update(aad)
        ct2 = cipher.encrypt(pt) + cipher.encrypt()
        self.assertEquals(ct, ct2)
        self.assertEquals(mac_tag, cipher.digest())

        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=12)
        cipher.update(aad)
        pt2 = cipher.decrypt(ct) + cipher.decrypt()
        self.assertEquals(pt, pt2)
        self.assertEquals(mac_tag, cipher.digest())

    def test3(self):

        for keylen, taglen, result in self.tv3:

            key = bchr(0) * (keylen // 8 - 1) + bchr(taglen)
            C = b("")

            for i in xrange(128):
                S = bchr(0) * i

                N = long_to_bytes(3 * i + 1, 12)
                cipher = AES.new(key, AES.MODE_OCB, nonce=N, mac_len=taglen // 8)
                cipher.update(S)
                C += cipher.encrypt(S) + cipher.encrypt() + cipher.digest()

                N = long_to_bytes(3 * i + 2, 12)
                cipher = AES.new(key, AES.MODE_OCB, nonce=N, mac_len=taglen // 8)
                C += cipher.encrypt(S) + cipher.encrypt() + cipher.digest()

                N = long_to_bytes(3 * i + 3, 12)
                cipher = AES.new(key, AES.MODE_OCB, nonce=N, mac_len=taglen // 8)
                cipher.update(S)
                C += cipher.encrypt() + cipher.digest()

            N = long_to_bytes(385, 12)
            cipher = AES.new(key, AES.MODE_OCB, nonce=N, mac_len=taglen // 8)
            cipher.update(C)
            result2 = cipher.encrypt() + cipher.digest()
            self.assertEquals(unhexlify(result), result2)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(OcbRfc7253Test)
    return tests


if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
