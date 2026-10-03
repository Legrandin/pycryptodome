#
#  SelfTest/IO/test_PBES.py: Self-test for the _PBES module
#
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

"""Self-tests for Crypto.IO._PBES module"""

import unittest

from Crypto.IO._PBES import PBES2, PbesError, _DEFAULT_MAX_ITERATION_COUNT
from Crypto.Util.asn1 import (DerSequence, DerOctetString,
                               DerObjectId, DerInteger)


class TestPBES2(unittest.TestCase):

    def setUp(self):
        self.ref = b"Test data"
        self.passphrase = b"Passphrase"

    def test1(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test2(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA224AndAES128-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test3(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA256AndAES192-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test4(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA384AndAES256-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test5(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA512AndAES128-GCM')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test6(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA512-224AndAES192-GCM')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test7(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA3-256AndAES256-GCM')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test8(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES128-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test9(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES192-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test10(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES256-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)


class TestPBES2_IterationLimit(unittest.TestCase):
    """Tests for the max_iteration_count guard in PBES2.decrypt."""

    def setUp(self):
        self.ref = b"Test data"
        self.passphrase = b"Passphrase"

    def _make_pbkdf2_blob(self, iteration_count):
        """Build a valid PBES2/PBKDF2 encrypted blob with the given
        iteration count by encrypting normally and then patching the
        DER-encoded iteration count field in place."""

        # Encrypt with a low count so it's fast
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                           prot_params={'iteration_count': 1000})

        # Decode the outer structure, replace the iteration count, re-encode.
        # The blob is:
        #   SEQUENCE {
        #     SEQUENCE {                          # encryptionAlgorithm
        #       OID 1.2.840.113549.1.5.13         # PBES2
        #       SEQUENCE {                         # PBES2-params
        #         SEQUENCE {                       # kdf
        #           OID 1.2.840.113549.1.5.12      # PBKDF2
        #           SEQUENCE { salt, iterCount }   # PBKDF2-params
        #         }
        #         SEQUENCE { ... }                 # enc
        #       }
        #     }
        #     OCTET STRING                         # encrypted data
        #   }
        outer = DerSequence().decode(ct, nr_elements=2)
        enc_algo = DerSequence().decode(outer[0])
        pbes2_params = DerSequence().decode(enc_algo[1], nr_elements=2)
        kdf_info = DerSequence().decode(pbes2_params[0], nr_elements=2)
        pbkdf2_params = DerSequence().decode(kdf_info[1], nr_elements=(2, 3, 4))

        # Patch the iteration count (index 1)
        pbkdf2_params[1] = iteration_count

        # Re-encode all the way back up
        kdf_info[1] = pbkdf2_params.encode()
        pbes2_params[0] = kdf_info.encode()
        enc_algo[1] = pbes2_params.encode()
        outer[0] = enc_algo.encode()
        return outer.encode()

    def _make_scrypt_blob(self, cost_param):
        """Build a valid PBES2/scrypt encrypted blob with the given
        scrypt cost parameter (N) by encrypting normally then patching."""

        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES128-CBC',
                           prot_params={'iteration_count': 16384})

        outer = DerSequence().decode(ct, nr_elements=2)
        enc_algo = DerSequence().decode(outer[0])
        pbes2_params = DerSequence().decode(enc_algo[1], nr_elements=2)
        kdf_info = DerSequence().decode(pbes2_params[0], nr_elements=2)
        scrypt_params = DerSequence().decode(kdf_info[1], nr_elements=(4, 5))

        # Patch the cost parameter (index 1)
        scrypt_params[1] = cost_param

        kdf_info[1] = scrypt_params.encode()
        pbes2_params[0] = kdf_info.encode()
        enc_algo[1] = pbes2_params.encode()
        outer[0] = enc_algo.encode()
        return outer.encode()

    def test_pbkdf2_default_limit_rejects_high_count(self):
        """PBES2.decrypt rejects PBKDF2 iteration count above the default
        limit (50M) without burning CPU."""
        blob = self._make_pbkdf2_blob(2**31 - 1)
        with self.assertRaises(PbesError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        self.assertIn("too high", str(ctx.exception))

    def test_pbkdf2_custom_limit(self):
        """PBES2.decrypt honours a caller-supplied max_iteration_count."""
        blob = self._make_pbkdf2_blob(5000)
        with self.assertRaises(PbesError):
            PBES2.decrypt(blob, self.passphrase, max_iteration_count=4999)

    def test_pbkdf2_limit_disabled_with_zero(self):
        """Setting max_iteration_count=0 disables the check.
        We use a very low iteration count so this stays fast."""
        # Encrypt with count=1000, then decrypt with check disabled.
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                           prot_params={'iteration_count': 1000})
        pt = PBES2.decrypt(ct, self.passphrase, max_iteration_count=0)
        self.assertEqual(self.ref, pt)

    def test_scrypt_default_limit_rejects_high_count(self):
        """PBES2.decrypt rejects scrypt cost parameter above the default
        limit without burning CPU."""
        blob = self._make_scrypt_blob(2**31 - 1)
        with self.assertRaises(PbesError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        self.assertIn("too high", str(ctx.exception))

    def test_scrypt_custom_limit(self):
        """PBES2.decrypt honours a caller-supplied max_iteration_count
        for scrypt."""
        blob = self._make_scrypt_blob(100000)
        with self.assertRaises(PbesError):
            PBES2.decrypt(blob, self.passphrase, max_iteration_count=99999)

    def test_normal_decrypt_within_limit(self):
        """Normal encrypt→decrypt round-trip still works with the default
        limit in place (default PBKDF2 count is 1000)."""
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA256AndAES256-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test_at_boundary_is_allowed(self):
        """An iteration count exactly at the limit should be accepted."""
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                           prot_params={'iteration_count': 5000})
        # max_iteration_count == iteration_count → should pass
        pt = PBES2.decrypt(ct, self.passphrase, max_iteration_count=5000)
        self.assertEqual(self.ref, pt)


def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    listTests = []
    listTests += list_test_cases(TestPBES2)
    listTests += list_test_cases(TestPBES2_IterationLimit)
    return listTests


if __name__ == '__main__':
    def suite():
        return unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
