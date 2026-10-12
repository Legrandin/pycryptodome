#
#  SelfTest/IO/test_PBES.py: Self-test for the _PBES module
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-tests for Crypto.IO._PBES module"""

import pytest

from Crypto.IO._PBES import (
    _DEFAULT_LIMIT,
    _DEFAULT_MAX_MEMORY,
    _DEFAULT_MAX_PBKDF1,
    _DEFAULT_MAX_PBKDF2,
    _DEFAULT_MAX_SCRYPT_COST,
    _ITERATION_COUNT_ERROR,
    _MEMORY_ERROR,
    _OID_PBE_WITH_SHA1_AND_DES_CBC,
    _PBKDF1_COUNT,
    _PBKDF2_COUNT,
    _SCRYPT_COST,
    PBES1,
    PBES2,
    PbesError,
    PbesIterationCountError,
    PbesMemoryError,
    _check_scrypt_cost,
    _scrypt_threads,
)
from Crypto.Util.asn1 import DerInteger, DerObjectId, DerOctetString, DerSequence

_OID_SHA1 = "1.3.14.3.2.26"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA3_256 = "2.16.840.1.101.3.4.2.8"


class TestPBES2:
    def setup_method(self):
        self.ref = b"Test data"
        self.passphrase = b"Passphrase"

    def test1(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test2(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA224AndAES128-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test3(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA256AndAES192-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test4(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA384AndAES256-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test5(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA512AndAES128-GCM")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test6(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA512-224AndAES192-GCM")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test7(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA3-256AndAES256-GCM")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test8(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "scryptAndAES128-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test9(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "scryptAndAES192-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test10(self):
        ct = PBES2.encrypt(self.ref, self.passphrase, "scryptAndAES256-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt


class TestPBES2_IterationLimit:
    """Tests for the max_iteration_count guard in PBES2.decrypt."""

    def setup_method(self):
        self.ref = b"Test data"
        self.passphrase = b"Passphrase"

    def _make_pbkdf2_blob(self, iteration_count, hash_name="SHA1"):
        """Build a valid PBES2/PBKDF2 encrypted blob with the given
        iteration count by encrypting normally and then patching the
        DER-encoded iteration count field in place."""

        # Encrypt with a low count so it's fast
        ct = PBES2.encrypt(
            self.ref,
            self.passphrase,
            "PBKDF2WithHMAC-%sAndDES-EDE3-CBC" % hash_name,
            prot_params={"iteration_count": 1000},
        )

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

    def _make_scrypt_blob(self, cost_param, r=8, p=1):
        """Build a valid PBES2/scrypt encrypted blob with the given
        scrypt cost parameter (N), r and p by encrypting normally then patching."""

        ct = PBES2.encrypt(
            self.ref, self.passphrase, "scryptAndAES128-CBC", prot_params={"iteration_count": 16384}
        )

        outer = DerSequence().decode(ct, nr_elements=2)
        enc_algo = DerSequence().decode(outer[0])
        pbes2_params = DerSequence().decode(enc_algo[1], nr_elements=2)
        kdf_info = DerSequence().decode(pbes2_params[0], nr_elements=2)
        scrypt_params = DerSequence().decode(kdf_info[1], nr_elements=(4, 5))

        # Patch the cost parameter, r and p (indices 1, 2, 3)
        scrypt_params[1] = cost_param
        scrypt_params[2] = r
        scrypt_params[3] = p

        kdf_info[1] = scrypt_params.encode()
        pbes2_params[0] = kdf_info.encode()
        enc_algo[1] = pbes2_params.encode()
        outer[0] = enc_algo.encode()
        return outer.encode()

    def test_pbkdf2_default_limit_rejects_high_count(self):
        """PBES2.decrypt rejects PBKDF2 iteration count above the default
        limit (for HMAC-SHA1) without burning CPU."""
        blob = self._make_pbkdf2_blob(2**31 - 1)
        with pytest.raises(PbesError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        assert str(ctx.value) == _ITERATION_COUNT_ERROR.format(
            what=_PBKDF2_COUNT, count=2**31 - 1, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_PBKDF2[_OID_SHA1])
        )

    def test_pbkdf2_custom_limit(self):
        """PBES2.decrypt honours a caller-supplied max_iteration_count."""
        blob = self._make_pbkdf2_blob(5000)
        with pytest.raises(PbesError):
            PBES2.decrypt(blob, self.passphrase, max_iteration_count=4999)

    def test_pbkdf2_limit_disabled_with_zero(self):
        """Setting max_iteration_count=0 disables the check.
        We use a very low iteration count so this stays fast."""
        # Encrypt with count=1000, then decrypt with check disabled.
        ct = PBES2.encrypt(
            self.ref,
            self.passphrase,
            "PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
            prot_params={"iteration_count": 1000},
        )
        pt = PBES2.decrypt(ct, self.passphrase, max_iteration_count=0)
        assert self.ref == pt

    def test_scrypt_default_limit_rejects_high_count(self):
        """PBES2.decrypt rejects scrypt cost parameter above the default
        limit without burning CPU."""
        blob = self._make_scrypt_blob(2**31 - 1)
        with pytest.raises(PbesError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        assert str(ctx.value) == _ITERATION_COUNT_ERROR.format(
            what=_SCRYPT_COST, count=2**31 - 1, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_SCRYPT_COST)
        )

    def test_scrypt_custom_limit(self):
        """PBES2.decrypt honours a caller-supplied max_iteration_count
        for scrypt."""
        blob = self._make_scrypt_blob(100000)
        with pytest.raises(PbesError):
            PBES2.decrypt(blob, self.passphrase, max_iteration_count=99999)

    def test_normal_decrypt_within_limit(self):
        """Normal encrypt→decrypt round-trip still works with the default
        limit in place (default PBKDF2 count is 1000)."""
        ct = PBES2.encrypt(self.ref, self.passphrase, "PBKDF2WithHMAC-SHA256AndAES256-CBC")
        pt = PBES2.decrypt(ct, self.passphrase)
        assert self.ref == pt

    def test_at_boundary_is_allowed(self):
        """An iteration count exactly at the limit should be accepted."""
        ct = PBES2.encrypt(
            self.ref,
            self.passphrase,
            "PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC",
            prot_params={"iteration_count": 5000},
        )
        # max_iteration_count == iteration_count → should pass
        pt = PBES2.decrypt(ct, self.passphrase, max_iteration_count=5000)
        assert self.ref == pt

    def test_pbkdf2_default_limit_depends_on_hash(self):
        """The default limit is lower for the hashes without a C loop (SHA-3)."""
        count = _DEFAULT_MAX_PBKDF2[_OID_SHA3_256] + 1
        assert count <= _DEFAULT_MAX_PBKDF2[_OID_SHA256]

        with pytest.raises(PbesIterationCountError) as ctx:
            PBES2.decrypt(self._make_pbkdf2_blob(count, "SHA3-256"), self.passphrase)
        assert str(ctx.value) == _ITERATION_COUNT_ERROR.format(
            what=_PBKDF2_COUNT, count=count, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_PBKDF2[_OID_SHA3_256])
        )

        # The same count is fine with SHA-256
        ct = PBES2.encrypt(
            self.ref,
            self.passphrase,
            "PBKDF2WithHMAC-SHA256AndAES128-CBC",
            prot_params={"iteration_count": count},
        )
        assert PBES2.decrypt(ct, self.passphrase) == self.ref

    def test_scrypt_default_limit_rejects_high_r_p(self):
        """Large r or p are not hidden behind a small N."""
        blob = self._make_scrypt_blob(2**20, r=8, p=64)  # cost 2^26
        with pytest.raises(PbesIterationCountError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        assert str(ctx.value) == _ITERATION_COUNT_ERROR.format(
            what=_SCRYPT_COST, count=2**26, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_SCRYPT_COST)
        )

        # With an explicit limit, as well
        blob = self._make_scrypt_blob(1024, r=1000, p=1)  # cost 128000
        with pytest.raises(PbesIterationCountError):
            PBES2.decrypt(blob, self.passphrase, max_iteration_count=2**16)

    def test_scrypt_default_limit_memory(self):
        """By default, scrypt cannot use more than 256 MiB."""
        blob = self._make_scrypt_blob(2**19, r=8, p=1)  # 512 MiB
        with pytest.raises(PbesMemoryError) as ctx:
            PBES2.decrypt(blob, self.passphrase)
        assert str(ctx.value) == _MEMORY_ERROR.format(
            memory=2**29, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_MEMORY)
        )

        # An explicit limit
        blob = self._make_scrypt_blob(2**10, r=8, p=1)  # 1 MiB
        with pytest.raises(PbesMemoryError) as ctx:
            PBES2.decrypt(blob, self.passphrase, max_memory=2**20 - 1)
        assert str(ctx.value) == _MEMORY_ERROR.format(memory=2**20, limit=2**20 - 1)

    def test_scrypt_threads_within_memory(self):
        """Fewer threads are used, so that the memory stays within max_memory
        (checked without running scrypt)."""
        from Crypto.Util._cpu_features import available_cores

        # 128 MiB for each thread: 2 fit in the default 256 MiB
        assert _scrypt_threads(2**17, 8, 4, 4, None) == 2
        assert _scrypt_threads(2**18, 8, 4, 4, None) == 1
        assert _scrypt_threads(2**17, 8, 4, 4, 2**29) == 4
        # No more than p, and 0 means all the cores
        assert _scrypt_threads(2**17, 8, 2, 4, 0) == 2
        assert _scrypt_threads(2**10, 8, 64, 0, None) == min(available_cores(), 64)
        # Not even one thread fits
        with pytest.raises(PbesMemoryError):
            _scrypt_threads(2**19, 8, 1, 1, None)
        assert _scrypt_threads(2**19, 8, 1, 1, 2**29) == 1
        assert _scrypt_threads(2**19, 8, 1, 1, 0) == 1

    def test_scrypt_check_accepts(self):
        """Parameters within the limits (checked without running scrypt)."""
        # The default, also with a large p and a small N
        _check_scrypt_cost(2**20, 8, 1, None)
        _check_scrypt_cost(2**14, 8, 2**10, None)
        # The limit is about the cost only (max_memory is about the memory)
        _check_scrypt_cost(2**21, 8, 1, 2**21)
        # The cost is N for r=8 and p=1, as for the previous versions
        _check_scrypt_cost(2**16, 8, 1, 2**16)
        with pytest.raises(PbesIterationCountError):
            _check_scrypt_cost(2**16, 8, 1, 2**16 - 1)
        # 0 disables all checks
        _check_scrypt_cost(2**40, 2**10, 2**10, 0)


class TestPBES1_IterationLimit:
    def test_pbkdf1_default_limit(self):
        """PBES1.decrypt rejects a PBKDF1 iteration count above the default limit."""
        count = _DEFAULT_MAX_PBKDF1 + 1
        blob = DerSequence(
            [
                DerSequence(
                    [
                        DerObjectId(_OID_PBE_WITH_SHA1_AND_DES_CBC),
                        DerSequence([DerOctetString(b"\x00" * 8), DerInteger(count)]),
                    ]
                ),
                DerOctetString(b"\x00" * 16),
            ]
        ).encode()
        with pytest.raises(PbesIterationCountError) as ctx:
            PBES1.decrypt(blob, b"passphrase")
        assert str(ctx.value) == _ITERATION_COUNT_ERROR.format(
            what=_PBKDF1_COUNT, count=count, limit=_DEFAULT_LIMIT.format(_DEFAULT_MAX_PBKDF1)
        )
