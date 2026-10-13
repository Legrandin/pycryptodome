#
#  PublicKey/_PBES.py : Password-Based Encryption functions
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Callable, Optional, TypedDict

from Crypto import (
    _INCORRECT_PASSPHRASE,
    Hash,
    IncorrectPassphraseError,
    KdfIterationLimitError,
    KdfMemoryLimitError,
    Random,
)
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1, PBKDF2, scrypt
from Crypto.Util._threads import threads_param
from Crypto.Util.asn1 import (
    DerInteger,
    DerObjectId,
    DerOctetString,
    DerSequence,
)
from Crypto.Util.Padding import pad, unpad

if TYPE_CHECKING:
    from types import ModuleType


class ProtParams(TypedDict, total=False):
    iteration_count: int
    salt_size: int
    block_size: int
    parallelization: int


_OID_PBE_WITH_MD5_AND_DES_CBC = "1.2.840.113549.1.5.3"
_OID_PBE_WITH_MD5_AND_RC2_CBC = "1.2.840.113549.1.5.6"
_OID_PBE_WITH_SHA1_AND_DES_CBC = "1.2.840.113549.1.5.10"
_OID_PBE_WITH_SHA1_AND_RC2_CBC = "1.2.840.113549.1.5.11"

_OID_PBES2 = "1.2.840.113549.1.5.13"

_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_SCRYPT = "1.3.6.1.4.1.11591.4.11"

_OID_HMAC_SHA1 = "1.2.840.113549.2.7"

_OID_DES_EDE3_CBC = "1.2.840.113549.3.7"
_OID_AES128_CBC = "2.16.840.1.101.3.4.1.2"
_OID_AES192_CBC = "2.16.840.1.101.3.4.1.22"
_OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"
_OID_AES128_GCM = "2.16.840.1.101.3.4.1.6"
_OID_AES192_GCM = "2.16.840.1.101.3.4.1.26"
_OID_AES256_GCM = "2.16.840.1.101.3.4.1.46"

# Default parameters for encryption, when ``prot_params`` does not specify them,
# from the OWASP Password Storage Cheat Sheet (as revised in March 2026)

#: Iteration count of PBKDF2 (the OWASP value for HMAC-SHA256, used for all hashes;
#: OWASP gives 220 000 for HMAC-SHA512, and 1 400 000 for HMAC-SHA1, legacy only)
_DEFAULT_PBKDF2_COUNT = 600_000

#: Cost N of scrypt, with r = 8 and p = 1 (128 MiB of memory)
_DEFAULT_SCRYPT_N = 2**17

# Default limits for decryption (when max_iteration_count is None), against
# crafted blobs that would tie up the CPU or the memory. With each of them,
# the key derivation takes at most about one minute on a recent x86-64 laptop,
# for the worst key length (32 bytes) and without SHA-NI.

#: Maximum iteration count of PBKDF1 (PBES1) and PBKDF2 (PBES2), whatever the hash.
#: The slowest are PBKDF2 with SHA-1, SHA-224, SHA-512/224 and SHA3-224 and a
#: 32-byte key: their digest is shorter than the key, so PBKDF2 has to run twice.
_DEFAULT_MAX_ITERATION_COUNT = 50_000_000

#: Maximum scrypt cost N*r*p/8 (that is, N for r=8 and p=1)
_DEFAULT_MAX_SCRYPT_COST = 2**25

#: Besides the N*r*p work of its flows, scrypt does some work in proportion to
#: r*p only (the two PBKDF2 steps, over 128*r*p bytes), about as much as
#: 128*r*p of the former. In the cost, N counts as at least this value,
#: which accounts for that work within ~12%, and leaves the cost of any
#: real key (N >= 1024) unchanged.
_SCRYPT_MIN_N_COST = 1024

#: Maximum number of rounds of bcrypt_pbkdf, for OpenSSH private keys
#: (each round is two bcrypt hashes with cost 6)
_DEFAULT_MAX_BCRYPT_ROUNDS = 16_384

#: Maximum memory for the key derivation (when max_memory is None): 256 MiB,
#: for all threads together. Only scrypt needs a significant amount
#: (128*N*r bytes for each thread).
_DEFAULT_MAX_MEMORY = 256 * 2**20


class PbesError(ValueError):
    pass


#: Message of :class:`KdfIterationLimitError`
_ITERATION_COUNT_ERROR = (
    "The encrypted key has a {what} of {count}, above the maximum allowed by "
    "max_iteration_count: {limit}. If you trust the key, increase "
    "max_iteration_count (or set it to 0 to disable the check)."
)
#: The ``limit`` in the message, when the caller did not set ``max_iteration_count``
_DEFAULT_LIMIT = "{} (the default)"

#: The ``what`` in the message, for each KDF
_PBKDF1_COUNT = "PBKDF1 iteration count"
_PBKDF2_COUNT = "PBKDF2 iteration count"
_SCRYPT_COST = "scrypt cost N*r*p/8"
_BCRYPT_ROUNDS = "bcrypt_pbkdf rounds count"

#: Message of :class:`KdfMemoryLimitError`
_MEMORY_ERROR = (
    "The encrypted key needs {memory} bytes of memory for scrypt, above the maximum "
    "allowed by max_memory: {limit}. If you trust the key, increase max_memory "
    "(or set it to 0 to disable the check)."
)


def _check_iteration_count(what: str, count: int, max_iteration_count: Optional[int], default: int) -> None:
    """Raise :class:`KdfIterationLimitError` if ``count`` (``what``, like
    :data:`_PBKDF2_COUNT`) is above ``max_iteration_count``
    (``None`` for the ``default`` limit, ``0`` for no limit)."""

    if max_iteration_count is None:
        limit = _DEFAULT_LIMIT.format(default)
        max_iteration_count = default
    else:
        limit = str(max_iteration_count)

    if max_iteration_count and count > max_iteration_count:
        raise KdfIterationLimitError(_ITERATION_COUNT_ERROR.format(what=what, count=count, limit=limit))


def _check_scrypt_params(N: int, r: int, p: int) -> None:
    """Raise :class:`PbesError` if the parameters are not valid for scrypt
    (RFC 7914): N a power of 2 larger than 1, r and p positive."""

    if N < 2 or (N & (N - 1)) or r < 1 or p < 1:
        raise PbesError("Invalid scrypt parameters")


def _check_scrypt_cost(N: int, r: int, p: int, max_iteration_count: Optional[int]) -> None:
    """Raise :class:`KdfIterationLimitError` if the cost N*r*p/8 of scrypt
    (with N at least :data:`_SCRYPT_MIN_N_COST`) is above ``max_iteration_count``
    (``None`` for the default limit)."""

    cost = (max(N, _SCRYPT_MIN_N_COST) * r * p + 7) // 8
    _check_iteration_count(_SCRYPT_COST, cost, max_iteration_count, _DEFAULT_MAX_SCRYPT_COST)


def _scrypt_threads(N: int, r: int, p: int, threads: int, max_memory: Optional[int]) -> int:
    """Return how many threads scrypt can use (at most ``threads``, with 0 for
    all CPU cores, and at most ``p``), so that its memory stays within
    ``max_memory`` (``None`` for the default limit, ``0`` for no limit).

    Raise :class:`KdfMemoryLimitError` if even one thread needs too much memory.
    """

    if max_memory is None:
        max_memory = _DEFAULT_MAX_MEMORY
        limit = _DEFAULT_LIMIT.format(max_memory)
    else:
        limit = str(max_memory)

    threads = min(threads_param(threads), p)
    shared = 2 * 128 * r * p  # The input and the output of all flows
    each = 128 * (N + 2) * r  # The memory of ROMix, for each thread
    if max_memory:
        if shared + each > max_memory:
            raise KdfMemoryLimitError(_MEMORY_ERROR.format(memory=shared + each, limit=limit))
        threads = min(threads, (max_memory - shared) // each)
    return max(threads, 1)


# These are the ASN.1 definitions used by the PBES1/2 logic:
#
# EncryptedPrivateKeyInfo ::= SEQUENCE {
#   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
#   encryptedData        EncryptedData
# }
#
# EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
#
# EncryptedData ::= OCTET STRING
#
# AlgorithmIdentifier  ::=  SEQUENCE  {
#       algorithm   OBJECT IDENTIFIER,
#       parameters  ANY DEFINED BY algorithm OPTIONAL
# }
#
# PBEParameter ::= SEQUENCE {
#       salt OCTET STRING (SIZE(8)),
#       iterationCount INTEGER
# }
#
# PBES2-params ::= SEQUENCE {
#       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
#       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
# }
#
# PBKDF2-params ::= SEQUENCE {
#   salt CHOICE {
#       specified OCTET STRING,
#       otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
#       },
#   iterationCount INTEGER (1..MAX),
#   keyLength INTEGER (1..MAX) OPTIONAL,
#   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
#   }
#
#   PBKDF2-PRFs ALGORITHM-IDENTIFIER ::= {
#        {NULL IDENTIFIED BY id-hmacWithSHA1},
#        {NULL IDENTIFIED BY id-hmacWithSHA224},
#        {NULL IDENTIFIED BY id-hmacWithSHA256},
#        {NULL IDENTIFIED BY id-hmacWithSHA384},
#        {NULL IDENTIFIED BY id-hmacWithSHA512},
#        {NULL IDENTIFIED BY id-hmacWithSHA512-224},
#        {NULL IDENTIFIED BY id-hmacWithSHA512-256},
#        ...
# }
# scrypt-params ::= SEQUENCE {
#       salt OCTET STRING,
#       costParameter INTEGER (1..MAX),
#       blockSize INTEGER (1..MAX),
#       parallelizationParameter INTEGER (1..MAX),
#       keyLength INTEGER (1..MAX) OPTIONAL
#   }


class PBES1:
    """Deprecated encryption scheme with password-based key derivation
    (originally defined in PKCS#5 v1.5, but still present in `v2.1`__).

    .. __: https://www.rfc-editor.org/rfc/rfc8018
    """

    @staticmethod
    def decrypt(data: bytes, passphrase: bytes, max_iteration_count: Optional[int] = None) -> bytes:
        """Decrypt a piece of data using a passphrase and *PBES1*.

        The algorithm to use is automatically detected.

        :Parameters:
          data : byte string
            The piece of data to decrypt.
          passphrase : byte string
            The passphrase to use for decrypting the data.
          max_iteration_count : integer
            The maximum value allowed for the PBKDF1 iteration count.
            An attacker could craft a malicious key blob that requires an
            extremely high number of iterations, tying up the CPU for hours.
            The default value is None (enforcing the limit
            :data:`_DEFAULT_MAX_ITERATION_COUNT`).
            Set it to ``0`` to disable the check.
        :Returns:
          The decrypted data, as a binary string.
        """

        enc_private_key_info = DerSequence().decode(data)
        encrypted_algorithm = DerSequence().decode(enc_private_key_info[0])
        encrypted_data = DerOctetString().decode(enc_private_key_info[1]).payload

        pbe_oid = DerObjectId().decode(encrypted_algorithm[0]).value
        cipher_params = {}
        hashmod: ModuleType
        module: ModuleType
        if pbe_oid == _OID_PBE_WITH_MD5_AND_DES_CBC:
            # PBE_MD5_DES_CBC
            from Crypto.Cipher import DES
            from Crypto.Hash import MD5

            hashmod = MD5
            module = DES
        elif pbe_oid == _OID_PBE_WITH_MD5_AND_RC2_CBC:
            # PBE_MD5_RC2_CBC
            from Crypto.Cipher import ARC2
            from Crypto.Hash import MD5

            hashmod = MD5
            module = ARC2
            cipher_params["effective_keylen"] = 64
        elif pbe_oid == _OID_PBE_WITH_SHA1_AND_DES_CBC:
            # PBE_SHA1_DES_CBC
            from Crypto.Cipher import DES
            from Crypto.Hash import SHA1

            hashmod = SHA1
            module = DES
        elif pbe_oid == _OID_PBE_WITH_SHA1_AND_RC2_CBC:
            # PBE_SHA1_RC2_CBC
            from Crypto.Cipher import ARC2
            from Crypto.Hash import SHA1

            hashmod = SHA1
            module = ARC2
            cipher_params["effective_keylen"] = 64
        else:
            raise PbesError("Unknown OID for PBES1")

        pbe_params = DerSequence().decode(encrypted_algorithm[1], nr_elements=2)
        salt = DerOctetString().decode(pbe_params[0]).payload
        iterations = pbe_params[1]

        if iterations < 1:
            raise PbesError("Invalid PBKDF1 iteration count")
        _check_iteration_count(_PBKDF1_COUNT, iterations, max_iteration_count, _DEFAULT_MAX_ITERATION_COUNT)

        key_iv = PBKDF1(passphrase, salt, 16, iterations, hashmod)
        key, iv = key_iv[:8], key_iv[8:]

        cipher = module.new(key, module.MODE_CBC, iv, **cipher_params)
        try:
            return unpad(cipher.decrypt(encrypted_data), cipher.block_size)
        except ValueError:
            raise IncorrectPassphraseError(_INCORRECT_PASSPHRASE) from None


class PBES2:
    """Encryption scheme with password-based key derivation
    (defined in `PKCS#5 v2.1`__).

    .. __: https://www.rfc-editor.org/rfc/rfc8018
    """

    @staticmethod
    def encrypt(
        data: bytes,
        passphrase: bytes,
        protection: str,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[Callable[[int], bytes]] = None,
        threads: int = 1,
    ) -> bytes:
        """Encrypt a piece of data using a passphrase and *PBES2*.

        :Parameters:
          data : byte string
            The piece of data to encrypt.
          passphrase : byte string
            The passphrase to use for encrypting the data.
          protection : string
            The identifier of the encryption algorithm to use.
          prot_params : dictionary
            Parameters of the protection algorithm.

            +------------------+-----------------------------------------------+
            | Key              | Description                                   |
            +==================+===============================================+
            | iteration_count  | The KDF algorithm is repeated several times to|
            |                  | slow down brute force attacks on passwords    |
            |                  | (called *N* or CPU/memory cost in scrypt).    |
            |                  |                                               |
            |                  | The default value for PBKDF2 is 600 000.      |
            |                  | The default value for scrypt is 131 072.      |
            +------------------+-----------------------------------------------+
            | salt_size        | Salt is used to thwart dictionary and rainbow |
            |                  | attacks on passwords. The default value is 8  |
            |                  | bytes.                                        |
            +------------------+-----------------------------------------------+
            | block_size       | *(scrypt only)* Memory-cost (r). The default  |
            |                  | value is 8.                                   |
            +------------------+-----------------------------------------------+
            | parallelization  | *(scrypt only)* CPU-cost (p). The default     |
            |                  | value is 1.                                   |
            +------------------+-----------------------------------------------+


          randfunc : callable
            Random number generation function; it should accept
            a single integer N and return a string of random data,
            N bytes long. If not specified, a new RNG will be
            instantiated from ``Crypto.Random``.
          threads : integer
            The maximum number of threads used by scrypt
            (see :func:`Crypto.Protocol.KDF.scrypt`).

        :Returns:
          The encrypted data, as a binary string.
        """

        if prot_params is None:
            prot_params = {}

        if randfunc is None:
            randfunc = Random.get_random_bytes

        pattern = re.compile(r"^(PBKDF2WithHMAC-([0-9A-Z-]+)|scrypt)And([0-9A-Z-]+)$")
        res = pattern.match(protection)
        if res is None:
            raise ValueError("Unknown protection %s" % protection)

        if protection.startswith("PBKDF"):
            pbkdf = "pbkdf2"
            pbkdf2_hmac_algo = res.group(2)
            enc_algo = res.group(3)
        else:
            pbkdf = "scrypt"
            enc_algo = res.group(3)

        aead = False
        module: ModuleType
        if enc_algo == "DES-EDE3-CBC":
            from Crypto.Cipher import DES3

            key_size = 24
            module = DES3
            cipher_mode = DES3.MODE_CBC
            enc_oid = _OID_DES_EDE3_CBC
            enc_param = {"iv": randfunc(8)}
        elif enc_algo == "AES128-CBC":
            key_size = 16
            module = AES
            cipher_mode = AES.MODE_CBC
            enc_oid = _OID_AES128_CBC
            enc_param = {"iv": randfunc(16)}
        elif enc_algo == "AES192-CBC":
            key_size = 24
            module = AES
            cipher_mode = AES.MODE_CBC
            enc_oid = _OID_AES192_CBC
            enc_param = {"iv": randfunc(16)}
        elif enc_algo == "AES256-CBC":
            key_size = 32
            module = AES
            cipher_mode = AES.MODE_CBC
            enc_oid = _OID_AES256_CBC
            enc_param = {"iv": randfunc(16)}
        elif enc_algo == "AES128-GCM":
            key_size = 16
            module = AES
            cipher_mode = AES.MODE_GCM
            enc_oid = _OID_AES128_GCM
            enc_param = {"nonce": randfunc(12)}
            aead = True
        elif enc_algo == "AES192-GCM":
            key_size = 24
            module = AES
            cipher_mode = AES.MODE_GCM
            enc_oid = _OID_AES192_GCM
            enc_param = {"nonce": randfunc(12)}
            aead = True
        elif enc_algo == "AES256-GCM":
            key_size = 32
            module = AES
            cipher_mode = AES.MODE_GCM
            enc_oid = _OID_AES256_GCM
            enc_param = {"nonce": randfunc(12)}
            aead = True
        else:
            raise ValueError("Unknown encryption mode '%s'" % enc_algo)

        iv_nonce = list(enc_param.values())[0]
        salt = randfunc(prot_params.get("salt_size", 8))

        # Derive key from password
        if pbkdf == "pbkdf2":
            count = prot_params.get("iteration_count", _DEFAULT_PBKDF2_COUNT)
            digestmod: Any = Hash.new(pbkdf2_hmac_algo)

            key = PBKDF2(passphrase, salt, key_size, count, hmac_hash_module=digestmod)

            pbkdf2_params = DerSequence([DerOctetString(salt), DerInteger(count)])

            if pbkdf2_hmac_algo != "SHA1":
                try:
                    hmac_oid = Hash.HMAC.new(b"", digestmod=digestmod).oid
                except KeyError:
                    raise ValueError("No OID for HMAC hash algorithm")
                pbkdf2_params.append(DerSequence([DerObjectId(hmac_oid)]))

            kdf_info = DerSequence(
                [
                    DerObjectId(_OID_PBKDF2),  # PBKDF2
                    pbkdf2_params,
                ]
            )

        elif pbkdf == "scrypt":
            count = prot_params.get("iteration_count", _DEFAULT_SCRYPT_N)
            scrypt_r = prot_params.get("block_size", 8)
            scrypt_p = prot_params.get("parallelization", 1)
            key = scrypt(passphrase, salt, key_size, count, scrypt_r, scrypt_p, threads=threads)
            kdf_info = DerSequence(
                [
                    DerObjectId(_OID_SCRYPT),  # scrypt
                    DerSequence(
                        [DerOctetString(salt), DerInteger(count), DerInteger(scrypt_r), DerInteger(scrypt_p)]
                    ),
                ]
            )

        else:
            raise ValueError("Unknown KDF " + res.group(1))

        # Create cipher and use it
        cipher = module.new(key, cipher_mode, **enc_param)
        if aead:
            ct, tag = cipher.encrypt_and_digest(data)
            encrypted_data = ct + tag
        else:
            encrypted_data = cipher.encrypt(pad(data, cipher.block_size))
        enc_info = DerSequence([DerObjectId(enc_oid), DerOctetString(iv_nonce)])

        # Result
        enc_private_key_info = DerSequence(
            [
                # encryptionAlgorithm
                DerSequence(
                    [
                        DerObjectId(_OID_PBES2),
                        DerSequence([kdf_info, enc_info]),
                    ]
                ),
                DerOctetString(encrypted_data),
            ]
        )
        return enc_private_key_info.encode()

    @staticmethod
    def decrypt(
        data: bytes,
        passphrase: bytes,
        max_iteration_count: Optional[int] = None,
        threads: int = 1,
        max_memory: Optional[int] = None,
    ) -> bytes:
        """Decrypt a piece of data using a passphrase and *PBES2*.

        The algorithm to use is automatically detected.

        :Parameters:
          data : byte string
            The piece of data to decrypt.
          passphrase : byte string
            The passphrase to use for decrypting the data.
          max_iteration_count : integer
            The maximum value allowed for the PBKDF2 iteration count
            or for the scrypt cost N*r*p/8.
            An attacker could craft a malicious key blob that requires an
            extremely high number of iterations, tying up the CPU for hours.
            The default value is None (enforcing the limits
            :data:`_DEFAULT_MAX_ITERATION_COUNT`, or
            :data:`_DEFAULT_MAX_SCRYPT_COST`).
            Set it to ``0`` to disable the check.
          threads : integer
            The maximum number of threads used by scrypt
            (see :func:`Crypto.Protocol.KDF.scrypt`).
          max_memory : integer
            The maximum memory (in bytes) for the key derivation, as a limit on the
            total of all threads together (scrypt needs 128*N*r bytes for each thread).
            Fewer threads are used if needed, down to one.
            The default value is None (enforcing the limit :data:`_DEFAULT_MAX_MEMORY`).
            Set it to ``0`` to disable the check.
        :Returns:
          The decrypted data, as a binary string.
        """

        enc_private_key_info = DerSequence().decode(data, nr_elements=2)
        enc_algo = DerSequence().decode(enc_private_key_info[0])
        encrypted_data = DerOctetString().decode(enc_private_key_info[1]).payload

        pbe_oid = DerObjectId().decode(enc_algo[0]).value
        if pbe_oid != _OID_PBES2:
            raise PbesError("Not a PBES2 object")

        pbes2_params = DerSequence().decode(enc_algo[1], nr_elements=2)

        # Key Derivation Function selection
        kdf_info = DerSequence().decode(pbes2_params[0], nr_elements=2)
        kdf_oid = DerObjectId().decode(kdf_info[0]).value

        kdf_key_length = None

        # We only support PBKDF2 or scrypt
        if kdf_oid == _OID_PBKDF2:
            pbkdf2_params = DerSequence().decode(kdf_info[1], nr_elements=(2, 3, 4))
            salt = DerOctetString().decode(pbkdf2_params[0]).payload
            iteration_count = pbkdf2_params[1]
            if iteration_count < 1:
                raise PbesError("Invalid PBKDF2 iteration count")

            left = len(pbkdf2_params) - 2
            idx = 2

            if left > 0:
                try:
                    # Check if it's an INTEGER
                    kdf_key_length = pbkdf2_params[idx] - 0
                    left -= 1
                    idx += 1
                except TypeError:
                    # keyLength is not present
                    pass

            # Default is HMAC-SHA1
            pbkdf2_prf_oid = _OID_HMAC_SHA1
            if left > 0:
                pbkdf2_prf_algo_id = DerSequence().decode(pbkdf2_params[idx])
                pbkdf2_prf_oid = DerObjectId().decode(pbkdf2_prf_algo_id[0]).value

            try:
                hmac_hash_module_oid = Hash.HMAC._hmac2hash_oid[pbkdf2_prf_oid]
            except KeyError:
                raise PbesError("Unsupported HMAC %s" % pbkdf2_prf_oid)

            _check_iteration_count(
                _PBKDF2_COUNT, iteration_count, max_iteration_count, _DEFAULT_MAX_ITERATION_COUNT
            )

        elif kdf_oid == _OID_SCRYPT:
            scrypt_params = DerSequence().decode(kdf_info[1], nr_elements=(4, 5))
            salt = DerOctetString().decode(scrypt_params[0]).payload
            iteration_count, scrypt_r, scrypt_p = (scrypt_params[x] for x in (1, 2, 3))

            _check_scrypt_params(iteration_count, scrypt_r, scrypt_p)
            _check_scrypt_cost(iteration_count, scrypt_r, scrypt_p, max_iteration_count)
            threads = _scrypt_threads(iteration_count, scrypt_r, scrypt_p, threads, max_memory)

            if len(scrypt_params) > 4:
                kdf_key_length = scrypt_params[4]
            else:
                kdf_key_length = None
        else:
            raise PbesError("Unsupported PBES2 KDF")

        # Cipher selection
        enc_info = DerSequence().decode(pbes2_params[1])
        enc_oid = DerObjectId().decode(enc_info[0]).value

        aead = False
        module: ModuleType
        if enc_oid == _OID_DES_EDE3_CBC:
            # DES_EDE3_CBC
            from Crypto.Cipher import DES3

            module = DES3
            cipher_mode = DES3.MODE_CBC
            key_size = 24
            cipher_param = "iv"
        elif enc_oid == _OID_AES128_CBC:
            module = AES
            cipher_mode = AES.MODE_CBC
            key_size = 16
            cipher_param = "iv"
        elif enc_oid == _OID_AES192_CBC:
            module = AES
            cipher_mode = AES.MODE_CBC
            key_size = 24
            cipher_param = "iv"
        elif enc_oid == _OID_AES256_CBC:
            module = AES
            cipher_mode = AES.MODE_CBC
            key_size = 32
            cipher_param = "iv"
        elif enc_oid == _OID_AES128_GCM:
            module = AES
            cipher_mode = AES.MODE_GCM
            key_size = 16
            cipher_param = "nonce"
            aead = True
        elif enc_oid == _OID_AES192_GCM:
            module = AES
            cipher_mode = AES.MODE_GCM
            key_size = 24
            cipher_param = "nonce"
            aead = True
        elif enc_oid == _OID_AES256_GCM:
            module = AES
            cipher_mode = AES.MODE_GCM
            key_size = 32
            cipher_param = "nonce"
            aead = True
        else:
            raise PbesError("Unsupported PBES2 cipher " + enc_oid)

        if kdf_key_length and kdf_key_length != key_size:
            raise PbesError("Mismatch between PBES2 KDF parameters and selected cipher")

        iv_nonce = DerOctetString().decode(enc_info[1]).payload

        # Create cipher
        if kdf_oid == _OID_PBKDF2:
            hmac_hash_module: Any = Hash.new(hmac_hash_module_oid)

            key = PBKDF2(passphrase, salt, key_size, iteration_count, hmac_hash_module=hmac_hash_module)
        else:
            key = scrypt(passphrase, salt, key_size, iteration_count, scrypt_r, scrypt_p, threads=threads)
        cipher = module.new(key, cipher_mode, **{cipher_param: iv_nonce})

        # Decrypt data
        if len(encrypted_data) < cipher.block_size:
            raise ValueError("Too little data to decrypt")

        try:
            if aead:
                tag_len = cipher.block_size
                pt = cipher.decrypt_and_verify(encrypted_data[:-tag_len], encrypted_data[-tag_len:])
            else:
                pt_padded = cipher.decrypt(encrypted_data)
                pt = unpad(pt_padded, cipher.block_size)
        except ValueError:
            raise IncorrectPassphraseError(_INCORRECT_PASSPHRASE) from None

        return pt
