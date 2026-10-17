# SPDX-FileCopyrightText: 2015 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Optional, Union

from Crypto.Util._cpu_features import load_avx2_bmi2_lib
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_ubyte,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

_keccak_cdecl = """
                        int keccak_init(void **state,
                                        size_t capacity_bytes,
                                        uint8_t rounds);
                        int keccak_destroy(void *state);
                        int keccak_absorb(void *state,
                                          const uint8_t *in,
                                          size_t len);
                        int keccak_squeeze(const void *state,
                                           uint8_t *out,
                                           size_t len,
                                           uint8_t padding);
                        int keccak_digest(void *state,
                                          uint8_t *digest,
                                          size_t len,
                                          uint8_t padding);
                        int keccak_copy(const void *src, void *dst);
                        int keccak_reset(void *state);
                        int keccak_oneshot(const uint8_t *in,
                                           size_t in_len,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t capacity_bytes,
                                           uint8_t rounds,
                                           uint8_t padding);
                        int keccak_pbkdf2_hmac_assist(const void *inner,
                                                      const void *outer,
                                                      const uint8_t *first_hmac,
                                                      uint8_t *result,
                                                      size_t iterations,
                                                      size_t digest_size,
                                                      uint8_t padding);
                        """

_raw_keccak_portable_lib = load_pycryptodome_raw_lib("Crypto.Hash._keccak", _keccak_cdecl)


_raw_keccak_avx2_bmi2_lib = load_avx2_bmi2_lib("Crypto.Hash._keccak_avx2_bmi2", _keccak_cdecl)

# The implementation used by all Keccak-based hashes
if _raw_keccak_avx2_bmi2_lib is not None:
    _raw_keccak_lib = _raw_keccak_avx2_bmi2_lib
else:
    _raw_keccak_lib = _raw_keccak_portable_lib


def _pbkdf2_hmac_assist(inner, outer, first_digest: bytes, iterations: int) -> bytes:
    """Compute the expensive inner loop in PBKDF2-HMAC, for the SHA-3 hashes.

    The modules of the SHA-3 hashes import it,
    because :func:`Crypto.Protocol.KDF.PBKDF2` looks for it there.
    """

    # Not an assert: a negative number would become a huge one in C
    if iterations < 1:
        raise ValueError("The number of iterations must be positive")

    bfr = create_string_buffer(len(first_digest))
    result = _raw_keccak_lib.keccak_pbkdf2_hmac_assist(
        inner._state.get(),
        outer._state.get(),
        first_digest,
        bfr,
        c_size_t(iterations),
        c_size_t(len(first_digest)),
        c_ubyte(inner._padding),
    )

    if result:
        raise ValueError("Error %d with PBKDF2-HMAC assist for SHA-3" % result)

    return get_raw_buffer(bfr)


class Keccak_Hash:
    """A Keccak hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer
    """

    def __init__(self, data: Optional[Buffer], digest_bytes: int, update_after_digest: bool) -> None:
        # The size of the resulting hash in bytes.
        self.digest_size = digest_bytes

        self._update_after_digest = update_after_digest
        self._digest_done = False
        self._padding = 0x01

        state = VoidPointer()
        result = _raw_keccak_lib.keccak_init(state.address_of(), c_size_t(self.digest_size * 2), c_ubyte(24))
        if result:
            raise ValueError("Error %d while instantiating keccak" % result)
        self._state = SmartPointer(state.get(), _raw_keccak_lib.keccak_destroy)
        if data:
            self.update(data)

    def update(self, data: Buffer) -> Keccak_Hash:
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        if self._digest_done and not self._update_after_digest:
            raise TypeError("You can only call 'digest' or 'hexdigest' on this object")

        data_ptr, data_len = c_uint8_ptr_len(data)
        result = _raw_keccak_lib.keccak_absorb(self._state.get(), data_ptr, c_size_t(data_len))
        if result:
            raise ValueError("Error %d while updating keccak" % result)
        return self

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        self._digest_done = True
        bfr = create_string_buffer(self.digest_size)
        result = _raw_keccak_lib.keccak_digest(
            self._state.get(), bfr, c_size_t(self.digest_size), c_ubyte(self._padding)
        )
        if result:
            raise ValueError("Error %d while squeezing keccak" % result)

        return get_raw_buffer(bfr)

    def hexdigest(self) -> str:
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return self.digest().hex()

    def new(
        self,
        *,
        data: Optional[Buffer] = None,
        digest_bytes: Optional[int] = None,
        digest_bits: Optional[int] = None,
        update_after_digest: bool = False,
    ) -> Keccak_Hash:
        """Create a fresh Keccak hash object."""

        if digest_bytes is None and digest_bits is None:
            digest_bytes = self.digest_size

        return new(
            data=data,
            digest_bytes=digest_bytes,
            digest_bits=digest_bits,
            update_after_digest=update_after_digest,
        )


def new(
    *,
    data: Optional[Buffer] = None,
    digest_bytes: Optional[int] = None,
    digest_bits: Optional[int] = None,
    update_after_digest: bool = False,
) -> Keccak_Hash:
    """Create a new hash object.

    Args:
        data (bytes/bytearray/memoryview):
            The very first chunk of the message to hash.
            It is equivalent to an early call to :meth:`Keccak_Hash.update`.
        digest_bytes (integer):
            The size of the digest, in bytes (28, 32, 48, 64).
        digest_bits (integer):
            The size of the digest, in bits (224, 256, 384, 512).
        update_after_digest (boolean):
            Whether :meth:`Keccak.digest` can be followed by another
            :meth:`Keccak.update` (default: ``False``).

    :Return: A :class:`Keccak_Hash` hash object
    """

    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    if (digest_bytes, digest_bits) == (None, None):
        raise TypeError("Digest size (bits, bytes) not provided")
    if digest_bytes is not None:
        if digest_bytes not in (28, 32, 48, 64):
            raise ValueError("'digest_bytes' must be: 28, 32, 48 or 64")
    else:
        if digest_bits not in (224, 256, 384, 512):
            raise ValueError("'digest_bytes' must be: 224, 256, 384 or 512")
        digest_bytes = digest_bits // 8

    return Keccak_Hash(data, digest_bytes, update_after_digest)
