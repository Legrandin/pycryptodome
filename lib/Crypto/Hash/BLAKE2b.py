# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from binascii import unhexlify
from typing import Optional, Union

from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import tobytes
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

_raw_blake2b_lib = load_pycryptodome_raw_lib(
    "Crypto.Hash._BLAKE2b",
    """
                        int blake2b_init(void **state,
                                         const uint8_t *key,
                                         size_t key_size,
                                         size_t digest_size);
                        int blake2b_destroy(void *state);
                        int blake2b_update(void *state,
                                           const uint8_t *buf,
                                           size_t len);
                        int blake2b_digest(const void *state,
                                           uint8_t digest[64]);
                        int blake2b_copy(const void *src, void *dst);
                        """,
)


class BLAKE2b_Hash:
    """A BLAKE2b hash object.
    Do not instantiate directly. Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string

    :ivar block_size: the size in bytes of the internal message block,
                      input to the compression function
    :vartype block_size: integer

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer
    """

    # The internal block size of the hash algorithm in bytes.
    block_size: int = 64

    def __init__(
        self, data: Optional[Buffer], key: Buffer, digest_bytes: int, update_after_digest: bool
    ) -> None:
        # The size of the resulting hash in bytes.
        self.digest_size = digest_bytes

        self._update_after_digest = update_after_digest
        self._digest_done = False

        # See https://tools.ietf.org/html/rfc7693
        if digest_bytes in (20, 32, 48, 64) and not key:
            self.oid = "1.3.6.1.4.1.1722.12.2.1." + str(digest_bytes // 4)

        state = VoidPointer()
        key_ptr, key_len = c_uint8_ptr_len(key)
        result = _raw_blake2b_lib.blake2b_init(
            state.address_of(), key_ptr, c_size_t(key_len), c_size_t(digest_bytes)
        )
        if result:
            raise ValueError("Error %d while instantiating BLAKE2b" % result)
        self._state = SmartPointer(state.get(), _raw_blake2b_lib.blake2b_destroy)
        if data:
            self.update(data)

    def update(self, data: Buffer) -> BLAKE2b_Hash:
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (bytes/bytearray/memoryview): The next chunk of the message being hashed.
        """

        if self._digest_done and not self._update_after_digest:
            raise TypeError("You can only call 'digest' or 'hexdigest' on this object")

        data_ptr, data_len = c_uint8_ptr_len(data)
        result = _raw_blake2b_lib.blake2b_update(self._state.get(), data_ptr, c_size_t(data_len))
        if result:
            raise ValueError("Error %d while hashing BLAKE2b data" % result)
        return self

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        bfr = create_string_buffer(64)
        result = _raw_blake2b_lib.blake2b_digest(self._state.get(), bfr)
        if result:
            raise ValueError("Error %d while creating BLAKE2b digest" % result)

        self._digest_done = True

        return get_raw_buffer(bfr)[: self.digest_size]

    def hexdigest(self) -> str:
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % x for x in tuple(self.digest())])

    def verify(self, mac_tag: Buffer) -> None:
        """Verify that a given **binary** MAC (computed by another party)
        is valid.

        Args:
          mac_tag (bytes/bytearray/memoryview): the expected MAC of the message.

        Raises:
            ValueError: if the MAC does not match. It means that the message
                has been tampered with or that the MAC key is incorrect.
        """

        secret = get_random_bytes(16)

        mac1 = new(digest_bits=160, key=secret, data=mac_tag)
        mac2 = new(digest_bits=160, key=secret, data=self.digest())

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag: str) -> None:
        """Verify that a given **printable** MAC (computed by another party)
        is valid.

        Args:
            hex_mac_tag (string): the expected MAC of the message, as a hexadecimal string.

        Raises:
            ValueError: if the MAC does not match. It means that the message
                has been tampered with or that the MAC key is incorrect.
        """

        self.verify(unhexlify(tobytes(hex_mac_tag)))

    def new(
        self,
        *,
        data: Optional[Buffer] = None,
        digest_bytes: Optional[int] = None,
        digest_bits: Optional[int] = None,
        key: Buffer = b"",
        update_after_digest: bool = False,
    ) -> BLAKE2b_Hash:
        """Return a new instance of a BLAKE2b hash object.
        See :func:`new`.
        """

        if digest_bytes is None and digest_bits is None:
            digest_bytes = self.digest_size

        return new(
            data=data,
            digest_bytes=digest_bytes,
            digest_bits=digest_bits,
            key=key,
            update_after_digest=update_after_digest,
        )


def new(
    *,
    data: Optional[Buffer] = None,
    digest_bytes: Optional[int] = None,
    digest_bits: Optional[int] = None,
    key: Buffer = b"",
    update_after_digest: bool = False,
) -> BLAKE2b_Hash:
    """Create a new hash object.

    Args:
        data (bytes/bytearray/memoryview):
            Optional. The very first chunk of the message to hash.
            It is equivalent to an early call to :meth:`BLAKE2b_Hash.update`.
        digest_bytes (integer):
            Optional. The size of the digest, in bytes (1 to 64). Default is 64.
        digest_bits (integer):
            Optional and alternative to ``digest_bytes``.
            The size of the digest, in bits (8 to 512, in steps of 8).
            Default is 512.
        key (bytes/bytearray/memoryview):
            Optional. The key to use to compute the MAC (1 to 64 bytes).
            If not specified, no key will be used.
        update_after_digest (boolean):
            Optional. By default, a hash object cannot be updated anymore after
            the digest is computed. When this flag is ``True``, such check
            is no longer enforced.

    Returns:
        A :class:`BLAKE2b_Hash` hash object
    """

    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    for name, value in (("digest_bytes", digest_bytes), ("digest_bits", digest_bits)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise TypeError("'%s' must be an integer" % name)
    if digest_bits is None:
        if digest_bytes is None:
            digest_bytes = 64
        if not (1 <= digest_bytes <= 64):
            raise ValueError("'digest_bytes' not in range 1..64")
    else:
        if not (8 <= digest_bits <= 512) or (digest_bits % 8):
            raise ValueError("'digest_bits' not in range 8..512, with steps of 8")
        digest_bytes = digest_bits // 8

    if len(key) > 64:
        raise ValueError("BLAKE2b key cannot exceed 64 bytes")

    return BLAKE2b_Hash(data, key, digest_bytes, update_after_digest)
