# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Optional, Union

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

_raw_ripemd160_lib = load_pycryptodome_raw_lib(
    "Crypto.Hash._RIPEMD160",
    """
                        int ripemd160_init(void **shaState);
                        int ripemd160_destroy(void *shaState);
                        int ripemd160_update(void *hs,
                                          const uint8_t *buf,
                                          size_t len);
                        int ripemd160_digest(const void *shaState,
                                          uint8_t digest[20]);
                        int ripemd160_copy(const void *src, void *dst);
                        """,
)


class RIPEMD160Hash:
    """A RIPEMD-160 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string

    :ivar block_size: the size in bytes of the internal message block,
                      input to the compression function
    :vartype block_size: integer

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer
    """

    # The size of the resulting hash in bytes.
    digest_size: int = 20
    # The internal block size of the hash algorithm in bytes.
    block_size: int = 64
    # ASN.1 Object ID
    oid: str = "1.3.36.3.2.1"

    def __init__(self, data: Optional[Buffer] = None) -> None:
        state = VoidPointer()
        result = _raw_ripemd160_lib.ripemd160_init(state.address_of())
        if result:
            raise ValueError("Error %d while instantiating RIPEMD160" % result)
        self._state = SmartPointer(state.get(), _raw_ripemd160_lib.ripemd160_destroy)
        if data:
            self.update(data)

    def update(self, data: Buffer) -> None:
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        data_ptr, data_len = c_uint8_ptr_len(data)
        result = _raw_ripemd160_lib.ripemd160_update(self._state.get(), data_ptr, c_size_t(data_len))
        if result:
            raise ValueError("Error %d while instantiating ripemd160" % result)

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        bfr = create_string_buffer(self.digest_size)
        result = _raw_ripemd160_lib.ripemd160_digest(self._state.get(), bfr)
        if result:
            raise ValueError("Error %d while instantiating ripemd160" % result)

        return get_raw_buffer(bfr)

    def hexdigest(self) -> str:
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % x for x in self.digest()])

    def copy(self) -> RIPEMD160Hash:
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.
        This can be used to efficiently compute the digests of strings that
        share a common initial substring.

        :return: A hash object of the same type
        """

        clone = RIPEMD160Hash()
        result = _raw_ripemd160_lib.ripemd160_copy(self._state.get(), clone._state.get())
        if result:
            raise ValueError("Error %d while copying ripemd160" % result)
        return clone

    def new(self, data: Optional[Buffer] = None) -> RIPEMD160Hash:
        """Create a fresh RIPEMD-160 hash object."""

        return RIPEMD160Hash(data)


def new(data: Optional[Buffer] = None) -> RIPEMD160Hash:
    """Create a new hash object.

    :parameter data:
        Optional. The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`RIPEMD160Hash.update`.
    :type data: byte string/byte array/memoryview

    :Return: A :class:`RIPEMD160Hash` hash object
    """

    return RIPEMD160Hash().new(data)


# The size of the resulting hash in bytes.
digest_size: int = RIPEMD160Hash.digest_size

# The internal block size of the hash algorithm in bytes.
block_size: int = RIPEMD160Hash.block_size
