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

_raw_md4_lib = load_pycryptodome_raw_lib(
    "Crypto.Hash._MD4",
    """
                        int md4_init(void **shaState);
                        int md4_destroy(void *shaState);
                        int md4_update(void *hs,
                                          const uint8_t *buf,
                                          size_t len);
                        int md4_digest(const void *shaState,
                                          uint8_t digest[20]);
                        int md4_copy(const void *src, void *dst);
                        """,
)


class MD4Hash:
    """Class that implements an MD4 hash"""

    #: The size of the resulting hash in bytes.
    digest_size: int = 16
    #: The internal block size of the hash algorithm in bytes.
    block_size: int = 64
    #: ASN.1 Object ID
    oid: str = "1.2.840.113549.2.4"

    def __init__(self, data: Optional[Buffer] = None) -> None:
        state = VoidPointer()
        result = _raw_md4_lib.md4_init(state.address_of())
        if result:
            raise ValueError("Error %d while instantiating MD4" % result)
        self._state = SmartPointer(state.get(), _raw_md4_lib.md4_destroy)
        if data:
            self.update(data)

    def update(self, data: Buffer) -> None:
        """Continue hashing of a message by consuming the next chunk of data.

        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments. In other words:

           >>> m.update(a); m.update(b)

        is equivalent to:

           >>> m.update(a+b)

        :Parameters:
          data : byte string/byte array/memoryview
            The next chunk of the message being hashed.
        """

        data_ptr, data_len = c_uint8_ptr_len(data)
        result = _raw_md4_lib.md4_update(self._state.get(), data_ptr, c_size_t(data_len))
        if result:
            raise ValueError("Error %d while instantiating MD4" % result)

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the message that
        has been hashed so far.

        This method does not change the state of the hash object.
        You can continue updating the object after calling this function.

        :Return: A byte string of `digest_size` bytes. It may contain non-ASCII
         characters, including null bytes.
        """

        bfr = create_string_buffer(self.digest_size)
        result = _raw_md4_lib.md4_digest(self._state.get(), bfr)
        if result:
            raise ValueError("Error %d while instantiating MD4" % result)

        return get_raw_buffer(bfr)

    def hexdigest(self) -> str:
        """Return the **printable** digest of the message that has been
        hashed so far.

        This method does not change the state of the hash object.

        :Return: A string of 2* `digest_size` characters. It contains only
         hexadecimal ASCII digits.
        """

        return "".join(["%02x" % x for x in self.digest()])

    def copy(self) -> MD4Hash:
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.
        This can be used to efficiently compute the digests of strings that
        share a common initial substring.

        :Return: A hash object of the same type
        """

        clone = MD4Hash()
        result = _raw_md4_lib.md4_copy(self._state.get(), clone._state.get())
        if result:
            raise ValueError("Error %d while copying MD4" % result)
        return clone

    def new(self, data: Optional[Buffer] = None) -> MD4Hash:
        return MD4Hash(data)


def new(data: Optional[Buffer] = None) -> MD4Hash:
    """Return a fresh instance of the hash object.

    :Parameters:
       data : byte string/byte array/memoryview
        The very first chunk of the message to hash.
        It is equivalent to an early call to `MD4Hash.update()`.
        Optional.

    :Return: A `MD4Hash` object
    """
    return MD4Hash().new(data)


#: The size of the resulting hash in bytes.
digest_size: int = MD4Hash.digest_size

#: The internal block size of the hash algorithm in bytes.
block_size: int = MD4Hash.block_size
