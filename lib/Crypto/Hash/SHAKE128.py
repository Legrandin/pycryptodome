# SPDX-FileCopyrightText: 2015 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Optional, Union

from Crypto.Hash.keccak import _raw_keccak_lib
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_ubyte,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_output_buffer,
    get_raw_buffer,
)

Buffer = Union[bytes, bytearray, memoryview]


class SHAKE128_XOF:
    """A SHAKE128 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string
    """

    # ASN.1 Object ID
    oid: str = "2.16.840.1.101.3.4.2.11"

    def __init__(self, data: Optional[Buffer] = None) -> None:
        state = VoidPointer()
        result = _raw_keccak_lib.keccak_init(state.address_of(), c_size_t(32), c_ubyte(24))
        if result:
            raise ValueError("Error %d while instantiating SHAKE128" % result)
        self._state = SmartPointer(state.get(), _raw_keccak_lib.keccak_destroy)
        self._is_squeezing = False
        self._padding = 0x1F
        if data:
            self.update(data)

    def update(self, data: Buffer) -> SHAKE128_XOF:
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        if self._is_squeezing:
            raise TypeError("You cannot call 'update' after the first 'read'")

        data_ptr, data_len = c_uint8_ptr_len(data)
        result = _raw_keccak_lib.keccak_absorb(self._state.get(), data_ptr, c_size_t(data_len))
        if result:
            raise ValueError("Error %d while updating SHAKE128 state" % result)
        return self

    def read(self, length: int) -> bytes:
        """
        Compute the next piece of XOF output.

        .. note::
            You cannot use :meth:`update` anymore after the first call to
            :meth:`read`.

        Args:
            length (integer): the amount of bytes this method must return

        :return: the next piece of XOF output (of the given length)
        :rtype: byte string
        """

        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("'length' must be an integer")
        if length < 0:
            raise ValueError("'length' must be a non-negative integer")

        self._is_squeezing = True
        bfr = create_output_buffer(length)
        with c_uint8_ptr_out(bfr) as bfr_ptr:
            result = _raw_keccak_lib.keccak_squeeze(
                self._state.get(), bfr_ptr, c_size_t(length), c_ubyte(self._padding)
            )
        if result:
            raise ValueError("Error %d while extracting from SHAKE128" % result)

        return get_raw_buffer(bfr)

    def copy(self) -> SHAKE128_XOF:
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.

        :return: A hash object of the same type
        """

        clone = self.new()
        result = _raw_keccak_lib.keccak_copy(self._state.get(), clone._state.get())
        if result:
            raise ValueError("Error %d while copying SHAKE128" % result)
        return clone

    def new(self, data: Optional[Buffer] = None) -> SHAKE128_XOF:
        return type(self)(data=data)


def new(data: Optional[Buffer] = None) -> SHAKE128_XOF:
    """Return a fresh instance of a SHAKE128 object.

    Args:
       data (bytes/bytearray/memoryview):
        The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.
        Optional.

    :Return: A :class:`SHAKE128_XOF` object
    """

    return SHAKE128_XOF(data=data)
