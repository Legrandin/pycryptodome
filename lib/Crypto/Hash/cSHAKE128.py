# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
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

from Crypto.Util.py3compat import bchr

from Crypto.Util._raw_api import (VoidPointer, SmartPointer,
                                  create_string_buffer,
                                  get_raw_buffer, c_size_t,
                                  c_uint8_ptr)

from Crypto.Hash.keccak import _raw_keccak_lib


def left_encode(x: int):
    """Left encode function as defined in NIST SP 800-185"""

    assert (x < (1 << 2040) and x >= 0)

    # Get number of bytes needed to represent this integer.
    num = 1 if x == 0 else (x.bit_length() + 7) // 8
    # Chop off least significant byte of integer.
    enc = bchr(num) + bchr(x & 0xFF)
    x >>= 8
    # Chop off remaining bytes if needed.
    while x > 0:
        enc = enc + bchr(x & 0xFF)
        x >>= 8

    return enc


def encode_str(x: bytes):
    """Encode string function as defined in NIST SP 800-185"""

    if x is None:
        return left_encode(0)
    else:
        bitlen = len(x) * 8

        if bitlen >= (1 << 2040):
            raise ValueError("String too large to encode in cSHAKE128")

        return left_encode(bitlen) + x


def byte_align(x: bytes, length: int):
    """Zero pad byte string as defined in NIST SP 800-185"""

    x = left_encode(length) + x

    # Note: this implementation works with byte aligned strings,
    # hence no additional bit padding is needed at this point.
    npad = (length - len(x) % length) % length
    while npad:
        x += bchr(0x00)
        npad -= 1

    return x


class cSHAKE128_XOF(object):
    """A cSHAKE128 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.
    """

    # Parameters
    name = "cSHAKE128"
    prefix_alignment = 168
    keccak_capacity = c_size_t(32)

    def __init__(self, data=None, function=None, custom=None):
        state = VoidPointer()

        self.function = function
        self.custom = custom

        prefix = None
        pad = 0x1F  # default to SHAKE
        if function or custom:
            prefix = encode_str(function) + encode_str(custom)
            prefix = byte_align(prefix, self.prefix_alignment)
            pad = 0x04  # for cSHAKE

        result = _raw_keccak_lib.keccak_init(state.address_of(),
                                             self.keccak_capacity,
                                             pad)
        if result:
            raise ValueError("Error %d while instantiating %s"
                             % (result, self.name))
        self._state = SmartPointer(state.get(),
                                   _raw_keccak_lib.keccak_destroy)
        self._is_squeezing = False

        if prefix:
            self.update(prefix)

        if data:
            self.update(data)

    def update(self, data):
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        if self._is_squeezing:
            raise TypeError("You cannot call 'update' after the first 'read'")

        result = _raw_keccak_lib.keccak_absorb(self._state.get(),
                                               c_uint8_ptr(data),
                                               c_size_t(len(data)))
        if result:
            raise ValueError("Error %d while updating %s state"
                             % (result, self.name))
        return self

    def read(self, length):
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

        self._is_squeezing = True
        bfr = create_string_buffer(length)
        result = _raw_keccak_lib.keccak_squeeze(self._state.get(),
                                                bfr,
                                                c_size_t(length))
        if result:
            raise ValueError("Error %d while extracting from %s"
                             % (result, self.name))

        return get_raw_buffer(bfr)

    def new(self, data=None, function=None, custom=None):
        return type(self)(data=data, function=function, custom=custom)


def new(data=None, function=None, custom=None):
    """Return a fresh instance of a cSHAKE128 object.

    Args:
       data (bytes/bytearray/memoryview):
        The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.
        Optional.
       function (bytes):
        Optional function bytestring.
       custom (bytes):
        Optional customization bytestring.

    :Return: A :class:`cSHAKE128_XOF` object
    """

    return cSHAKE128_XOF(data=data, function=function, custom=custom)
