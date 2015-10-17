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

"""Keccak family of cryptographic hash algorithms.

`Keccak`_ is the winning algorithm of the SHA-3 competition organized by NIST.
What eventually became SHA-3 is a variant incompatible to Keccak,
even though the security principles and margins remain the same.

If you are interested in writing SHA-3 compliant code, you must use
the modules ``SHA3_224``, ``SHA3_256``, ``SHA3_384`` or ``SHA3_512``.

This module implements the Keccak hash functions for the 64 bit word
length (b=1600) and the fixed digest sizes of 224, 256, 384 and 512 bits.

    >>> from Crypto.Hash import keccak
    >>>
    >>> h_obj = keccak.new(digest_bits=512)
    >>> h_obj.update(b'Some data')
    >>> print h_obj.hexdigest()

.. _Keccak: http://www.keccak.noekeon.org/Keccak-specifications.pdf
"""

from Crypto.Util.py3compat import bord

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  create_string_buffer,
                                  get_raw_buffer, c_size_t,
                                  expect_byte_string)

_raw_keccak_lib = load_pycryptodome_raw_lib("Crypto.Hash._keccak",
                        """
                        int keccak_init(void **state, size_t digest_size,
                                        uint8_t padding_byte);
                        int keccak_destroy(void *state);
                        int keccak_absorb(void *state,
                                          const uint8_t *buf,
                                          size_t len);
                        int keccak_digest(const void *state,
                                          uint8_t *digest,
                                          size_t digest_bytes);
                        int keccak_copy(const void *src, void *dst);
                        """)

class Keccak_Hash(object):
    """Class that implements a Keccak hash
    """

    def __init__(self, data, digest_bytes):
        #: The size of the resulting hash in bytes.
        self.digest_size = digest_bytes

        state = VoidPointer()
        result = _raw_keccak_lib.keccak_init(state.address_of(),
                                             c_size_t(self.digest_size),
                                             0x01)
        if result:
            raise ValueError("Error %d while instantiating keccak" % result)
        self._state = SmartPointer(state.get(),
                                   _raw_keccak_lib.keccak_destroy)
        if data:
            self.update(data)

    def update(self, data):
        """Continue hashing of a message by consuming the next chunk of data.

        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments. In other words:

           >>> m.update(a); m.update(b)

        is equivalent to:

           >>> m.update(a+b)

        :Parameters:
          data : byte string
            The next chunk of the message being hashed.
        """

        expect_byte_string(data)
        result = _raw_keccak_lib.keccak_absorb(self._state.get(),
                                               data,
                                               c_size_t(len(data)))
        if result:
            raise ValueError("Error %d while instantiating keccak" % result)
        return self

    def digest(self):
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        This method does not change the state of the hash object.
        You can continue updating the object after calling this function.

        :Return: A byte string of `digest_size` bytes. It may contain non-ASCII
         characters, including null bytes.
        """

        bfr = create_string_buffer(self.digest_size)
        result = _raw_keccak_lib.keccak_digest(self._state.get(),
                                               bfr,
                                               c_size_t(self.digest_size))
        if result:
            raise ValueError("Error %d while instantiating keccak" % result)

        return get_raw_buffer(bfr)

    def hexdigest(self):
        """Return the **printable** digest of the message that has been hashed so far.

        This method does not change the state of the hash object.

        :Return: A string of 2* `digest_size` characters. It contains only
         hexadecimal ASCII digits.
        """

        return "".join(["%02x" % bord(x) for x in self.digest()])

    def copy(self):
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.
        This can be used to efficiently compute the digests of strings that
        share a common initial substring.

        :Return: A hash object of the same type
        """

        clone = type(self)(None, self.digest_size)
        result = _raw_keccak_lib.keccak_copy(self._state.get(),
                                             clone._state.get())
        if result:
            raise ValueError("Error %d while copying keccak" % result)
        return clone

    def new(self):
        return type(self)(None, self.digest_size)


def new(**kwargs):
    """Return a fresh instance of the hash object.

    :Parameters:
      data : byte string
        Optional. The very first chunk of the message to hash.
        It is equivalent to an early call to ``update()``.
      digest_bytes : integer
        The size of the digest, in bytes (24, 32, 48, 64).
      digest_bits : integer
        The size of the digest, in bits (224, 256, 384, 512).

    :Return: A `Keccak_Hash` object
    """

    data = kwargs.pop("data", None)

    digest_bytes = kwargs.pop("digest_bytes", None)
    digest_bits = kwargs.pop("digest_bits", None)
    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    if (None, None) == (digest_bytes, digest_bits):
        raise TypeError("Digest size (bits, bytes) not provided")
    if digest_bytes is not None:
        if digest_bytes not in (24, 32, 48, 64):
            raise ValueError("'digest_bytes' must be: 24, 32, 48 or 64")
    else:
        if digest_bits not in (224, 256, 384, 512):
            raise ValueError("'digest_bytes' must be: 224, 256, 384 or 512")
        digest_bytes = digest_bits // 8

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    return Keccak_Hash(data, digest_bytes)
