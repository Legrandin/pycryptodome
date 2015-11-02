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

"""BLAKE2b cryptographic hash algorithm.

`BLAKE2b`_ is an optimized variant of BLAKE, one of the SHA-3 candidates that
made it to the final round of the NIST hash competition.

The algorithm uses 64 bit words, and it therefore works best on
64-bit platforms. The digest size ranges from 8 to 512 bits.

    >>> from Crypto.Hash import BLAKE2b
    >>>
    >>> h_obj = BLAKE2b.new(digest_bits=512)
    >>> h_obj.update(b'Some data')
    >>> print h_obj.hexdigest()

Optionally, BLAKE2b can work as a cryptographic MAC when initialized
with a secret key.

    >>> from Crypto.Hash import BLAKE2b
    >>>
    >>> mac = BLAKE2b.new(digest_bits=256, key=b'secret')
    >>> mac.update(b'Some data')
    >>> print mac.hexdigest()

:undocumented: __package__

.. _BLAKE2b: https://blake2.net/
"""

from binascii import unhexlify

from Crypto.Util.py3compat import b, bord, tobytes

from Crypto.Random import get_random_bytes
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  create_string_buffer,
                                  get_raw_buffer, c_size_t,
                                  expect_byte_string)

_raw_blake2b_lib = load_pycryptodome_raw_lib("Crypto.Hash._BLAKE2b",
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
                        """)


class BLAKE2b_Hash(object):
    """Class that implements a BLAKE2b hash
    """

    #: The internal block size of the hash algorithm in bytes.
    block_size = 64

    def __init__(self, data, key, digest_bytes, update_after_digest):
        """
        Initialize a BLAKE2b hash object.
        """

        #: The size of the resulting hash in bytes.
        self.digest_size = digest_bytes

        self._update_after_digest = update_after_digest
        self._digest_done = False

        # See https://tools.ietf.org/html/draft-saarinen-blake2-02
        if digest_bytes in (20, 32, 48, 64) and not key:
            self.oid = "1.3.6.1.4.1.1722.12.2.1." + str(digest_bytes)

        expect_byte_string(key)

        state = VoidPointer()
        result = _raw_blake2b_lib.blake2b_init(state.address_of(),
                                               key,
                                               c_size_t(len(key)),
                                               c_size_t(digest_bytes)
                                               )
        if result:
            raise ValueError("Error %d while instantiating BLAKE2b" % result)
        self._state = SmartPointer(state.get(),
                                   _raw_blake2b_lib.blake2b_destroy)
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

        if self._digest_done and not self._update_after_digest:
            raise TypeError("You can only call 'digest' or 'hexdigest' on this object")

        expect_byte_string(data)
        result = _raw_blake2b_lib.blake2b_update(self._state.get(),
                                                 data,
                                                 c_size_t(len(data)))
        if result:
            raise ValueError("Error %d while hashing BLAKE2b data" % result)
        return self

    def digest(self):
        """Return the **binary** (non-printable) digest of the message that
        has been hashed so far.

        You cannot update the hash anymore after the first call to ``digest``
        (or ``hexdigest``).

        :Return: A byte string of `digest_size` bytes. It may contain non-ASCII
         characters, including null bytes.
        """

        bfr = create_string_buffer(64)
        result = _raw_blake2b_lib.blake2b_digest(self._state.get(),
                                                 bfr)
        if result:
            raise ValueError("Error %d while creating BLAKE2b digest" % result)

        self._digest_done = True

        return get_raw_buffer(bfr)[:self.digest_size]

    def hexdigest(self):
        """Return the **printable** digest of the message that has been
        hashed so far.

        This method does not change the state of the hash object.

        :Return: A string of 2* `digest_size` characters. It contains only
         hexadecimal ASCII digits.
        """

        return "".join(["%02x" % bord(x) for x in tuple(self.digest())])

    def verify(self, mac_tag):
        """Verify that a given **binary** MAC (computed by another party)
        is valid.

        :Parameters:
          mac_tag : byte string
            The expected MAC of the message.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        secret = get_random_bytes(16)

        mac1 = new(digest_bits=160, key=secret, data=mac_tag)
        mac2 = new(digest_bits=160, key=secret, data=self.digest())

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Verify that a given **printable** MAC (computed by another party)
        is valid.

        :Parameters:
          hex_mac_tag : string
            The expected MAC of the message, as a hexadecimal string.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        self.verify(unhexlify(tobytes(hex_mac_tag)))

    def new(self, **kwargs):
        """Return a new instance of a BLAKE2b hash object."""

        if "digest_bytes" not in kwargs and "digest_bits" not in kwargs:
            kwargs["digest_bytes"] = self.digest_size

        return new(**kwargs)


def new(**kwargs):
    """Return a new instance of a BLAKE2b hash object.

    :Keywords:
      data : byte string
        The very first chunk of the message to hash.
        It is equivalent to an early call to `BLAKE2b_Hash.update()`.
      digest_bytes : integer
        The size of the digest, in bytes (1 to 64).
      digest_bits : integer
        The size of the digest, in bits (8 to 512, in steps of 8).
      key : byte string
        The key to use to compute the MAC (1 to 64 bytes).
        If not specified, no key will be used.
      update_after_digest : boolean
        Optional. By default, a hash object cannot be updated anymore after
        the digest is computed. When this flag is ``True``, such check
        is no longer enforced.
    :Return: A `BLAKE2b_Hash` object
    """

    data = kwargs.pop("data", None)
    update_after_digest = kwargs.pop("update_after_digest", False)

    digest_bytes = kwargs.pop("digest_bytes", None)
    digest_bits = kwargs.pop("digest_bits", None)
    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    if (None, None) == (digest_bytes, digest_bits):
        raise TypeError("Digest size (bits, bytes) not provided")
    if digest_bytes is not None:
        if not (1 <= digest_bytes <= 64):
            raise ValueError("'digest_bytes' not in range 1..64")
    else:
        if not (8 <= digest_bits <= 512) or (digest_bits % 8):
            raise ValueError("'digest_bytes' not in range 8..512, "
                             "with steps of 8")
        digest_bytes = digest_bits // 8

    key = kwargs.pop("key", b(""))
    if len(key) > 64:
        raise ValueError("BLAKE2s key cannot exceed 64 bytes")

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    return BLAKE2b_Hash(data, key, digest_bytes, update_after_digest)
