# ===================================================================
#
# Copyright (c) 2021, Legrandin <helderijs@gmail.com>
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

from binascii import unhexlify

from Crypto.Util.number import long_to_bytes
from Crypto.Util.py3compat import bchr, bord, tobytes, is_bytes
from Crypto.Random import get_random_bytes

from . import cSHAKE128, SHA3_256
from .cSHAKE128 import _bytepad, _encode_str


def _right_encode(x):
    """Right encode function as defined in NIST SP 800-185"""

    assert (x < (1 << 2040) and x >= 0)

    # Get number of bytes needed to represent this integer.
    num = 1 if x == 0 else (x.bit_length() + 7) // 8

    return long_to_bytes(x) + bchr(num)


class KMAC_Hash(object):
    """A KMAC hash object.
    Do not instantiate directly.
    Use the :func:`new` function.
    """

    def __init__(self, data, key, digest_bytes, custom,
                 oid_variant, cshake, rate):

        # See https://tools.ietf.org/html/rfc8702
        self.oid = "2.16.840.1.101.3.4.2." + oid_variant
        self.digest_size = digest_bytes

        self._digest = None

        partial_newX = _bytepad(_encode_str(key), rate)
        self._cshake = cshake._new(partial_newX, custom, b"KMAC")

        if data:
            self._cshake.update(data)

    def update(self, data):
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (bytes/bytearray/memoryview): The next chunk of the message being hashed.
        """

        if self._digest:
            raise TypeError("You can only call 'digest' or 'hexdigest' on this object")

        self._cshake.update(data)
        return self

    def digest(self):
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        if not self._digest:
            self._cshake.update(_right_encode(self.digest_size * 8))
            self._digest = self._cshake.read(self.digest_size)

        return self._digest

    def hexdigest(self):
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % bord(x) for x in tuple(self.digest())])

    def verify(self, mac_tag):
        """Verify that a given **binary** MAC (computed by another party)
        is valid.

        Args:
          mac_tag (bytes/bytearray/memoryview): the expected MAC of the message.

        Raises:
            ValueError: if the MAC does not match. It means that the message
                has been tampered with or that the MAC key is incorrect.
        """

        secret = get_random_bytes(16)

        mac1 = SHA3_256.new(secret + mac_tag)
        mac2 = SHA3_256.new(secret + self.digest())

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Verify that a given **printable** MAC (computed by another party)
        is valid.

        Args:
            hex_mac_tag (string): the expected MAC of the message, as a hexadecimal string.

        Raises:
            ValueError: if the MAC does not match. It means that the message
                has been tampered with or that the MAC key is incorrect.
        """

        self.verify(unhexlify(tobytes(hex_mac_tag)))

    def new(self, **kwargs):
        """Return a new instance of a KMAC hash object.
        See :func:`new`.
        """

        if "digest_bytes" not in kwargs and "digest_bits" not in kwargs:
            kwargs["digest_bytes"] = self.digest_size

        return new(**kwargs)


def new(**kwargs):
    """Create a new KMAC128 object.

    Args:
        key (bytes/bytearray/memoryview):
            The key to use to compute the MAC.
            It must be at least 128 bits long (16 bytes).
        data (bytes/bytearray/memoryview):
            Optional. The very first chunk of the message to hash.
            It is equivalent to an early call to :meth:`KMAC128_Hash.update`.
        digest_bytes (integer):
            Optional. The size of the digest, in bytes.
            Default is 64. Minimum is 8.
        digest_bits (integer):
            Optional and alternative to ``digest_bytes``.
            The size of the digest, in bits, multiple of 8.
            Default is 512. Minimum is 64.
        custom (bytes/bytearray/memoryview):
            Optional. A customization bytestring (``S`` in SP 800-185).

    Returns:
        A :class:`KMAC_Hash` hash object
    """

    key = kwargs.pop("key", None)
    if not is_bytes(key):
        raise TypeError("You must pass a key to KMAC128")
    if len(key) < 16:
        raise ValueError("The key must be at least 128 bits long (16 bytes)")

    data = kwargs.pop("data", None)

    digest_bytes = kwargs.pop("digest_bytes", None)
    digest_bits = kwargs.pop("digest_bits", None)
    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    if (None, None) == (digest_bytes, digest_bits):
        digest_bytes = 64
    if digest_bytes is not None:
        if (digest_bytes < 8):
            raise ValueError("Incorrect 'digest_bytes' value")
    else:
        if (digest_bits < 64) or (digest_bits % 8):
            raise ValueError("Incorrect 'digest_bits' value")
        digest_bytes = digest_bits // 8

    custom = kwargs.pop("custom", b"")

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    return KMAC_Hash(data, key, digest_bytes, custom, "19", cSHAKE128, 168)
