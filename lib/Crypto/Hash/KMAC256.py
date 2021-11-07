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

from Crypto.Util.py3compat import is_bytes

from .KMAC128 import KMAC_Hash
from . import cSHAKE256


def new(**kwargs):
    """Create a new KMAC256 object.

    Args:
        key (bytes/bytearray/memoryview):
            The key to use to compute the MAC.
            It must be at least 256 bits long (32 bytes).
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
        A :class:`KMAC128_Hash` hash object
    """

    key = kwargs.pop("key", None)
    if not is_bytes(key):
        raise TypeError("You must pass a key to KMAC256")
    if len(key) < 32:
        raise ValueError("The key must be at least 256 bits long (32 bytes)")

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

    return KMAC_Hash(data, key, digest_bytes, custom, "20", cSHAKE256, 136)
