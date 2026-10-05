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

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Union

from Crypto.Util._raw_api import is_buffer

from . import cSHAKE128
from .cSHAKE128 import _encode_str, _right_encode

if TYPE_CHECKING:
    from types import ModuleType

Buffer = Union[bytes, bytearray, memoryview]


class TupleHash:
    """A Tuple hash object.
    Do not instantiate directly.
    Use the :func:`new` function.
    """

    def __init__(self, custom: Buffer, cshake: ModuleType, digest_size: int) -> None:

        self.digest_size = digest_size

        self._cshake_module = cshake
        self._cshake = cshake._new(b"", custom, b"TupleHash")
        self._digest: Optional[bytes] = None

    def update(self, *data: Buffer) -> TupleHash:
        """Authenticate the next tuple of byte strings.
        TupleHash guarantees the logical separation between each byte string.

        Args:
            data (bytes/bytearray/memoryview): One or more items to hash.
        """

        if self._digest is not None:
            raise TypeError("You cannot call 'update' after 'digest' or 'hexdigest'")

        for item in data:
            if not is_buffer(item):
                raise TypeError("You can only call 'update' on bytes")
            self._cshake.update(_encode_str(item))

        return self

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) digest of the tuple of byte strings.

        :return: The hash digest. Binary form.
        :rtype: byte string
        """

        if self._digest is None:
            self._cshake.update(_right_encode(self.digest_size * 8))
            self._digest = self._cshake.read(self.digest_size)

        return self._digest

    def hexdigest(self) -> str:
        """Return the **printable** digest of the tuple of byte strings.

        :return: The hash digest. Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % x for x in tuple(self.digest())])

    def new(
        self, *, digest_bytes: Optional[int] = None, digest_bits: Optional[int] = None, custom: Buffer = b""
    ) -> TupleHash:
        """Return a new instance of a TupleHash object.
        See :func:`new`.
        """

        if digest_bytes is None and digest_bits is None:
            digest_bytes = self.digest_size

        # The same class implements both TupleHash128 and TupleHash256
        if self._cshake_module is cSHAKE128:
            factory = new
        else:
            from .TupleHash256 import new as factory

        return factory(digest_bytes=digest_bytes, digest_bits=digest_bits, custom=custom)


def new(
    *, digest_bytes: Optional[int] = None, digest_bits: Optional[int] = None, custom: Buffer = b""
) -> TupleHash:
    """Create a new TupleHash128 object.

    Args:
       digest_bytes (integer):
        Optional. The size of the digest, in bytes.
        Default is 64. Minimum is 8.
       digest_bits (integer):
        Optional and alternative to ``digest_bytes``.
        The size of the digest, in bits (and in steps of 8).
        Default is 512. Minimum is 64.
       custom (bytes):
        Optional.
        A customization bytestring (``S`` in SP 800-185).

    :Return: A :class:`TupleHash` object
    """

    if None not in (digest_bytes, digest_bits):
        raise TypeError("Only one digest parameter must be provided")
    if digest_bits is None:
        if digest_bytes is None:
            digest_bytes = 64
        if digest_bytes < 8:
            raise ValueError("'digest_bytes' must be at least 8")
    else:
        if digest_bits < 64 or digest_bits % 8:
            raise ValueError("'digest_bytes' must be at least 64 in steps of 8")
        digest_bytes = digest_bits // 8

    return TupleHash(custom, cSHAKE128, digest_bytes)
