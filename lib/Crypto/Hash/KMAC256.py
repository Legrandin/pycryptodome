# SPDX-FileCopyrightText: 2021 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from typing import Optional, Union

from Crypto.Util._raw_api import is_buffer

from . import cSHAKE256
from .KMAC128 import KMAC_Hash

Buffer = Union[bytes, bytearray, memoryview]


def new(*, key: Buffer, data: Optional[Buffer] = None, mac_len: int = 64, custom: Buffer = b"") -> KMAC_Hash:
    """Create a new KMAC256 object.

    Args:
        key (bytes/bytearray/memoryview):
            The key to use to compute the MAC.
            It must be at least 256 bits long (32 bytes).
        data (bytes/bytearray/memoryview):
            Optional. The very first chunk of the message to authenticate.
            It is equivalent to an early call to :meth:`KMAC_Hash.update`.
        mac_len (integer):
            Optional. The size of the authentication tag, in bytes.
            Default is 64. Minimum is 8.
        custom (bytes/bytearray/memoryview):
            Optional. A customization byte string (``S`` in SP 800-185).

    Returns:
        A :class:`KMAC_Hash` hash object
    """

    if not is_buffer(key):
        raise TypeError("You must pass a key to KMAC256")
    if len(key) < 32:
        raise ValueError("The key must be at least 256 bits long (32 bytes)")

    if mac_len < 8:
        raise ValueError("'mac_len' must be 8 bytes or more")

    return KMAC_Hash(data, key, mac_len, custom, "20", cSHAKE256, 136)
