# SPDX-FileCopyrightText: 2021 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from typing import Optional, Union

from . import cSHAKE256
from .TupleHash128 import TupleHash

Buffer = Union[bytes, bytearray, memoryview]


def new(
    *, digest_bytes: Optional[int] = None, digest_bits: Optional[int] = None, custom: Buffer = b""
) -> TupleHash:
    """Create a new TupleHash256 object.

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

    return TupleHash(custom, cSHAKE256, digest_bytes)
