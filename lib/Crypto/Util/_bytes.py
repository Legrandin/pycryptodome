# SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Internal helpers for handling byte sequences."""

from __future__ import annotations

from typing import Union

Buffer = Union[bytes, bytearray, memoryview]


def tobytes(s: Union[str, Buffer], encoding: str = "latin-1") -> bytes:
    """Return an immutable byte string out of a text string
    (encoded with ``encoding``), a byte string, a bytearray or a memoryview."""

    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode(encoding)
    elif isinstance(s, (bytearray, memoryview)):
        return bytes(s)
    raise TypeError("Expected a string or a bytes-like object, not %s" % type(s).__name__)
