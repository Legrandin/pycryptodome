# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Type aliases shared by the PyCryptodome modules (for annotations only).

This module must not import anything from ``Crypto``, so that any module can
import it without creating an import cycle."""

from typing import Callable, Union

# The types accepted wherever PyCryptodome reads bytes.
# With Python 3.12 as the minimum, it can become collections.abc.Buffer (PEP 688).
Buffer = Union[bytes, bytearray, memoryview]

# A function that returns the requested number of random bytes
RNG = Callable[[int], bytes]

# A message as pieces to concatenate, so that a long piece is never copied
# (for instance, the message M' of ML-DSA and SLH-DSA: a short prefix and M)
Message = tuple[Buffer, ...]
