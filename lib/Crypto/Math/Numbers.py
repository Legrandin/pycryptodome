# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = ["Integer"]

import os

_implementation: dict[str, Any]

if TYPE_CHECKING:
    # The actual class is only known at runtime
    from Crypto.Math._IntegerBase import IntegerBase as Integer
else:
    # The environment variable PYCRYPTODOME_INTEGER forces one implementation
    # (for testing): "nat", "custom" or "native".
    _forced = os.getenv("PYCRYPTODOME_INTEGER")
    if _forced not in (None, "nat", "custom", "native"):
        raise ValueError("Unknown value for PYCRYPTODOME_INTEGER: %s" % _forced)

    if _forced == "nat":
        from Crypto.Math._IntegerNat import IntegerNat as Integer
        from Crypto.Math._IntegerNat import implementation as _implementation
    elif _forced == "custom":
        from Crypto.Math._IntegerCustom import IntegerCustom as Integer
        from Crypto.Math._IntegerCustom import implementation as _implementation
    elif _forced == "native":
        from Crypto.Math._IntegerNative import IntegerNative as Integer

        _implementation = {}
    else:
        try:
            # Constant-time arithmetic, in C
            from Crypto.Math._IntegerNat import IntegerNat as Integer
            from Crypto.Math._IntegerNat import implementation as _implementation
        except (ImportError, OSError):
            try:
                from Crypto.Math._IntegerCustom import IntegerCustom as Integer
                from Crypto.Math._IntegerCustom import implementation as _implementation
            except (ImportError, OSError):
                from Crypto.Math._IntegerNative import IntegerNative as Integer

                _implementation = {}
