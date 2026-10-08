# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""The order in which the methods of a cipher object can be called.

Each cipher object keeps in ``self._next`` the methods that the caller
may invoke next. Each method checks that it is in ``self._next`` (or raises
``TypeError``), and then sets ``self._next`` to the methods allowed after it.
"""

from enum import Enum


class Method(Enum):
    """A method of a cipher object"""

    UPDATE = "update"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    DIGEST = "digest"
    VERIFY = "verify"
