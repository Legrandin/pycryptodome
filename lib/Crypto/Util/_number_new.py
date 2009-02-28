# -*- coding: ascii -*-
#
#  Util/_number_new.py : utility functions
#
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# =======================================================================
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================

## NOTE: Do not import this module directly.  Import these functions from Crypto.Util.number.

__revision__ = "$Id$"
__all__ = ['ceil_shift', 'ceil_div', 'floor_div', 'exact_log2', 'exact_div']

from Crypto.Util.python_compat import *

def ceil_shift(n, b):
    """Return ceil(n / 2**b) without performing any floating-point or division operations.

    This is done by right-shifting n by b bits and incrementing the result by 1
    if any '1' bits were shifted out.
    """
    if not isinstance(n, (int, long)) or not isinstance(b, (int, long)):
        raise TypeError("unsupported operand type(s): %r and %r" % (type(n).__name__, type(b).__name__))

    assert n >= 0 and b >= 0    # I haven't tested or even thought about negative values
    mask = (1L << b) - 1
    if n & mask:
        return (n >> b) + 1
    else:
        return n >> b

def ceil_div(a, b):
    """Return ceil(a / b) without performing any floating-point operations."""

    if not isinstance(a, (int, long)) or not isinstance(b, (int, long)):
        raise TypeError("unsupported operand type(s): %r and %r" % (type(a).__name__, type(b).__name__))

    (q, r) = divmod(a, b)
    if r:
        return q + 1
    else:
        return q

def floor_div(a, b):
    if not isinstance(a, (int, long)) or not isinstance(b, (int, long)):
        raise TypeError("unsupported operand type(s): %r and %r" % (type(a).__name__, type(b).__name__))

    (q, r) = divmod(a, b)
    return q

def exact_log2(num):
    """Find and return an integer i >= 0 such that num == 2**i.

    If no such integer exists, this function raises ValueError.
    """

    if not isinstance(num, (int, long)):
        raise TypeError("unsupported operand type: %r" % (type(num).__name__,))

    n = long(num)
    if n <= 0:
        raise ValueError("cannot compute logarithm of non-positive number")

    i = 0
    while n != 0:
        if (n & 1) and n != 1:
            raise ValueError("No solution could be found")
        i += 1
        n >>= 1
    i -= 1

    assert num == (1L << i)
    return i

def exact_div(p, d, allow_divzero=False):
    """Find and return an integer n such that p == n * d

    If no such integer exists, this function raises ValueError.

    Both operands must be integers.

    If the second operand is zero, this function will raise ZeroDivisionError
    unless allow_divzero is true (default: False).
    """

    if not isinstance(p, (int, long)) or not isinstance(d, (int, long)):
        raise TypeError("unsupported operand type(s): %r and %r" % (type(p).__name__, type(d).__name__))

    if d == 0 and allow_divzero:
        n = 0
        if p != n * d:
            raise ValueError("No solution could be found")
    else:
        (n, r) = divmod(p, d)
        if r != 0:
            raise ValueError("No solution could be found")

    assert p == n * d
    return n

# vim:set ts=4 sw=4 sts=4 expandtab:
