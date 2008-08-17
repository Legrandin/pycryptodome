# -*- coding: ascii -*-
#
#  Util/Counter.py : Fast counter for use with CTR-mode ciphers
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

from Crypto.Util.python_compat import *

from Crypto.Util import _counter
import struct

# Factory function
def new(nbits, prefix="", suffix="", initial_value=1, overflow=0, little_endian=False):
    # TODO: Document this

    # Sanity-check the message size
    (nbytes, remainder) = divmod(nbits, 8)
    if remainder != 0:
        # In the future, we might support arbitrary bit lengths, but for now we don't.
        raise ValueError("nbits must be a multiple of 8; got %d" % (nbits,))
    if nbytes < 1:
        raise ValueError("nbits too small")
    elif nbytes > 0xffff:
        raise ValueError("nbits too large")

    initval = _encode(initial_value, nbytes, little_endian)
    if little_endian:
        return _counter.CounterLE(str(prefix), str(suffix), initval)
    else:
        return _counter.CounterBE(str(prefix), str(suffix), initval)

def _encode(n, nbytes, little_endian=False):
    retval = []
    n = long(n)
    for i in range(nbytes):
        if little_endian:
            retval.append(chr(n & 0xff))
        else:
            retval.insert(0, chr(n & 0xff))
        n >>= 8
    return "".join(retval)

# vim:set ts=4 sw=4 sts=4 expandtab:
