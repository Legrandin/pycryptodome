#
#  Random/OSRNG/rng_base.py : Base class for OSRNG
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

__revision__ = "$Id$"

# Python 2.1 compatibility
try:
    True, False
except NameError:
    True = 1
    False = 0
try:
    object
except NameError:
    class object: pass

class BaseRNG(object):

    def __init__(self):
        self.closed = False
        self._selftest()

    def __del__(self):
        self.close()

    def _selftest(self):
        # Test that urandom can return data
        data = self.read(16)
        if len(data) != 16:
            raise AssertionError("read truncated")

        # Test that we get different data every time (if we don't, the RNG is
        # probably malfunctioning)
        data2 = self.read(16)
        if data == data2:
            raise AssertionError("OS RNG returned duplicate data")

    # PEP 343: Support for the "with" statement
    def __enter__(self):
        pass
    def __exit__(self):
        """PEP 343 support"""
        self.close()

    def close(self):
        if not self.closed:
            self._close()
        self.closed = True

    def flush(self):
        pass

    def read(self, N=-1):
        """Return N bytes from the RNG."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not isinstance(N, (long, int)):
            raise TypeError("an integer is required")
        if N < 0:
            raise ValueError("cannot read to end of infinite stream")
        elif N == 0:
            return ""
        data = self._read(N)
        if len(data) != N:
            raise AssertionError("%s produced truncated output (requested %d, got %d)" % (self.name, N, len(data)))
        return data

    def _close(self):
        raise NotImplementedError("child class must implement this")

    def _read(self, N):
        raise NotImplementedError("child class must implement this")


# vim:set ts=4 sw=4 sts=4 expandtab:
