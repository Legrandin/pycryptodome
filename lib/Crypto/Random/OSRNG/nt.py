#
#  Random/OSRNG/nt.py : OS entropy source for MS Windows
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
__all__ = ['WindowsRNG']

import winrandom
from rng_base import BaseRNG

class WindowsRNG(BaseRNG):

    name = "<CryptGenRandom>"

    def __init__(self):
        self.__winrand = winrandom.new()
        BaseRNG.__init__(self)

    def flush(self):
        """Work around weakness in Windows RNG.

        The CryptGenRandom mechanism in some versions of Windows allows an
        attacker to learn 128 KiB of past and future output.  As a workaround,
        this function reads 128 KiB of 'random' data from Windows and discards
        it.

        For more information about the weaknesses in CryptGenRandom, see
        _Cryptanalysis of the Random Number Generator of the Windows Operating
        System_, by Leo Dorrendorf and Zvi Gutterman and Benny Pinkas
        http://eprint.iacr.org/2007/419
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        data = self.__winrand.get_bytes(128*1024)
        assert (len(data) == 128*1024)
        BaseRNG.flush(self)

    def _close(self):
        self.__winrand = None

    def _read(self, N):
        # Unfortunately, research shows that CryptGenRandom doesn't provide
        # forward secrecy and fails the next-bit test unless we apply a
        # workaround, which we do here.  See http://eprint.iacr.org/2007/419
        # for information on the vulnerability.
        self.flush()
        data = self.__winrand.get_bytes(N)
        self.flush()
        return data

def new(*args, **kwargs):
    return WindowsRNG(*args, **kwargs)

# vim:set ts=4 sw=4 sts=4 expandtab:
