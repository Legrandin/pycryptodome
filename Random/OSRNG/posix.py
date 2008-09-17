#
#  Random/OSRNG/posix.py : OS entropy source for POSIX systems
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
__all__ = ['DevURandomRNG']

import os
import stat

from rng_base import BaseRNG

class DevURandomRNG(BaseRNG):

    def __init__(self, devname=None):
        if devname is None:
            self.name = "/dev/urandom"
        else:
            self.name = devname

        # Test that /dev/urandom is a character special device
        f = open(self.name, "rb", 0)
        fmode = os.fstat(f.fileno())[stat.ST_MODE]
        if not stat.S_ISCHR(fmode):
            f.close()
            raise TypeError("%r is not a character special device" % (self.name,))

        self.__file = f
        self._read = f.read

        BaseRNG.__init__(self)

    def _close(self):
        self.__file.close()

    def _read(self, N):
        return self.__file.read(N)

def new(*args, **kwargs):
    return DevURandomRNG(*args, **kwargs)


# vim:set ts=4 sw=4 sts=4 expandtab:
