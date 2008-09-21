# -*- coding: utf-8 -*-
#
#  Random/__init__.py : PyCrypto random number generation
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
__all__ = ['new', 'RandomPoolCompat']

import OSRNG

def new(*args, **kwargs):
    """Return a file-like object that outputs cryptographically random bytes."""
    return OSRNG.new(*args, **kwargs)

class RandomPoolCompat:
    """RandomPool-like interface for Crypto.Random.

    Use this instead of Crypto.Util.randpool.RandomPool.
    """
    def __init__(self, numbytes = 160, cipher=None, hash=None, file=None):
        if file is None:
            self.__rng = new()
        else:
            self.__rng = file
        self.bytes = numbytes
        self.bits = self.bytes * 8
        self.entropy = self.bits

    def get_bytes(self, N):
        return self.__rng.read(N)

    def _updateEntropyEstimate(self, nbits):
        self.entropy += nbits
        if self.entropy < 0:
            self.entropy = 0
        elif self.entropy > self.bits:
            self.entropy = self.bits

    def _randomize(self, N=0, devname="/dev/urandom"):
        """Dummy _randomize() function"""
        self.__rng.flush()

    def randomize(self, N=0):
        """Dummy randomize() function"""
        self.__rng.flush()

    def stir(self, s=''):
        """Dummy stir() function"""
        self.__rng.flush()

    def stir_n(self, N=3):
        """Dummy stir_n() function"""
        self.__rng.flush()

    def add_event(self, s=''):
        """Dummy add_event() function"""
        self.__rng.flush()

    def getBytes(self, N):
        """Dummy getBytes() function"""
        return self.get_bytes(N)

    def addEvent(self, event, s=""):
        """Dummy addEvent() function"""
        return self.add_event()

# vim:set ts=4 sw=4 sts=4 expandtab:
