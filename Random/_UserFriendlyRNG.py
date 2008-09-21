# -*- coding: utf-8 -*-
#
#  Random/_UserFriendlyRNG.py : A user-friendly random number generator
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

from Crypto.Util.python_compat import *

import os
import threading

from Crypto.Random import OSRNG
from Crypto.Random.Fortuna import FortunaAccumulator

class _UserFriendlyRNG(object):

    def __init__(self):
        self.closed = False
        self._poolnum = 0
        self._fa = FortunaAccumulator.FortunaAccumulator()
        self.reinit()

    def reinit(self):
        """Initialize the random number generator and seed it with entropy from
        the operating system.
        """
        self._pid = os.getpid()
        self._osrng = OSRNG.new()

        # Add 256 bits to each of the 32 pools, twice.  (For a total of 16384
        # bits collected from the operating system.)
        for i in range(2):
            block = self._osrng.read(32*32)
            for p in range(32):
                self._fa.add_random_event(255, p, block[p*32:(p+1)*32])
            block = None
        self._osrng.flush()

    def close(self):
        self.closed = True
        self._osrng = None
        self._fa = None

    def flush(self):
        pass

    def read(self, N):
        """Return N bytes from the RNG."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not isinstance(N, (long, int)):
            raise TypeError("an integer is required")
        if N < 0:
            raise ValueError("cannot read to end of infinite stream")

        # Collect 64 bits of entropy from the operating system and feed it to Fortuna.
        self._fa.add_random_event(255, self._poolnum, self._osrng.read(8))
        self._poolnum = (self._poolnum + 1) & 31

        # Ask Fortuna to generate some bytes
        retval = self._fa.random_data(N)

        # Check that we haven't forked in the meantime.  (If we have, we don't
        # want to use the data, because it might have been duplicated in the
        # parent process.
        self._check_pid()

        # Return the random data.
        return retval

    def _check_pid(self):
        # Lame fork detection to remind the user not to use the same PRNG between forked processes.
        if os.getpid() != self._pid:
            raise AssertionError("PID check failed. RNG must be re-initialized after fork()")

class _LockingUserFriendlyRNG(_UserFriendlyRNG):
    def __init__(self):
        self._lock = threading.Lock()
        _UserFriendlyRNG.__init__(self)

    def close(self):
        self._lock.acquire()
        try:
            return _UserFriendlyRNG.close(self)
        finally:
            self._lock.release()

    def reinit(self):
        self._lock.acquire()
        try:
            return _UserFriendlyRNG.reinit(self)
        finally:
            self._lock.release()

    def read(self, bytes):
        self._lock.acquire()
        try:
            return _UserFriendlyRNG.read(self, bytes)
        finally:
            self._lock.release()

class RNGFile(object):
    def __init__(self, singleton):
        self.closed = False
        self._singleton = singleton

    # PEP 343: Support for the "with" statement
    def __enter__(self):
        """PEP 343 support"""
    def __exit__(self):
        """PEP 343 support"""
        self.close()

    def close(self):
        # Don't actually close the singleton, just close this RNGFile instance.
        self.closed = True
        self._singleton = None

    def read(self, bytes):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return self._singleton.read(bytes)

    def flush(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")

_singleton_lock = threading.Lock()
_singleton = None
def _get_singleton():
    global _singleton
    _singleton_lock.acquire()
    try:
        if _singleton is None:
            _singleton = _LockingUserFriendlyRNG()
        return _singleton
    finally:
        _singleton_lock.release()

def new():
    return RNGFile(_get_singleton())

def reinit():
    _get_singleton().reinit()

# vim:set ts=4 sw=4 sts=4 expandtab:
