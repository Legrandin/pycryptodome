# -*- coding: ascii -*-
#
#  FortunaAccumulator.py : Fortuna's internal accumulator
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

from binascii import b2a_hex
import time
import warnings

from Crypto.pct_warnings import ClockRewindWarning
import SHAd256

import FortunaGenerator

class FortunaPool(object):
    """Fortuna pool type

    This object acts like a hash object, with the following differences:

        - It keeps a count (the .length attribute) of the number of bytes that
          have been added to the pool
        - It supports a .reset() method for in-place reinitialization
        - The method to add bytes to the pool is .append(), not .update().
    """

    digest_size = SHAd256.digest_size

    def __init__(self):
        self.reset()

    def append(self, data):
        self._h.update(data)
        self.length += len(data)

    def digest(self):
        return self._h.digest()

    def hexdigest(self):
        return b2a_hex(self.digest())

    def reset(self):
        self._h = SHAd256.new()
        self.length = 0

def which_pools(r):
    """Return a list of pools indexes (in range(32)) that are to be included during reseed number r.

    According to _Practical Cryptography_, chapter 10.5.2 "Pools":

        "Pool P_i is included if 2**i is a divisor of r.  Thus P_0 is used
        every reseed, P_1 every other reseed, P_2 every fourth reseed, etc."
    """
    # This is a separate function so that it can be unit-tested.
    assert r >= 1
    retval = []
    mask = 0
    for i in range(32):
        # "Pool P_i is included if 2**i is a divisor of [reseed_count]"
        if (r & mask) == 0:
            retval.append(i)
        else:
            break   # optimization.  once this fails, it always fails
        mask = (mask << 1) | 1L
    return retval

class FortunaAccumulator(object):

    min_pool_size = 64      # TODO: explain why
    reseed_interval = 0.100   # 100 ms    TODO: explain why

    def __init__(self):
        self.reseed_count = 0
        self.generator = FortunaGenerator.AESGenerator()
        self.last_reseed = None

        # Initialize 32 FortunaPool instances.
        # NB: This is _not_ equivalent to [FortunaPool()]*32, which would give
        # us 32 references to the _same_ FortunaPool instance (and cause the
        # assertion below to fail).
        self.pools = [FortunaPool() for i in range(32)]     # 32 pools
        assert(self.pools[0] is not self.pools[1])

    def random_data(self, bytes):
        current_time = time.time()
        if self.last_reseed > current_time:
            warnings.warn("Clock rewind detected. Resetting last_reseed.", ClockRewindWarning)
            self.last_reseed = None
        if (self.pools[0].length >= self.min_pool_size and
            (self.last_reseed is None or
             current_time > self.last_reseed + self.reseed_interval)):
            self._reseed(current_time)
        # The following should fail if we haven't seeded the pool yet.
        return self.generator.pseudo_random_data(bytes)

    def _reseed(self, current_time=None):
        if current_time is None:
            current_time = time.time()
        seed = []
        self.reseed_count += 1
        self.last_reseed = current_time
        for i in which_pools(self.reseed_count):
            seed.append(self.pools[i].digest())
            self.pools[i].reset()

        seed = "".join(seed)
        self.generator.reseed(seed)

    def add_random_event(self, source_number, pool_number, data):
        assert 1 <= len(data) <= 32
        assert 0 <= source_number <= 255
        assert 0 <= pool_number <= 31
        self.pools[pool_number].append(chr(source_number))
        self.pools[pool_number].append(chr(len(data)))
        self.pools[pool_number].append(data)

# vim:set ts=4 sw=4 sts=4 expandtab:
