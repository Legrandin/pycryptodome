# -*- coding: utf-8 -*-
#
#  Random/__init__.py : PyCrypto random number generation
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

__revision__ = "$Id$"
__all__ = ['new', 'RandomPoolCompat']

import OSRNG
import _UserFriendlyRNG

def new(*args, **kwargs):
    """Return a file-like object that outputs cryptographically random bytes."""
    return _UserFriendlyRNG.new(*args, **kwargs)

def atfork():
    """Call this whenever you call os.fork()"""
    _UserFriendlyRNG.reinit()

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
