#
#  KDF.py : a collection of Key Derivation Functions
#
# Part of the Python Cryptography Toolkit
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

"""This file contains a collection of standard key derivation functions.

A key derivation function derives one or more secondary secret keys from
one primary secret (a master key or a pass phrase).

This is typically done to insulate the secondary keys from each other,
to avoid that leakage of a secondary key compromises the security of the
master key, or to thwart attacks on pass phrases (e.g. via rainbow tables).

:undocumented: __revision__
"""

__revision__ = "$Id$"

import math
import struct

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto.Hash import SHA1, HMAC, CMAC
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

def PBKDF1(password, salt, dkLen, count=1000, hashAlgo=None):
    """Derive one key from a password (or passphrase).

    This function performs key derivation according an old version of
    the PKCS#5 standard (v1.5).

    This algorithm is called ``PBKDF1``. Even though it is still described
    in the latest version of the PKCS#5 standard (version 2, or RFC2898),
    newer applications should use the more secure and versatile `PBKDF2` instead.

    :Parameters:
     password : string
        The secret password or pass phrase to generate the key from.
     salt : byte string
        An 8 byte string to use for better protection from dictionary attacks.
        This value does not need to be kept secret, but it should be randomly
        chosen for each derivation.
     dkLen : integer
        The length of the desired key. Default is 16 bytes, suitable for instance for `Crypto.Cipher.AES`.
     count : integer
        The number of iterations to carry out. It's recommended to use at least 1000.
     hashAlgo : module
        The hash algorithm to use, as a module or an object from the `Crypto.Hash` package.
        The digest length must be no shorter than ``dkLen``.
        The default algorithm is `SHA1`.

    :Return: A byte string of length `dkLen` that can be used as key.
    """
    if not hashAlgo:
        hashAlgo = SHA1
    password = tobytes(password)
    pHash = hashAlgo.new(password+salt)
    digest = pHash.digest_size
    if dkLen>digest:
        raise TypeError("Selected hash algorithm has a too short digest (%d bytes)." % digest)
    if len(salt)!=8:
        raise ValueError("Salt is not 8 bytes long.")
    for i in xrange(count-1):
        pHash = pHash.new(pHash.digest())
    return pHash.digest()[:dkLen]

def PBKDF2(password, salt, dkLen=16, count=1000, prf=None):
    """Derive one or more keys from a password (or passphrase).

    This performs key derivation according to the PKCS#5 standard (v2.0),
    by means of the ``PBKDF2`` algorithm.

    :Parameters:
     password : string
        The secret password or pass phrase to generate the key from.
     salt : string
        A string to use for better protection from dictionary attacks.
        This value does not need to be kept secret, but it should be randomly
        chosen for each derivation. It is recommended to be at least 8 bytes long.
     dkLen : integer
        The cumulative length of the desired keys. Default is 16 bytes, suitable for instance for `Crypto.Cipher.AES`.
     count : integer
        The number of iterations to carry out. It's recommended to use at least 1000.
     prf : callable
        A pseudorandom function. It must be a function that returns a pseudorandom string
        from two parameters: a secret and a salt. If not specified, HMAC-SHA1 is used.

    :Return: A byte string of length `dkLen` that can be used as key material.
        If you wanted multiple keys, just break up this string into segments of the desired length.
"""
    password = tobytes(password)
    if prf is None:
        prf = lambda p,s: HMAC.new(p,s,SHA1).digest()
    key = b('')
    i = 1
    while len(key)<dkLen:
        U = previousU = prf(password,salt+struct.pack(">I", i))
        for j in xrange(count-1):
            previousU = t = prf(password,previousU)
            U = strxor(U,t)
        key += U
        i = i + 1
    return key[:dkLen]

class _S2V(object):
    """String-to-vector PRF as defined in `RFC5297`_.

    This class implements a pseudorandom function family
    based on CMAC that takes as input a vector of strings.

    .. _RFC5297: http://tools.ietf.org/html/rfc5297
    """

    def __init__(self, key, ciphermod):
        """Initialize the S2V PRF.

        :Parameters:
          key : byte string
            A secret that can be used as key for CMACs
            based on ciphers from ``ciphermod``.
          ciphermod : module
            A block cipher module from `Crypto.Cipher`.
        """

        self._key = key
        self._ciphermod = ciphermod
        self._last_string = self._cache = bchr(0)*ciphermod.block_size
        self._n_updates = ciphermod.block_size*8-1

    def new(key, ciphermod):
        """Create a new S2V PRF.

        :Parameters:
          key : byte string
            A secret that can be used as key for CMACs
            based on ciphers from ``ciphermod``.
          ciphermod : module
            A block cipher module from `Crypto.Cipher`.
        """
        return _S2V(key, ciphermod)
    new = staticmethod(new)

    def _double(self, bs):
        doubled = bytes_to_long(bs)<<1
        if bord(bs[0]) & 0x80:
            doubled ^= 0x87
        return long_to_bytes(doubled, len(bs))[-len(bs):]

    def update(self, item):
        """Pass the next component of the vector.

        The maximum number of components you can pass is equal to the block
        length of the cipher (in bits) minus 1.

        :Parameters:
          item : byte string
            The next component of the vector.
        :Raise TypeError: when the limit on the number of components has been reached.
        :Raise ValueError: when the component is empty
        """

        if not item:
            raise ValueError("A component cannot be empty")

        if self._n_updates==0:
            raise TypeError("Too many components passed to S2V")
        self._n_updates -= 1

        mac = CMAC.new(self._key, msg=self._last_string, ciphermod=self._ciphermod)
        self._cache = strxor(self._double(self._cache), mac.digest())
        self._last_string = item

    def derive(self):
        """"Derive a secret from the vector of components.

        :Return: a byte string, as long as the block length of the cipher.
        """

        if len(self._last_string)>=16:
            final = self._last_string[:-16] + strxor(self._last_string[-16:], self._cache)
        else:
            padded = (self._last_string + bchr(0x80)+ bchr(0)*15)[:16]
            final = strxor(padded, self._double(self._cache))
        mac = CMAC.new(self._key, msg=final, ciphermod=self._ciphermod)
        return mac.digest()
