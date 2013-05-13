# -*- coding: utf-8 -*-
#
# Hash/CMAC.py - Implements the CMAC algorithm
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

"""CMAC (Cipher-based Message Authentication Code) algorithm

CMAC is a MAC defined in `NIST SP 800-38B`_ and in RFC4493_ (for AES only)
and constructed using a block cipher. It was originally known as `OMAC1`_.

The algorithm is sometimes named *X-CMAC* where *X* is the name
of the cipher (e.g. AES-CMAC).

This is an example showing how to *create* an AES-CMAC:

    >>> from Crypto.Hash import CMAC
    >>> from Crypto.Cipher import AES
    >>>
    >>> secret = b'Sixteen byte key'
    >>> cobj = CMAC.new(secret, ciphermod=AES)
    >>> cobj.update(b'Hello')
    >>> print cobj.hexdigest()

And this is an example showing how to *check* an AES-CMAC:

    >>> from Crypto.Hash import CMAC
    >>> from Crypto.Cipher import AES
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Sixteen byte key'
    >>> cobj = CMAC.new(secret, ciphermod=AES)
    >>> cobj.update(msg)
    >>> try:
    >>>   cobj.verify(mac)
    >>>   print "The message '%s' is authentic" % msg
    >>> except ValueError:
    >>>   print "The message or the key is wrong"

.. _`NIST SP 800-38B`: http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
.. _RFC4493: http://www.ietf.org/rfc/rfc4493.txt
.. _OMAC1: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
"""

__all__ = ['new', 'digest_size', 'CMAC' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from binascii import unhexlify

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

#: The size of the authentication tag produced by the MAC.
digest_size = None

def _shift_bytes(bs, xor_lsb=0):
    num = (bytes_to_long(bs)<<1) ^ xor_lsb
    return long_to_bytes(num, len(bs))[-len(bs):]

class CMAC(object):
    """Class that implements CMAC"""

    #: The size of the authentication tag produced by the MAC.
    digest_size = None

    def __init__(self, key, msg = None, ciphermod = None):
        """Create a new CMAC object.

        :Parameters:
          key : byte string
            secret key for the CMAC object.
            The key must be valid for the underlying cipher algorithm.
            For instance, it must be 16 bytes long for AES-128.
          msg : byte string
            The very first chunk of the message to authenticate.
            It is equivalent to an early call to `update`. Optional.
          ciphermod : module
            A cipher module from `Crypto.Cipher`.
            The cipher's block size must be 64 or 128 bits.
            It is recommended to use `Crypto.Cipher.AES`.
        """

        if ciphermod is None:
            raise ValueError("ciphermod must be specified (try AES)")

        self._key = key
        self._factory = ciphermod

        # Section 5.3 of NIST SP 800 38B
        if ciphermod.block_size==8:
            const_Rb = 0x1B
        elif ciphermod.block_size==16:
            const_Rb = 0x87
        else:
            raise ValueError("For CMAC, block length of the selected cipher must be 8 or 16 bytes")
        self.digest_size = ciphermod.block_size

        # MAC cache
        self._tag = None

        # Compute sub-keys
        cipher = ciphermod.new(key, ciphermod.MODE_ECB)
        l = cipher.encrypt(bchr(0)*ciphermod.block_size)
        if bord(l[0]) & 0x80:
            self._k1 = _shift_bytes(l, const_Rb)
        else:
            self._k1 = _shift_bytes(l)
        if bord(self._k1[0]) & 0x80:
            self._k2 = _shift_bytes(self._k1, const_Rb)
        else:
            self._k2 = _shift_bytes(self._k1)

        # Initialize CBC cipher with zero IV
        self._IV = bchr(0)*ciphermod.block_size
        self._cipherCBC = ciphermod.new(key, ciphermod.MODE_CBC, self._IV)

        self._buffer = []
        self._buffer_len = 0

        if msg is not None:
            self.update(msg)

    def update(self, msg):
        """Continue authentication of a message by consuming the next chunk of data.

        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments. In other words:

           >>> m.update(a); m.update(b)

        is equivalent to:

           >>> m.update(a+b)

        :Parameters:
          msg : byte string
            The next chunk of the message being authenticated
        """

        self._buffer += [ msg ]
        self._buffer_len += len(msg)

        # MAC data as you go but leave at least 1 byte in the buffer
        bsize = self._cipherCBC.block_size
        if self._buffer_len>bsize:
            data = b("").join(self._buffer)
            self._buffer_len = self._buffer_len&(bsize-1)
            if self._buffer_len==0:
                self._buffer_len=bsize
            self._buffer = [ data[-self._buffer_len:] ]
            self._IV = self._cipherCBC.encrypt(data[:-self._buffer_len])[-bsize:]

    def copy(self):
        """Return a copy ("clone") of the MAC object.

        The copy will have the same internal state as the original MAC
        object.
        This can be used to efficiently compute the MAC of strings that
        share a common initial substring.

        :Returns: A `CMAC` object
        """
        obj = CMAC(self._key, ciphermod=self._factory)

        # Deep copy
        for m in [ '_tag', '_buffer', '_buffer_len', '_k1', '_k2', '_IV']:
            setattr(obj, m, getattr(self, m))
        obj._cipherCBC = self._factory.new(self._key, self._factory.MODE_CBC, self._IV)
        return obj

    def digest(self):
        """Return the **binary** (non-printable) MAC of the message that has
        been authenticated so far.

        This method does not change the state of the MAC object.
        You can continue updating the object after calling this function.

        :Return: A byte string of `digest_size` bytes. It may contain non-ASCII
         characters, including null bytes.
        """

        if not self._tag:
            data = b("").join(self._buffer)
            bsize = self._cipherCBC.block_size
            if len(data)==bsize:
                last_block = strxor(data, self._k1)
            else:
                last_block = strxor(data+bchr(128)+bchr(0)*(bsize-1-len(data)), self._k2)
            self._tag = self._cipherCBC.encrypt(last_block)

        return self._tag

    def hexdigest(self):
        """Return the **printable** MAC of the message that has been
        authenticated so far.

        This method does not change the state of the MAC object.

        :Return: A string of 2* `digest_size` bytes. It contains only
         hexadecimal ASCII digits.
        """
        return "".join(["%02x" % bord(x)
                  for x in tuple(self.digest())])

    def verify(self, mac_tag):
        """Verify that a given **binary** MAC (computed by another party) is valid.

        :Parameters:
          mac_tag : byte string
            The expected MAC of the message.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        mac = self.digest()
        res = 0
        # Constant-time comparison
        for x,y in zip(mac, mac_tag):
            res |= bord(x) ^ bord(y)
        if res or len(mac_tag)!=self.digest_size:
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Verify that a given **printable** MAC (computed by another party) is valid.

        :Parameters:
          hex_mac_tag : string
            The expected MAC of the message, as a hexadecimal string.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

def new(key, msg = None, ciphermod = None):
    """Create a new CMAC object.

    :Parameters:
        key : byte string
            secret key for the CMAC object.
            The key must be valid for the underlying cipher algorithm.
            For instance, it must be 16 bytes long for AES-128.
        msg : byte string
            The very first chunk of the message to authenticate.
            It is equivalent to an early call to `CMAC.update`. Optional.
        ciphermod : module
            A cipher module from `Crypto.Cipher`.
            The cipher's block size must be 64 or 128 bits.
            Default is `Crypto.Cipher.AES`.

    :Returns: A `CMAC` object
    """
    return CMAC(key, msg, ciphermod)
