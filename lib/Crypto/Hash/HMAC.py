#
# HMAC.py - Implements the HMAC algorithm as described by RFC 2104.
#
# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

"""HMAC (Hash-based Message Authentication Code) algorithm

HMAC is a MAC defined in RFC2104_ and FIPS-198_ and constructed using
a cryptograpic hash algorithm.
It is usually named *HMAC-X*, where *X* is the hash algorithm; for
instance *HMAC-SHA1* or *HMAC-MD5*.

The strength of an HMAC depends on:

 - the strength of the hash algorithm
 - the length and entropy of the secret key

This is an example showing how to *create* a MAC:

    >>> from Crypto.Hash import HMAC
    >>>
    >>> secret = b'Swordfish'
    >>> h = HMAC.new(secret)
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

This is an example showing how to *check* a MAC:

    >>> from Crypto.Hash import HMAC
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Swordfish'
    >>> h = HMAC.new(secret)
    >>> h.update(msg)
    >>> try:
    >>>   h.verify(mac)
    >>>   print "The message '%s' is authentic" % msg
    >>> except ValueError:
    >>>   print "The message or the key is wrong"

.. _RFC2104: http://www.ietf.org/rfc/rfc2104.txt
.. _FIPS-198: http://csrc.nist.gov/publications/fips/fips198/fips-198-1_final.pdf
"""

__all__ = ['new', 'HMAC']

from Crypto.Util.py3compat import b, bchr, bord, tobytes

from binascii import unhexlify

import MD5, BLAKE2s
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes


class HMAC:
    """Class that implements HMAC"""

    def __init__(self, key, msg=b(""), digestmod=None):
        """Create a new HMAC object.

        :Parameters:
          key : byte string
            secret key for the MAC object.
            It must be long enough to match the expected security level of the
            MAC. However, there is no benefit in using keys longer than the
            `digest_size` of the underlying hash algorithm.
          msg : byte string
            The very first chunk of the message to authenticate.
            It is equivalent to an early call to `update()`. Optional.
        :Parameter digestmod:
            The hash algorithm the HMAC is based on.
            Default is `Crypto.Hash.MD5`.
        :Type digestmod:
            A hash module or object instantiated from `Crypto.Hash`
        """

        if digestmod is None:
            digestmod = MD5

        if msg is None:
            msg = b("")

        #: Size of the MAC tag
        self.digest_size = digestmod.digest_size

        self._digestmod = digestmod

        try:
            if len(key) <= digestmod.block_size:
                # Step 1 or 2
                key_0 = key + bchr(0) * (digestmod.block_size - len(key))
            else:
                # Step 3
                hash_k = digestmod.new(key).digest()
                key_0 = hash_k + bchr(0) * (digestmod.block_size - len(hash_k))
        except AttributeError:
            # Not all hash types have "block_size"
            raise ValueError("Hash type incompatible to HMAC")

        # Step 4
        key_0_ipad = strxor(key_0, bchr(0x36) * len(key_0))

        # Start step 5 and 6
        self._inner = digestmod.new(key_0_ipad)
        self._inner.update(msg)

        # Step 7
        key_0_opad = strxor(key_0, bchr(0x5c) * len(key_0))

        # Start step 8 and 9
        self._outer = digestmod.new(key_0_opad)

    def update(self, msg):
        """Continue authentication of a message by consuming the next
        chunk of data.

        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments. In other words:

           >>> m.update(a); m.update(b)

        is equivalent to:

           >>> m.update(a+b)

        :Parameters:
          msg : byte string
            The next chunk of the message being authenticated
        """

        self._inner.update(msg)

    def copy(self):
        """Return a copy ("clone") of the MAC object.

        The copy will have the same internal state as the original MAC
        object.
        This can be used to efficiently compute the MAC of strings that
        share a common initial substring.

        :Returns: An `HMAC` object
        """

        new_hmac = HMAC(b("fake key"), digestmod=self._digestmod)

        # Syncronize the state
        new_hmac._inner = self._inner.copy()
        new_hmac._outer = self._outer.copy()

        return new_hmac

    def digest(self):
        """Return the **binary** (non-printable) MAC of the message that has
        been authenticated so far.

        This method does not change the state of the MAC object.
        You can continue updating the object after calling this function.

        :Return: A byte string of `digest_size` bytes. It may contain non-ASCII
            characters, including null bytes.
        """

        frozen_outer_hash = self._outer.copy()
        frozen_outer_hash.update(self._inner.digest())
        return frozen_outer_hash.digest()

    def verify(self, mac_tag):
        """Verify that a given **binary** MAC (computed by another party)
        is valid.

        :Parameters:
          mac_tag : byte string
            The expected MAC of the message.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        secret = get_random_bytes(16)

        mac1 = BLAKE2s.new(digest_bits=160, key=secret, data=mac_tag)
        mac2 = BLAKE2s.new(digest_bits=160, key=secret, data=self.digest())

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexdigest(self):
        """Return the **printable** MAC of the message that has been
        authenticated so far.

        This method does not change the state of the MAC object.

        :Return: A string of 2* `digest_size` bytes. It contains only
         hexadecimal ASCII digits.
        """
        return "".join(["%02x" % bord(x)
                        for x in tuple(self.digest())])

    def hexverify(self, hex_mac_tag):
        """Verify that a given **printable** MAC (computed by another party)
        is valid.

        :Parameters:
          hex_mac_tag : string
            The expected MAC of the message, as a hexadecimal string.
        :Raises ValueError:
            if the MAC does not match. It means that the message
            has been tampered with or that the MAC key is incorrect.
        """

        self.verify(unhexlify(tobytes(hex_mac_tag)))


def new(key, msg=b(""), digestmod=None):
    """Create a new HMAC object.

    :Parameters:
      key : byte string
        key for the MAC object.
        It must be long enough to match the expected security level of the
        MAC. However, there is no benefit in using keys longer than the
        *digest_size* of the underlying hash algorithm.
      msg : byte string
        The very first chunk of the message to authenticate.
        It is equivalent to an early call to `HMAC.update()`.
        Optional.
    :Parameter digestmod:
        The hash to use to implement the HMAC. Default is `Crypto.Hash.MD5`.
    :Type digestmod:
        A hash module or instantiated object from `Crypto.Hash`
    :Returns: An `HMAC` object
    """
    return HMAC(key, msg, digestmod)
