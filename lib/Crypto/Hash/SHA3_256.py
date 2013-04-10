# -*- coding: utf-8 -*-
# An implementation of the SHA-3 (Keccak) hash function family.
#
# Algorithm specifications: http://keccak.noekeon.org/
# NIST Announcement:
# http://csrc.nist.gov/groups/ST/hash/sha-3/winner_sha-3.html
#
# Written in 2013 by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
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

"""SHA3-256 cryptographic hash algorithm.

SHA3-256 belongs to the SHA-3 family of cryptographic hashes.
It produces the 256 bit digest of a message.

    >>> from Crypto.Hash import SHA3-256
    >>>
    >>> h = SHA3_256.new()
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

*SHA* stands for Secure Hash Algorithm.

.. Algorithm specifications: http://keccak.noekeon.org/
.. As of March 2013, NIST has not yet updated Secure Hash Standard
.. (SHS) for SHA-3. This module is subject to change once the final
.. standard is published.
"""

_revision__ = "$Id$"

__all__ = ['new', 'digest_size', 'SHA3_256Hash' ]

from Crypto.Util.py3compat import *
from Crypto.Hash.hashalgo import HashAlgo

from Crypto.Hash import _SHA3_256
hashFactory = _SHA3_256

class SHA3_256Hash(HashAlgo):
    """Class that implements a SHA3_256 hash
    
    :undocumented: block_size
    """

    #: ASN.1 Object identifier (OID)::
    #:
    #:
    #: This value uniquely identifies the SHA3_256 algorithm.
    oid = b('*-not yet assigned-*')

    digest_size = _SHA3_256.digest_size
    block_size = _SHA3_256.block_size

    def __init__(self, data=None):
        HashAlgo.__init__(self, hashFactory, data)

    def new(self, data=None):
        return SHA3_256Hash(data)

def new(data=None):
    """Return a fresh instance of the hash object.

    :Parameters:
       data : byte string
        The very first chunk of the message to hash.
        It is equivalent to an early call to `SHA3_256Hash.update()`.
        Optional.

    :Return: A `SHA3_256Hash` object
    """
    return SHA3_256Hash().new(data)

#: The size of the resulting hash in bytes.
digest_size = SHA3_256Hash.digest_size

#: The internal block size of the hash algorithm in bytes.
block_size = SHA3_256Hash.block_size

# vim:set ts=4 sw=4 sts=4 expandtab:

