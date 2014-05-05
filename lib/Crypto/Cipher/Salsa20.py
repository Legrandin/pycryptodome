# -*- coding: utf-8 -*-
#
# Cipher/Salsa20.py : Salsa20 stream cipher (http://cr.yp.to/snuffle.html)
#
# Contributed by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>.
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
"""Salsa20 stream cipher

Salsa20 is a stream cipher submitted to eSTREAM project by Daniel J.
Bernstein.

:undocumented: __revision__, __package__
"""

__revision__ = "$Id$"

from Crypto.Cipher import _Salsa20

class Salsa20Cipher:
    """Salsa20 cipher object"""

    def __init__(self, key, *args, **kwargs):
        """Initialize a Salsa20 cipher object

        See also `new()` at the module level."""
        self._cipher = _Salsa20.new(key, *args, **kwargs)
        self.block_size = self._cipher.block_size
        self.key_size = self._cipher.key_size

    def encrypt(self, plaintext):
        """Encrypt a piece of data.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt. It can be of any size.
        :Return: the encrypted data (byte string, as long as the
          plaintext).
        """
        return self._cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        """Decrypt a piece of data.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt. It can be of any size.
        :Return: the decrypted data (byte string, as long as the
          ciphertext).
        """
        return self._cipher.decrypt(ciphertext)

def new(key, *args, **kwargs):
    """Create a new Salsa20 cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
      nonce : byte string
        A mandatory value that must never be reused for any other encryption.
        It must be 8 bytes long.

    :Return: an `Salsa20Cipher` object
    """
    return Salsa20Cipher(key, *args, **kwargs)

#: Size of a data block (in bytes)
block_size = 1

#: Size of a key (in bytes)
key_size = (16, 32)

# vim:set ts=4 sw=4 sts=4 expandtab:

