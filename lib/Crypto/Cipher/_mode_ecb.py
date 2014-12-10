# -*- coding: utf-8 -*-
#
#  Cipher/mode_ecb.py : ECB mode
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

"""
Electronic Code Book (ECB) mode.
"""

class ModeECB(object):
    """*Electronic Code Book (ECB)*.

    This is the simplest encryption mode. Each of the plaintext blocks
    is directly encrypted into a ciphertext block, independently of
    any other block.

    This mode is dangerous because it exposes frequency of symbols
    in your plaintext. Other modes (e.g. *CBC*) should be used instead.

    See `NIST SP800-38A`_ , Section 6.1 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in ECB mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.

        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.
        """

        self.block_size = factory.block_size

        try:
            key = kwargs.pop("key")
        except KeyError, e:
            raise TypeError("Missing parameter: " + str(e))

        self._cipher = factory.new(key, factory.MODE_ECB, **kwargs)

    def encrypt(self, plaintext):
        """Encrypt data with the key set at initialization.

        The data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
            The length must be multiple of the cipher block length.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        return self._cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        """Decrypt data with the key set at initialization.

        The data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        This function does not remove any padding from the plaintext.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
            The length must be multiple of the cipher block length.

        :Return:
            the decrypted data (byte string).
            It is as long as *ciphertext*.
        """

        return self._cipher.decrypt(ciphertext)
