# -*- coding: utf-8 -*-
#
#  Cipher/mode_ctr.py : CTR mode
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
Counter (CTR) mode.
"""

from Crypto.Util import Counter

class ModeCTR(object):
    """*CounTeR (CTR)* mode.

    This mode is very similar to ECB, in that
    encryption of one block is done independently of all other blocks.

    Unlike ECB, the block *position* contributes to the encryption
    and no information leaks about symbol frequency.

    Each message block is associated to a *counter* which
    must be unique across all messages that get encrypted
    with the same key (not just within the same message).
    The counter is as big as the block size.

    Counters can be generated in several ways. The most
    straightword one is to choose an *initial counter block*
    (which can be made public, similarly to the *IV* for the
    other modes) and increment its lowest **m** bits by one
    (modulo *2^m*) for each block. In most cases, **m** is
    chosen to be half the block size.

    See `NIST SP800-38A`_ , Section 6.5 (for the mode) and
    Appendix B (for how to manage the *initial counter block*).

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in CTR mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.

        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.

          counter : callable
            A stateful function that returns the next *counter block*.
            A counter block is a byte string as long as the cipher
            block size.

            The *initial counter block* must not be reused.
            It shall contain a nonce or a random component.

            Reusing the *initial counter block* for encryptions
            performed with the same key compromises confidentiality.

            For better performance, use `Crypto.Util.Counter`.
        """

        #: The block size of the underlying cipher, in bytes.
        self.block_size = factory.block_size

        try:
            key = kwargs.pop("key")
            counter = kwargs.pop("counter")
        except KeyError, e:
            raise TypeError("Missing parameter: " + str(e))

        self._cipher = factory.new(key,
                                   factory.MODE_CTR,
                                   counter=counter,
                                   **kwargs)

    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

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
            It can be of any length.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        return self._cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

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
            It can be of any length.

        :Return: the decrypted data (byte string).
        """

        return self._cipher.decrypt(ciphertext)
