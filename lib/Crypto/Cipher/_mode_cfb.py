# -*- coding: utf-8 -*-
#
#  Cipher/mode_cfb.py : CFB mode
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
Counter Feedback (CFB) mode.
"""

class ModeCFB(object):
    """*Cipher FeedBack (CFB)*.

    This mode is similar to CBC, but it transforms
    the underlying block cipher into a stream cipher.

    Plaintext and ciphertext are processed in *segments*
    of **s** bits. The mode is therefore sometimes
    labelled **s**-bit CFB.

    An Initialization Vector (*IV*) is required.

    See `NIST SP800-38A`_ , Section 6.3 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in CFB mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.

        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.

          IV : byte string
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            **The IV must be unpredictable**. Ideally it is picked randomly.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.

        segment_size : integer
            The number of bits the plaintext and ciphertext are segmented in.
            It must be a multiple of 8.
            If 0 or not specified, it will be assumed to be 8.
        """

        #: The block size of the underlying cipher, in bytes.
        self.block_size = factory.block_size

        #: The Initialization Vector originally used to create the object.
        #: The value does not change.
        self.IV = kwargs.pop("IV", None)

        try:
            key = kwargs.pop("key")
            if self.IV is None:
                self.IV = kwargs.pop("iv")
        except KeyError, e:
            raise TypeError("Missing parameter: " + str(e))

        self._cipher = factory.new(key, factory.MODE_CFB, self.IV, **kwargs)

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
