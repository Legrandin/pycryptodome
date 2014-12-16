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

from ctypes import CDLL, byref, c_void_p, create_string_buffer

from Crypto.Util._modules import get_mod_name

raw_cfb_lib = CDLL(get_mod_name("Crypto.Cipher._raw_cfb"))

class RawCfbMode(object):
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

    def __init__(self, block_cipher, iv, segment_size):
        """Create a new block cipher, configured in CFB mode.

        :Parameters:
          block_cipher : C pointer
            A pointer to the low-level block cipher instance.

          iv : byte string
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            **The IV must be unpredictable**. Ideally it is picked randomly.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.

          segment_size : integer
            The number of bytes the plaintext and ciphertext are segmented in.
        """

        self._state = None
        state = c_void_p()
        result = raw_cfb_lib.CFB_start_operation(block_cipher,
                                                 iv,
                                                 len(iv),
                                                 segment_size,
                                                 byref(state))
        if result:
            raise ValueError("Error %d while instatiating the CFB mode" % result)
        self._state = state.value

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

        ciphertext = create_string_buffer(len(plaintext))
        result = raw_cfb_lib.CFB_encrypt(self._state, plaintext, ciphertext, len(plaintext))
        if result:
            raise ValueError("Error %d while encrypting in CBC mode" % result)
        return ciphertext.raw

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

        plaintext = create_string_buffer(len(ciphertext))
        result = raw_cfb_lib.CFB_decrypt(self._state, ciphertext, plaintext, len(ciphertext))
        if result:
            raise ValueError("Error %d while decrypting in CBC mode" % result)
        return plaintext.raw

    def __del__(self):
        if self._state:
            raw_cfb_lib.CFB_stop_operation(self._state)
            self._state  = None

def _create_cfb_cipher(factory, **kwargs):

    cipher_state, stop_op = factory._create_base_cipher(kwargs)
    try:
        iv = kwargs.pop("IV", None)
        if iv is None:
            iv = kwargs.pop("iv")

        segment_size_bytes, rem = divmod(kwargs.pop("segment_size", 8), 8)
        if rem:
            raise ValueError("'segment_size' must be a multiple of 8 bits")
        if segment_size_bytes == 0:
            segment_size_bytes = 1

        if kwargs:
            raise ValueError("Unknown parameters for CBC: %s" % str(kwargs))
        return RawCfbMode(cipher_state, iv, segment_size_bytes)
    except:
        stop_op(cipher_state)
        raise
