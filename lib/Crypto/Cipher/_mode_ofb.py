# -*- coding: utf-8 -*-
#
#  Cipher/mode_ofb.py : OFB mode
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
Output Feedback (CFB) mode.
"""

from ctypes import byref, c_void_p, create_string_buffer

from Crypto.Util._modules import get_CDLL

raw_ofb_lib = get_CDLL("Crypto.Cipher._raw_ofb")


class RawOfbMode(object):
    """*Output FeedBack (OFB)*.

    This mode is very similar to CBC, but it
    transforms the underlying block cipher into a stream cipher.

    The keystream is the iterated block encryption of the
    previous ciphertext block.

    An Initialization Vector (*IV*) is required.

    See `NIST SP800-38A`_ , Section 6.4 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, block_cipher, iv):
        """Create a new block cipher, configured in OFB mode.

        :Parameters:
          block_cipher : C pointer
            A pointer to the low-level block cipher instance.

          iv: byte string
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            **The IV must be a nonce, to to be reused for any other
            message**. It shall be a nonce or a random value.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.
        """

        self._state = None
        state = c_void_p()
        result = raw_ofb_lib.OFB_start_operation(block_cipher,
                                                 iv,
                                                 len(iv),
                                                 byref(state))
        if result:
            raise ValueError("Error %d while instatiating the OFB mode"
                             % result)
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
        result = raw_ofb_lib.OFB_encrypt(self._state, plaintext, ciphertext,
                                         len(plaintext))
        if result:
            raise ValueError("Error %d while encrypting in OFB mode" % result)
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
        result = raw_ofb_lib.OFB_decrypt(self._state, ciphertext, plaintext,
                                         len(ciphertext))
        if result:
            raise ValueError("Error %d while decrypting in OFB mode" % result)
        return plaintext.raw

    def __del__(self):
        if self._state:
            raw_ofb_lib.OFB_stop_operation(self._state)
            self._state = None


def _create_ofb_cipher(factory, **kwargs):
    cipher_state, stop_op = factory._create_base_cipher(kwargs)
    try:
        iv = kwargs.pop("IV", None)
        if iv is None:
            iv = kwargs.pop("iv")
        if kwargs:
            raise ValueError("Unknown parameters for OFB: %s" % str(kwargs))
        return RawOfbMode(cipher_state, iv)
    except:
        stop_op(cipher_state)
        raise
