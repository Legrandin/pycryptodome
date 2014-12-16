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

import os
from ctypes import CDLL, byref, c_void_p, create_string_buffer

from Crypto.Util._modules import get_mod_name

raw_ecb_lib = CDLL(get_mod_name("Crypto.Cipher._raw_ecb"))

class RawEcbMode(object):
    """*Electronic Code Book (ECB)*.

    This is the simplest encryption mode. Each of the plaintext blocks
    is directly encrypted into a ciphertext block, independently of
    any other block.

    This mode is dangerous because it exposes frequency of symbols
    in your plaintext. Other modes (e.g. *CBC*) should be used instead.

    See `NIST SP800-38A`_ , Section 6.1 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, block_cipher):
        """Create a new block cipher, configured in ECB mode.

        :Parameters:
          block_cipher : C pointer
            A pointer to the low-level block cipher instance.
        """

        self._state = None
        state = c_void_p()
        result = raw_ecb_lib.ECB_start_operation(block_cipher,
                                                 byref(state))
        if result:
            raise ValueError("Error %d while instatiating the ECB mode" % result)
        self._state = state.value

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

        ciphertext = create_string_buffer(len(plaintext))
        result = raw_ecb_lib.ECB_encrypt(self._state, plaintext, ciphertext, len(plaintext))
        if result:
            raise ValueError("Error %d while encrypting in ECB mode" % result)
        return ciphertext.raw

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

        plaintext = create_string_buffer(len(ciphertext))
        result = raw_ecb_lib.ECB_decrypt(self._state, ciphertext, plaintext, len(ciphertext))
        if result:
            raise ValueError("Error %d while decrypting in ECB mode" % result)
        return plaintext.raw

    def __del__(self):
        if self._state:
            raw_ecb_lib.ECB_stop_operation(self._state)
            self._state  = None

def _create_ecb_cipher(factory, **kwargs):
    cipher_state, stop_op = factory._create_base_cipher(kwargs)
    try:
        if kwargs:
            raise ValueError("Unknown parameters for ECB: %s" % str(kwargs))
        return RawEcbMode(cipher_state)
    except:
        stop_op(cipher_state)
        raise
