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

"""
Ciphertext Block Chaining (CBC) mode.
"""

from ctypes import CDLL, byref, c_void_p, create_string_buffer

from Crypto.Util._modules import get_mod_name

raw_cbc_lib = CDLL(get_mod_name("Crypto.Cipher._raw_cbc"))


class RawCbcMode(object):
    """*Cipher-Block Chaining (CBC)*.

    Each of the ciphertext blocks depends on the current
    and all previous plaintext blocks.

    An Initialization Vector (*IV*) is required.

    See `NIST SP800-38A`_ , Section 6.2 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, block_cipher, iv):
        """Create a new block cipher, configured in CBC mode.

        :Parameters:
          block_cipher : C pointer
            A pointer to the low-level block cipher instance.

          iv : byte string
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            **The IV must be unpredictable**. Ideally it is picked randomly.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.
        """

        self._state = None
        state = c_void_p()
        result = raw_cbc_lib.CBC_start_operation(block_cipher,
                                                 iv,
                                                 len(iv),
                                                 byref(state))
        if result:
            raise ValueError("Error %d while instatiating the CBC mode"
                             % result)
        self._state = state.value

        #: The block size of the underlying cipher, in bytes.
        self.block_size = len(iv)

        #: The Initialization Vector originally used to create the object.
        #: The value does not change.
        self.IV = iv

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

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
            Its lenght must be multiple of the cipher block size.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        ciphertext = create_string_buffer(len(plaintext))
        result = raw_cbc_lib.CBC_encrypt(self._state, plaintext, ciphertext,
                                         len(plaintext))
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
            Its length must be multiple of the cipher block size.

        :Return: the decrypted data (byte string).
        """

        plaintext = create_string_buffer(len(ciphertext))
        result = raw_cbc_lib.CBC_decrypt(self._state, ciphertext, plaintext,
                                         len(ciphertext))
        if result:
            raise ValueError("Error %d while decrypting in CBC mode" % result)
        return plaintext.raw

    def __del__(self):
        if self._state:
            raw_cbc_lib.CBC_stop_operation(self._state)
            self._state = None


def _create_cbc_cipher(factory, **kwargs):

    cipher_state, stop_op = factory._create_base_cipher(kwargs)
    try:
        iv = kwargs.pop("IV", None)
        if iv is None:
            iv = kwargs.pop("iv")
        if kwargs:
            raise ValueError("Unknown parameters for CBC: %s" % str(kwargs))
        return RawCbcMode(cipher_state, iv)
    except:
        stop_op(cipher_state)
        raise
