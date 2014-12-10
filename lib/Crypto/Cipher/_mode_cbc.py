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

class ModeCBC(object):
    """*Cipher-Block Chaining (CBC)*.

    Each of the ciphertext blocks depends on the current
    and all previous plaintext blocks.

    An Initialization Vector (*IV*) is required.

    See `NIST SP800-38A`_ , Section 6.2 .

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    """

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in CBC mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.
        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.
          IV : byte string
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            The *IV* shall be unpredictable and it is best picked randomly.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.
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
            raise TypeError("Missing parameter: ", str(e))

        self._cipher = factory.new(key,
                                   factory.MODE_CBC,
                                   self.IV,
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
            Its length must be multiple of the cipher block size.

        :Return: the decrypted data (byte string).
        """

        return self._cipher.decrypt(ciphertext)
