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

"""ChaCha20 stream cipher

`ChaCha20`_ is a stream cipher designed by Daniel J. Bernstein.

The key is 256 bits long.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import ChaCha20
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = b'*Thirty-two byte (256 bits) key*'
    >>> iv = get_random_bytes(8)
    >>> cipher = ChaCha20.new(key, iv)
    >>> msg = iv + cipher.encrypt(b'Attack at dawn')

:undocumented: __package__

.. _ChaCha20: http://http://cr.yp.to/chacha.html
"""

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  create_string_buffer,
                                  get_raw_buffer, VoidPointer,
                                  SmartPointer, c_size_t,
                                  expect_byte_string, c_ulong)

_raw_chacha20_lib = load_pycryptodome_raw_lib("Crypto.Cipher._chacha20",
                    """
                    int chacha20_init(void **pState,
                                      const uint8_t *key,
                                      size_t keySize,
                                      const uint8_t *nonce,
                                      size_t nonceSize);

                    int chacha20_destroy(void *state);

                    int chacha20_encrypt(void *state,
                                         const uint8_t in[],
                                         uint8_t out[],
                                         size_t len);

                    int chacha20_seek(void *state,
                                      unsigned long block_high,
                                      unsigned long block_low,
                                      unsigned offset);
                    """)


class ChaCha20Cipher:
    """ChaCha20 cipher object"""

    block_size = 1

    def __init__(self, key, nonce):
        """Initialize a ChaCha20 cipher object

        See also `new()` at the module level."""

        expect_byte_string(key)
        expect_byte_string(nonce)

        self.nonce = nonce

        self._next = ( self.encrypt, self.decrypt )
        self._state = VoidPointer()
        result = _raw_chacha20_lib.chacha20_init(
                        self._state.address_of(),
                        key,
                        c_size_t(len(key)),
                        nonce,
                        c_size_t(len(nonce)))
        if result:
            raise ValueError("Error %d instantiating a ChaCha20 cipher")
        self._state = SmartPointer(self._state.get(),
                                   _raw_chacha20_lib.chacha20_destroy)

    def encrypt(self, plaintext):
        """Encrypt a piece of data.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt. It can be of any size.
        :Return: the encrypted data (byte string, as long as the
          plaintext).
        """

        if self.encrypt not in self._next:
            raise TypeError("Cipher object can only be used for decryption")
        self._next = ( self.encrypt, )
        return self._encrypt(plaintext)

    def _encrypt(self, plaintext):
        """Encrypt without FSM checks"""

        expect_byte_string(plaintext)
        ciphertext = create_string_buffer(len(plaintext))
        result = _raw_chacha20_lib.chacha20_encrypt(
                                         self._state.get(),
                                         plaintext,
                                         ciphertext,
                                         c_size_t(len(plaintext)))
        if result:
            raise ValueError("Error %d while encrypting with ChaCha20" % result)
        return get_raw_buffer(ciphertext)

    def decrypt(self, ciphertext):
        """Decrypt a piece of data.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt. It can be of any size.
        :Return: the decrypted data (byte string, as long as the
          ciphertext).
        """

        if self.decrypt not in self._next:
            raise TypeError("Cipher object can only be used for encryption")
        self._next = ( self.decrypt, )

        try:
            return self._encrypt(ciphertext)
        except ValueError, e:
            raise ValueError(str(e).replace("enc", "dec"))

    def seek(self, position):
        """Seek at a certain position in the key stream.

        :Parameters:
          position : integer
            The absolute position within the key stream, in bytes.
        """

        offset = position & 0x3f
        position >>= 6
        block_low = position & 0xFFFFFFFF
        block_high = position >> 32

        result = _raw_chacha20_lib.chacha20_seek(
                                                 self._state.get(),
                                                 c_ulong(block_high),
                                                 c_ulong(block_low),
                                                 offset
                                                 )
        if result:
            raise ValueError("Error %d while seeking with ChaCha20" % result)


def new(**kwargs):
    """Create a new ChaCha20 cipher

    :Keywords:
      key : byte string
        The secret key to use in the symmetric cipher.
        It must be 32 bytes long.
      nonce : byte string
        A mandatory value that must never be reused for any other encryption.
        It must be 8 bytes long.

    :Return: an `ChaCha20Cipher` object
    """

    try:
        key = kwargs.pop("key")
        nonce = kwargs.pop("nonce")
    except KeyError, e:
        raise TypeError("Missing parameter %s" % e)

    if len(key) != 32:
        raise ValueError("ChaCha20 key is 32 bytes long")
    if len(nonce) != 8:
        raise ValueError("ChaCha20 nonce is 8 bytes long")

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    return ChaCha20Cipher(key, nonce)

#: Size of a data block (in bytes)
block_size = 1

#: Size of a key (in bytes)
key_size = 32
