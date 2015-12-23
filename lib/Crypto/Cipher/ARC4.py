# -*- coding: utf-8 -*-
#
#  Cipher/ARC4.py : ARC4
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
"""ARC4 symmetric cipher

ARC4_ (Alleged RC4) is an implementation of RC4 (Rivest's Cipher version 4),
a symmetric stream cipher designed by Ron Rivest in 1987.

The cipher started as a proprietary design, that was reverse engineered and
anonymously posted on Usenet in 1994. The company that owns RC4 (RSA Data
Inc.) never confirmed the correctness of the leaked algorithm.

Unlike RC2, the company has never published the full specification of RC4,
of whom it still holds the trademark.

ARC4 keys can vary in length from 40 to 2048 bits.

One problem of ARC4 is that it does not take a nonce or an IV.
If it is required to encrypt multiple messages with the same long-term key, a
distinct independent nonce must be created for each message, and a short-term
key must be derived from the combination of the long-term key and the nonce.
Due to the weak key scheduling algorithm of RC2, the combination must be
carried out with a complex function (e.g. a cryptographic hash) and not by
simply concatenating key and nonce.

**Use ChaCha20, not ARC4. This module is only provided for legacy purposes.**

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import ARC4
    >>> from Crypto.Hash import SHA
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = b'Very long and confidential key'
    >>> nonce = get_random_bytes(16)
    >>> tempkey = SHA.new(key+nonce).digest()
    >>> cipher = ARC4.new(tempkey)
    >>> msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')

.. _ARC4: http://en.wikipedia.org/wiki/RC4

:undocumented: __package__
"""

from Crypto.Util.py3compat import b

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer,
                                  create_string_buffer, get_raw_buffer,
                                  SmartPointer, c_size_t, expect_byte_string)


_raw_arc4_lib = load_pycryptodome_raw_lib("Crypto.Cipher._ARC4", """
                    int ARC4_stream_encrypt(void *rc4State, const uint8_t in[],
                                            uint8_t out[], size_t len);
                    int ARC4_stream_init(uint8_t *key, size_t keylen,
                                         void **pRc4State);
                    int ARC4_stream_destroy(void *rc4State);
                    """)


class ARC4Cipher:
    """ARC4 cipher object"""

    def __init__(self, key, *args, **kwargs):
        """Initialize an ARC4 cipher object

        See also `new()` at the module level."""

        if len(args) > 0:
            ndrop = args[0]
            args = args[1:]
        else:
            ndrop = kwargs.pop('drop', 0)

        if len(key) not in key_size:
            raise ValueError("Incorrect ARC4 key length (%d bytes)" %
                             len(key))

        expect_byte_string(key)

        self._state = VoidPointer()
        result = _raw_arc4_lib.ARC4_stream_init(key,
                                                c_size_t(len(key)),
                                                self._state.address_of())
        if result != 0:
            raise ValueError("Error %d while creating the ARC4 cipher"
                             % result)
        self._state = SmartPointer(self._state.get(),
                                   _raw_arc4_lib.ARC4_stream_destroy)

        if ndrop > 0:
            # This is OK even if the cipher is used for decryption,
            # since encrypt and decrypt are actually the same thing
            # with ARC4.
            self.encrypt(b('\x00') * ndrop)

        self.block_size = 1
        self.key_size = len(key)

    def encrypt(self, plaintext):
        """Encrypt a piece of data.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt. It can be of any size.
        :Return: the encrypted data (byte string, as long as the
          plaintext).
        """

        expect_byte_string(plaintext)
        ciphertext = create_string_buffer(len(plaintext))
        result = _raw_arc4_lib.ARC4_stream_encrypt(self._state.get(),
                                                   plaintext,
                                                   ciphertext,
                                                   c_size_t(len(plaintext)))
        if result:
            raise ValueError("Error %d while encrypting with RC4" % result)
        return get_raw_buffer(ciphertext)

    def decrypt(self, ciphertext):
        """Decrypt a piece of data.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt. It can be of any size.
        :Return: the decrypted data (byte string, as long as the
          ciphertext).
        """
        try:
            return self.encrypt(ciphertext)
        except ValueError, e:
            raise ValueError(str(e).replace("enc", "dec"))


def new(key, *args, **kwargs):
    """Create a new ARC4 cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        Its length must be in the range ``[5..256]``.
        The recommended length is 16 bytes.

    :Keywords:
      drop : integer
        The amount of bytes to discard from the initial part of the keystream.
        In fact, such part has been found to be distinguishable from random
        data (while it shouldn't) and also correlated to key.

        The recommended value is 3072_ bytes. The default value is 0.

    :Return: an `ARC4Cipher` object

    .. _3072: http://eprint.iacr.org/2002/067.pdf
    """
    return ARC4Cipher(key, *args, **kwargs)

#: Size of a data block (in bytes)
block_size = 1
#: Size of a key (in bytes)
key_size = xrange(5, 256+1)
