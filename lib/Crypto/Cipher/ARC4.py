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

from __future__ import annotations

from collections.abc import Iterable
from typing import Union

from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_output_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]


_raw_arc4_lib = load_pycryptodome_raw_lib(
    "Crypto.Cipher._ARC4",
    """
                    int ARC4_stream_encrypt(void *rc4State, const uint8_t in[],
                                            uint8_t out[], size_t len);
                    int ARC4_stream_init(uint8_t *key, size_t keylen,
                                         void **pRc4State);
                    int ARC4_stream_destroy(void *rc4State);
                    """,
)


class ARC4Cipher:
    """ARC4 cipher object. Do not create it directly. Use
    :func:`Crypto.Cipher.ARC4.new` instead.
    """

    def __init__(self, key: Buffer, drop: int = 0) -> None:
        """Initialize an ARC4 cipher object

        See also `new()` at the module level."""

        if len(key) not in key_size:
            raise ValueError("Incorrect ARC4 key length (%d bytes)" % len(key))

        state = VoidPointer()
        key_ptr, key_len = c_uint8_ptr_len(key)
        result = _raw_arc4_lib.ARC4_stream_init(key_ptr, c_size_t(key_len), state.address_of())
        if result != 0:
            raise ValueError("Error %d while creating the ARC4 cipher" % result)
        self._state = SmartPointer(state.get(), _raw_arc4_lib.ARC4_stream_destroy)

        if drop > 0:
            # This is OK even if the cipher is used for decryption,
            # since encrypt and decrypt are actually the same thing
            # with ARC4.
            self.encrypt(b"\x00" * drop)

        self.block_size = 1
        self.key_size = len(key)

    def encrypt(self, plaintext: Buffer) -> bytes:
        """Encrypt a piece of data.

        :param plaintext: The data to encrypt, of any size.
        :type plaintext: bytes, bytearray, memoryview
        :returns: the encrypted byte string, of equal length as the
          plaintext.
        """

        ciphertext = create_output_buffer(len(plaintext))
        with c_uint8_ptr_out(ciphertext) as ciphertext_ptr:
            plaintext_ptr, plaintext_len = c_uint8_ptr_len(plaintext)
            # Check the lengths of the buffers that C code gets
            if len(ciphertext_ptr) != plaintext_len:
                raise ValueError("The plaintext changed length while being encrypted")
            result = _raw_arc4_lib.ARC4_stream_encrypt(
                self._state.get(), plaintext_ptr, ciphertext_ptr, c_size_t(plaintext_len)
            )
        if result:
            raise ValueError("Error %d while encrypting with RC4" % result)
        return get_raw_buffer(ciphertext)

    def decrypt(self, ciphertext: Buffer) -> bytes:
        """Decrypt a piece of data.

        :param ciphertext: The data to decrypt, of any size.
        :type ciphertext: bytes, bytearray, memoryview
        :returns: the decrypted byte string, of equal length as the
          ciphertext.
        """

        try:
            return self.encrypt(ciphertext)
        except ValueError as e:
            raise ValueError(str(e).replace("enc", "dec"))


def new(key: Buffer, drop: int = 0) -> ARC4Cipher:
    """Create a new ARC4 cipher.

    :param key:
        The secret key to use in the symmetric cipher.
        Its length must be in the range ``[1..256]``.
        The recommended length is 16 bytes.
    :type key: bytes, bytearray, memoryview

    :Keyword Arguments:
        *   *drop* (``integer``) --
            The amount of bytes to discard from the initial part of the keystream.
            In fact, such part has been found to be distinguishable from random
            data (while it shouldn't) and also correlated to key.

            The recommended value is 3072_ bytes. The default value is 0.

    :Return: an `ARC4Cipher` object

    .. _3072: http://eprint.iacr.org/2002/067.pdf
    """
    return ARC4Cipher(key, drop)


# Size of a data block (in bytes)
block_size: int = 1
# Size of a key (in bytes)
key_size: Iterable[int] = range(1, 256 + 1)
