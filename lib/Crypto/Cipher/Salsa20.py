#
# Cipher/Salsa20.py : Salsa20 stream cipher (http://cr.yp.to/snuffle.html)
#
# Contributed by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>.
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

from typing import Optional, Union, overload

from Crypto import MessageTooLongError
from Crypto.Random import get_random_bytes
from Crypto.Util._cpu_features import load_avx2_bmi2_lib
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    c_ulong,
    create_output_buffer,
    get_raw_buffer,
    is_writeable_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

_salsa20_cdecl = """
                    int Salsa20_stream_init(uint8_t *key, size_t keylen,
                                            uint8_t *nonce, size_t nonce_len,
                                            void **pSalsaState);
                    int Salsa20_stream_destroy(void *salsaState);
                    int Salsa20_stream_encrypt(void *salsaState,
                                               const uint8_t in[],
                                               uint8_t out[], size_t len);
                    int Salsa20_stream_seek(void *salsaState,
                                            unsigned long block_high,
                                            unsigned long block_low,
                                            unsigned offset);
                    """

_raw_salsa20_portable_lib = load_pycryptodome_raw_lib("Crypto.Cipher._Salsa20", _salsa20_cdecl)

# The same code, with the key stream computed 8 blocks at a time (AVX2)
_raw_salsa20_avx2_bmi2_lib = load_avx2_bmi2_lib("Crypto.Cipher._Salsa20_avx2_bmi2", _salsa20_cdecl)

if _raw_salsa20_avx2_bmi2_lib is not None:
    _raw_salsa20_lib = _raw_salsa20_avx2_bmi2_lib
else:
    _raw_salsa20_lib = _raw_salsa20_portable_lib


class Salsa20Cipher:
    """Salsa20 cipher object. Do not create it directly. Use :py:func:`new`
    instead.

    :var nonce: The nonce with length 8
    :vartype nonce: byte string
    """

    def __init__(self, key: Buffer, nonce: Buffer) -> None:
        """Initialize a Salsa20 cipher object

        See also `new()` at the module level."""

        if len(key) not in key_size:
            raise ValueError("Incorrect key length for Salsa20 (%d bytes)" % len(key))

        if len(nonce) != 8:
            raise ValueError("Incorrect nonce length for Salsa20 (%d bytes)" % len(nonce))

        self.nonce = bytes(nonce)

        state = VoidPointer()
        key_ptr, key_len = c_uint8_ptr_len(key)
        nonce_ptr, nonce_len = c_uint8_ptr_len(nonce)
        result = _raw_salsa20_lib.Salsa20_stream_init(
            key_ptr, c_size_t(key_len), nonce_ptr, c_size_t(nonce_len), state.address_of()
        )
        if result:
            raise ValueError("Error %d instantiating a Salsa20 cipher")
        self._state = SmartPointer(state.get(), _raw_salsa20_lib.Salsa20_stream_destroy)

        self.block_size = 1
        self.key_size = len(key)

    @overload
    def encrypt(self, plaintext: Buffer) -> bytes: ...

    @overload
    def encrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    @overload
    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]: ...

    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        """Encrypt a piece of data.

        Args:
          plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
        Keyword Args:
          output(bytes/bytearray/memoryview): The location where the ciphertext
            is written to. If ``None``, the ciphertext is returned.
        Returns:
          If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
          Otherwise, ``None``.
        Raises:
          MessageTooLongError: (a ``ValueError`` and an ``OverflowError``)
            if the data goes beyond the end of the key stream
            (2**70 bytes); nothing is encrypted then.
        """

        if output is None:
            ciphertext = create_output_buffer(len(plaintext))
        else:
            ciphertext = output

            if not is_writeable_buffer(output):
                raise TypeError("output must be a bytearray or a writeable memoryview")

            if len(plaintext) != len(output):
                raise ValueError("output must have the same length as the input  (%d bytes)" % len(plaintext))

        with c_uint8_ptr_out(ciphertext) as ciphertext_ptr:
            plaintext_ptr, plaintext_len = c_uint8_ptr_len(plaintext)
            # Check the lengths of the buffers that C code gets
            if len(ciphertext_ptr) != plaintext_len:
                raise ValueError("output must have the same length as the input  (%d bytes)" % plaintext_len)
            result = _raw_salsa20_lib.Salsa20_stream_encrypt(
                self._state.get(), plaintext_ptr, ciphertext_ptr, c_size_t(plaintext_len)
            )
        if result == 10:  # ERR_MAX_DATA
            raise MessageTooLongError("The key stream of Salsa20 is exhausted (2**70 bytes per nonce)")
        if result:
            raise ValueError("Error %d while encrypting with Salsa20" % result)

        if output is None:
            return get_raw_buffer(ciphertext)
        else:
            return None

    @overload
    def decrypt(self, ciphertext: Buffer) -> bytes: ...

    @overload
    def decrypt(self, ciphertext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    @overload
    def decrypt(
        self, ciphertext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]: ...

    def decrypt(
        self, ciphertext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        """Decrypt a piece of data.

        Args:
          ciphertext(bytes/bytearray/memoryview): The data to decrypt, of any size.
        Keyword Args:
          output(bytes/bytearray/memoryview): The location where the plaintext
            is written to. If ``None``, the plaintext is returned.
        Returns:
          If ``output`` is ``None``, the plaintext is returned as ``bytes``.
          Otherwise, ``None``.
        Raises:
          MessageTooLongError: (a ``ValueError`` and an ``OverflowError``)
            if the data goes beyond the end of the key stream
            (2**70 bytes); nothing is decrypted then.
        """

        try:
            return self.encrypt(ciphertext, output=output)
        except MessageTooLongError:
            raise
        except ValueError as e:
            raise ValueError(str(e).replace("enc", "dec"))

    def seek(self, position: int) -> None:
        """Seek to a certain position in the key stream.

        The key stream is made of 64-byte blocks, numbered by a 64-bit counter.
        If you want to start from a certain block (that is,
        to set the initial block counter), use ``seek(block_number * 64)``.

        Args:
          position (integer):
            The absolute position within the key stream, in bytes.
            It must be in the range [0, 2**70).
        """

        if not 0 <= position < 2**70:
            raise ValueError("The position must be between 0 and 2**70 - 1")

        block_number, offset = divmod(position, 64)
        block_low = block_number & 0xFFFFFFFF
        block_high = block_number >> 32

        result = _raw_salsa20_lib.Salsa20_stream_seek(
            self._state.get(), c_ulong(block_high), c_ulong(block_low), offset
        )
        if result:
            raise ValueError("Error %d while seeking with Salsa20" % result)


def new(key: Buffer, nonce: Optional[Buffer] = None) -> Salsa20Cipher:
    """Create a new Salsa20 cipher

    :keyword key: The secret key to use. It must be 16 or 32 bytes long.
    :type key: bytes/bytearray/memoryview

    :keyword nonce:
        A value that must never be reused for any other encryption
        done with this key. It must be 8 bytes long.

        If not provided, a random byte string will be generated (you can read
        it back via the ``nonce`` attribute of the returned object).
    :type nonce: bytes/bytearray/memoryview

    :Return: a :class:`Crypto.Cipher.Salsa20.Salsa20Cipher` object
    """

    if nonce is None:
        nonce = get_random_bytes(8)

    return Salsa20Cipher(key, nonce)


# Size of a data block (in bytes)
block_size: int = 1

# Size of a key (in bytes)
key_size: tuple[int, int] = (16, 32)
