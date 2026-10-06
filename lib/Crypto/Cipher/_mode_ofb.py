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

from __future__ import annotations

from typing import Optional, Union, overload

__all__ = ["OfbMode"]
from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import copy_bytes
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_string_buffer,
    get_raw_buffer,
    is_writeable_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

raw_ofb_lib = load_pycryptodome_raw_lib(
    "Crypto.Cipher._raw_ofb",
    """
                        int OFB_start_operation(void *cipher,
                                                const uint8_t iv[],
                                                size_t iv_len,
                                                void **pResult);
                        int OFB_encrypt(void *ofbState,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                        int OFB_decrypt(void *ofbState,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                        int OFB_stop_operation(void *state);
                        """,
)


class OfbMode:
    """*Output FeedBack (OFB)*.

    This mode is very similar to CBC, but it
    transforms the underlying block cipher into a stream cipher.

    The keystream is the iterated block encryption of the
    previous ciphertext block.

    An Initialization Vector (*IV*) is required.

    See `NIST SP800-38A`_ , Section 6.4.

    .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

    :undocumented: __init__
    """

    def __init__(self, block_cipher: SmartPointer, iv: Buffer) -> None:
        """Create a new block cipher, configured in OFB mode.

        :Parameters:
          block_cipher : C pointer
            A smart pointer to the low-level block cipher instance.

          iv : bytes/bytearray/memoryview
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.

            **The IV must be a nonce, to to be reused for any other
            message**. It shall be a nonce or a random value.

            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.
        """

        state = VoidPointer()
        iv_ptr, iv_len = c_uint8_ptr_len(iv)
        result = raw_ofb_lib.OFB_start_operation(
            block_cipher.get(), iv_ptr, c_size_t(iv_len), state.address_of()
        )
        if result:
            raise ValueError("Error %d while instantiating the OFB mode" % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the cipher mode
        self._state = SmartPointer(state.get(), raw_ofb_lib.OFB_stop_operation)

        # Memory allocated for the underlying block cipher is now owed
        # by the cipher mode
        block_cipher.release()

        self.block_size = len(iv)
        """The block size of the underlying cipher, in bytes."""

        self.iv = copy_bytes(None, None, iv)
        """The Initialization Vector originally used to create the object.
        The value does not change."""

        self.IV = self.iv
        """Alias for `iv`"""

        self._next = ["encrypt", "decrypt"]

    @overload
    def encrypt(self, plaintext: Buffer) -> bytes: ...

    @overload
    def encrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
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
          plaintext : bytes/bytearray/memoryview
            The piece of data to encrypt.
            It can be of any length.
        :Keywords:
          output : bytearray/memoryview
            The location where the ciphertext must be written to.
            If ``None``, the ciphertext is returned.
        :Return:
          If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
          Otherwise, ``None``.
        """

        if "encrypt" not in self._next:
            raise TypeError("encrypt() cannot be called after decrypt()")
        self._next = ["encrypt"]

        if output is None:
            ciphertext = create_string_buffer(len(plaintext))
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
            result = raw_ofb_lib.OFB_encrypt(
                self._state.get(), plaintext_ptr, ciphertext_ptr, c_size_t(plaintext_len)
            )
        if result:
            raise ValueError("Error %d while encrypting in OFB mode" % result)

        if output is None:
            return get_raw_buffer(ciphertext)
        else:
            return None

    @overload
    def decrypt(self, ciphertext: Buffer) -> bytes: ...

    @overload
    def decrypt(self, ciphertext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    def decrypt(
        self, ciphertext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
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
          ciphertext : bytes/bytearray/memoryview
            The piece of data to decrypt.
            It can be of any length.
        :Keywords:
          output : bytearray/memoryview
            The location where the plaintext is written to.
            If ``None``, the plaintext is returned.
        :Return:
          If ``output`` is ``None``, the plaintext is returned as ``bytes``.
          Otherwise, ``None``.
        """

        if "decrypt" not in self._next:
            raise TypeError("decrypt() cannot be called after encrypt()")
        self._next = ["decrypt"]

        if output is None:
            plaintext = create_string_buffer(len(ciphertext))
        else:
            plaintext = output

            if not is_writeable_buffer(output):
                raise TypeError("output must be a bytearray or a writeable memoryview")

            if len(ciphertext) != len(output):
                raise ValueError("output must have the same length as the input  (%d bytes)" % len(plaintext))

        with c_uint8_ptr_out(plaintext) as plaintext_ptr:
            ciphertext_ptr, ciphertext_len = c_uint8_ptr_len(ciphertext)
            # Check the lengths of the buffers that C code gets
            if len(plaintext_ptr) != ciphertext_len:
                raise ValueError("output must have the same length as the input  (%d bytes)" % ciphertext_len)
            result = raw_ofb_lib.OFB_decrypt(
                self._state.get(), ciphertext_ptr, plaintext_ptr, c_size_t(ciphertext_len)
            )
        if result:
            raise ValueError("Error %d while decrypting in OFB mode" % result)

        if output is None:
            return get_raw_buffer(plaintext)
        else:
            return None


def _create_ofb_cipher(factory, **kwargs):
    """Instantiate a cipher object that performs OFB encryption/decryption.

    :Parameters:
      factory : module
        The underlying block cipher, a module from ``Crypto.Cipher``.

    :Keywords:
      iv : bytes/bytearray/memoryview
        The IV to use for OFB.

      IV : bytes/bytearray/memoryview
        Alias for ``iv``.

    Any other keyword will be passed to the underlying block cipher.
    See the relevant documentation for details (at least ``key`` will need
    to be present).
    """

    cipher_state = factory._create_base_cipher(kwargs)
    iv = kwargs.pop("IV", None)
    IV = kwargs.pop("iv", None)

    if (iv, IV) == (None, None):
        iv = get_random_bytes(factory.block_size)
    if iv is not None:
        if IV is not None:
            raise TypeError("You must either use 'iv' or 'IV', not both")
    else:
        iv = IV

    if len(iv) != factory.block_size:
        raise ValueError("Incorrect IV length (it must be %d bytes long)" % factory.block_size)

    if kwargs:
        raise TypeError("Unknown parameters for OFB: %s" % str(kwargs))

    return OfbMode(cipher_state, iv)
