# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
XEX-based Tweaked-codebook mode with ciphertext Stealing (XTS).
"""

from __future__ import annotations

from hmac import compare_digest
from typing import Any, Optional, Union, overload

__all__ = ["XtsMode"]

from Crypto import MessageTooLongError
from Crypto.Cipher._state_machine import Method
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_output_buffer,
    get_raw_buffer,
    is_buffer,
    is_writeable_buffer,
    load_pycryptodome_raw_lib,
)

Buffer = Union[bytes, bytearray, memoryview]

raw_xts_lib = load_pycryptodome_raw_lib(
    "Crypto.Cipher._raw_xts",
    """
                    int XTS_start_operation(void *cipher,
                                            const uint8_t *encrypted_tweak,
                                            size_t tweak_len,
                                            void **pResult);
                    int XTS_encrypt(void *state,
                                    const uint8_t *in,
                                    uint8_t *out,
                                    size_t data_len);
                    int XTS_decrypt(void *state,
                                    const uint8_t *in,
                                    uint8_t *out,
                                    size_t data_len);
                    int XTS_stop_operation(void *state);
                    """,
)

# From src/errors.h
_ERR_NOT_ENOUGH_DATA = 3
_ERR_MAX_DATA = 10
_ERR_STATE = 20


class XtsMode:
    """*XEX-based Tweaked-codebook mode with ciphertext Stealing (XTS)*.

    This mode is meant for encrypting storage, where each data unit
    (such as a disk sector) is stored in place and cannot grow.
    It does not provide integrity.

    An object encrypts or decrypts one data unit.

    See `IEEE 1619`_ and `NIST SP 800-38E`_.

    .. _`IEEE 1619`: https://standards.ieee.org/ieee/1619/7168/
    .. _`NIST SP 800-38E`: https://csrc.nist.gov/pubs/sp/800/38/e/final
    """

    #: The tweak of the data unit.
    tweak: bytes

    def __init__(self, factory: Any, key: Buffer, tweak: Buffer, use_aesni: bool) -> None:
        """Create a new block cipher, configured in XTS mode.

        Args:
            factory (module):
                The underlying block cipher, a module from ``Crypto.Cipher``.
            key (bytes/bytearray/memoryview):
                The two AES keys, concatenated.
            tweak (bytes/bytearray/memoryview):
                The 16-byte tweak of the data unit.
            use_aesni (bool):
                Whether the AES instructions of the CPU can be used.
        """

        if len(key) not in (32, 64):
            raise ValueError("Incorrect key length for AES-XTS (%d bytes)" % len(key))

        half = len(key) // 2
        key_1, key_2 = key[:half], key[half:]

        # With two equal keys, XTS loses its security properties
        if compare_digest(key_1, key_2):
            raise ValueError("The two halves of an AES-XTS key must be different")

        if not is_buffer(tweak):
            raise TypeError("The tweak must be bytes, bytearray or memoryview")

        if len(tweak) != 16:
            raise ValueError("The tweak must be 16 bytes long in XTS mode")

        self.block_size = factory.block_size
        self.tweak = bytes(tweak)
        self._next = [Method.ENCRYPT, Method.DECRYPT]

        encrypted_tweak = factory.new(key_2, factory.MODE_ECB, use_aesni=use_aesni).encrypt(self.tweak)
        block_cipher = factory._create_base_cipher({"key": key_1, "use_aesni": use_aesni})

        state = VoidPointer()
        tweak_ptr, tweak_len = c_uint8_ptr_len(encrypted_tweak)
        result = raw_xts_lib.XTS_start_operation(
            block_cipher.get(), tweak_ptr, c_size_t(tweak_len), state.address_of()
        )
        if result:
            raise ValueError("Error %d while instantiating the XTS mode" % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the cipher mode
        self._state = SmartPointer(state.get(), raw_xts_lib.XTS_stop_operation)

        # Memory allocated for the underlying block cipher is now owned
        # by the cipher mode
        block_cipher.release()

    @overload
    def encrypt(self, plaintext: Buffer) -> bytes: ...

    @overload
    def encrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        """Encrypt (a piece of) the data unit.

        The data can be split over several calls: the length of each piece must
        be a multiple of 16 bytes, except for the last one, which can have any
        length above 16 bytes.
        The data unit must be at least 16 bytes long,
        and it cannot be longer than 16 MiB (2\\ :sup:`20` blocks).

        Args:
            plaintext (bytes/bytearray/memoryview):
                The piece of data to encrypt.
        Keyword Args:
            output (bytearray/memoryview):
                The location where the ciphertext must be written to.
                It can be the same buffer as ``plaintext``.
                If ``None``, the ciphertext is returned.
        Returns:
            If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
            Otherwise, ``None``.
        """

        if Method.ENCRYPT not in self._next:
            raise TypeError("encrypt() cannot be called after decrypt()")
        self._next = [Method.ENCRYPT]

        return self._process(raw_xts_lib.XTS_encrypt, plaintext, output, "encrypting")

    @overload
    def decrypt(self, ciphertext: Buffer) -> bytes: ...

    @overload
    def decrypt(self, ciphertext: Buffer, output: Union[bytearray, memoryview]) -> None: ...

    def decrypt(
        self, ciphertext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        """Decrypt (a piece of) the data unit.

        The data can be split over several calls: the length of each piece must
        be a multiple of 16 bytes, except for the last one, which can have any
        length above 16 bytes.
        The data unit must be at least 16 bytes long,
        and it cannot be longer than 16 MiB (2\\ :sup:`20` blocks).

        Args:
            ciphertext (bytes/bytearray/memoryview):
                The piece of data to decrypt.
        Keyword Args:
            output (bytearray/memoryview):
                The location where the plaintext must be written to.
                It can be the same buffer as ``ciphertext``.
                If ``None``, the plaintext is returned.
        Returns:
            If ``output`` is ``None``, the plaintext is returned as ``bytes``.
            Otherwise, ``None``.
        """

        if Method.DECRYPT not in self._next:
            raise TypeError("decrypt() cannot be called after encrypt()")
        self._next = [Method.DECRYPT]

        return self._process(raw_xts_lib.XTS_decrypt, ciphertext, output, "decrypting")

    def _process(
        self, function: Any, data: Buffer, output: Optional[Union[bytearray, memoryview]], what: str
    ) -> Optional[bytes]:
        if output is None:
            result_buffer = create_output_buffer(len(data))
        else:
            result_buffer = output

            if not is_writeable_buffer(output):
                raise TypeError("output must be a bytearray or a writeable memoryview")

            if len(data) != len(output):
                raise ValueError("output must have the same length as the input (%d bytes)" % len(data))

        with c_uint8_ptr_out(result_buffer) as result_ptr:
            data_ptr, data_len = c_uint8_ptr_len(data)
            # Check the lengths of the buffers that C code gets
            if len(result_ptr) != data_len:
                raise ValueError("output must have the same length as the input (%d bytes)" % data_len)
            result = function(self._state.get(), data_ptr, result_ptr, c_size_t(data_len))

        if result == _ERR_NOT_ENOUGH_DATA:
            raise ValueError("Each piece of data in XTS mode must be at least 16 bytes long")
        if result == _ERR_MAX_DATA:
            raise MessageTooLongError("A data unit in XTS mode cannot be longer than 16 MiB")
        if result == _ERR_STATE:
            raise TypeError("No more data after a piece whose length is not a multiple of 16 bytes")
        if result:
            raise ValueError("Error %d while %s in XTS mode" % (result, what))

        if output is None:
            return get_raw_buffer(result_buffer)
        return None


def _create_xts_cipher(factory, **kwargs):
    """Instantiate a cipher object that performs XTS encryption/decryption.

    Args:
        factory (module):
            The underlying block cipher, a module from ``Crypto.Cipher``.

    Keyword Args:
        key (bytes/bytearray/memoryview):
            The two AES keys, concatenated (32 or 64 bytes).
        tweak (bytes/bytearray/memoryview):
            The 16-byte tweak of the data unit.
        use_aesni (bool):
            Whether the AES instructions of the CPU can be used.
    """

    try:
        key = kwargs.pop("key")
    except KeyError as e:
        raise TypeError("Missing parameter:" + str(e))

    try:
        tweak = kwargs.pop("tweak")
    except KeyError:
        raise TypeError("Missing 'tweak' parameter: it must identify the data unit")

    use_aesni = kwargs.pop("use_aesni", True)

    if kwargs:
        raise TypeError("Unknown parameters for XTS: %s" % str(kwargs))

    return XtsMode(factory, key, tweak, use_aesni)
