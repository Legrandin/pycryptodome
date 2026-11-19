# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""AEGIS-128L and AEGIS-256 authenticated encryption (RFC 10032)"""

from __future__ import annotations

from binascii import unhexlify
from hmac import compare_digest
from typing import Any, Literal, Optional, Union, overload

from Crypto import MessageTooLongError
from Crypto.Cipher._state_machine import Method
from Crypto.Random import get_random_bytes
from Crypto.Util import _cpu_features
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    create_output_buffer,
    create_string_buffer,
    get_raw_buffer,
    is_buffer,
    is_writeable_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util._typing import Buffer

__all__ = ["AegisCipher", "new", "MODE_128L", "MODE_256"]

MODE_128L: Literal[1] = 1  #: AEGIS-128L (16-byte key and nonce)
MODE_256: Literal[2] = 2  #: AEGIS-256 (32-byte key and nonce)

_names = {MODE_128L: "AEGIS-128L", MODE_256: "AEGIS-256"}
_key_sizes = {MODE_128L: 16, MODE_256: 32}

_cproto = """
        int AEGIS_init(unsigned variant,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       void **pState);
        int AEGIS_destroy(void *state);
        int AEGIS_update_ad(void *state, const uint8_t *in, size_t len);
        int AEGIS_encrypt(void *state, const uint8_t *in, uint8_t *out, size_t len);
        int AEGIS_decrypt(void *state, const uint8_t *in, uint8_t *out, size_t len);
        int AEGIS_digest(void *state, uint8_t *tag, size_t tag_len);
        """


def _load_lib(name: str, prefix: str) -> Any:
    """Load an AEGIS module, with its functions under the names without prefix"""

    lib = load_pycryptodome_raw_lib(name, _cproto.replace("AEGIS_", prefix))

    class _Lib:
        pass

    funcs = _Lib()
    for func in ("init", "destroy", "update_ad", "encrypt", "decrypt", "digest"):
        setattr(funcs, func, getattr(lib, prefix + func))
    return funcs


def _load_backends() -> dict[str, Any]:
    """The available implementations: ``portable`` (constant time, without
    AES instructions), and ``aesni`` or ``armv8`` if the CPU has AES instructions."""

    backends = {"portable": _load_lib("Crypto.Cipher._raw_aegis", "AEGIS_")}
    if _cpu_features.have_aes_ni():
        name, prefix, key = "Crypto.Cipher._raw_aegis_aesni", "AEGIS_AESNI_", "aesni"
    elif _cpu_features.have_aes_armv8():
        name, prefix, key = "Crypto.Cipher._raw_aegis_armv8", "AEGIS_ARMV8_", "armv8"
    else:
        return backends
    try:
        backends[key] = _load_lib(name, prefix)
    # The module may not have been compiled in
    except OSError:
        pass
    return backends


_backends = _load_backends()

# The fastest implementation (the last one)
_default_backend = list(_backends)[-1]


class AegisCipher:
    """AEGIS-128L or AEGIS-256 cipher object.
    Do not create it directly. Use :func:`new` instead.

    :var nonce: The nonce (16 bytes for AEGIS-128L, 32 bytes for AEGIS-256)
    :vartype nonce: bytes
    """

    nonce: bytes

    def __init__(self, key: Buffer, mode: int, nonce: Buffer, mac_len: int, backend: str) -> None:
        self._name = _names[mode]
        self._lib = _backends[backend]
        self._mac_len = mac_len
        self._mac_tag: Optional[bytes] = None
        self.nonce = bytes(nonce)

        self._next: tuple[Method, ...] = (
            Method.UPDATE,
            Method.ENCRYPT,
            Method.DECRYPT,
            Method.DIGEST,
            Method.VERIFY,
        )

        state = VoidPointer()
        key_ptr, key_len = c_uint8_ptr_len(key)
        nonce_ptr, nonce_len = c_uint8_ptr_len(nonce)
        result = self._lib.init(
            mode, key_ptr, c_size_t(key_len), nonce_ptr, c_size_t(nonce_len), state.address_of()
        )
        if result:
            raise ValueError("Error %d while initializing %s" % (result, self._name))
        self._state = SmartPointer(state.get(), self._lib.destroy)

    def update(self, assoc_data: Buffer) -> AegisCipher:
        """Protect the associated data.

        Associated data (also known as *additional authenticated data* - AAD)
        is the piece of the message that must stay in the clear, while
        still allowing the receiver to verify its integrity.
        An example is packet headers.

        The associated data (possibly split into multiple segments) is
        fed into :meth:`update` before any call to :meth:`decrypt` or :meth:`encrypt`.
        If there is no associated data, :meth:`update` is not called.

        :param bytes/bytearray/memoryview assoc_data:
            A piece of associated data. There are no restrictions on its size.
        """

        if Method.UPDATE not in self._next:
            raise TypeError("update() can only be called immediately after initialization")

        self._next = (Method.UPDATE, Method.ENCRYPT, Method.DECRYPT, Method.DIGEST, Method.VERIFY)

        data_ptr, data_len = c_uint8_ptr_len(assoc_data)
        result = self._lib.update_ad(self._state.get(), data_ptr, c_size_t(data_len))
        if result == 10:  # ERR_MAX_DATA
            raise MessageTooLongError("The associated data is too long for %s" % self._name)
        if result:
            raise ValueError("Error %d while processing the associated data" % result)
        return self

    def _crypt(self, func, data, output, what):
        if output is None:
            out = create_output_buffer(len(data))
        else:
            out = output
            if not is_writeable_buffer(output):
                raise TypeError("output must be a bytearray or a writeable memoryview")

        with c_uint8_ptr_out(out) as out_ptr:
            data_ptr, data_len = c_uint8_ptr_len(data)
            if len(out_ptr) != data_len:
                raise ValueError("output must have the same length as the input (%d bytes)" % data_len)
            result = func(self._state.get(), data_ptr, out_ptr, c_size_t(data_len))
        if result == 10:  # ERR_MAX_DATA
            raise MessageTooLongError("The %s is too long for %s" % (what, self._name))
        if result:
            raise ValueError("Error %d while processing the %s" % (result, what))

        if output is None:
            return get_raw_buffer(out)
        return None

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

        The message can be passed in pieces of any size, with several calls.

        Args:
          plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
        Keyword Args:
          output(bytearray/memoryview): The location where the ciphertext
            is written to. If ``None``, the ciphertext is returned.
        Returns:
          If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
          Otherwise, ``None``.
        """

        if Method.ENCRYPT not in self._next:
            raise TypeError("encrypt() can only be called after initialization or an update()")
        self._next = (Method.ENCRYPT, Method.DIGEST)
        return self._crypt(self._lib.encrypt, plaintext, output, "plaintext")

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

        The message can be passed in pieces of any size, with several calls.
        The plaintext must not be used before :meth:`verify` succeeds:
        prefer :meth:`decrypt_and_verify`.

        Args:
          ciphertext(bytes/bytearray/memoryview): The data to decrypt, of any size.
        Keyword Args:
          output(bytearray/memoryview): The location where the plaintext
            is written to. If ``None``, the plaintext is returned.
        Returns:
          If ``output`` is ``None``, the plaintext is returned as ``bytes``.
          Otherwise, ``None``.
        """

        if Method.DECRYPT not in self._next:
            raise TypeError("decrypt() can only be called after initialization or an update()")
        self._next = (Method.DECRYPT, Method.VERIFY)
        return self._crypt(self._lib.decrypt, ciphertext, output, "ciphertext")

    def _compute_mac(self) -> bytes:
        if self._mac_tag is None:
            tag = create_string_buffer(self._mac_len)
            result = self._lib.digest(self._state.get(), tag, c_size_t(self._mac_len))
            if result:
                raise ValueError("Error %d while computing the tag" % result)
            self._mac_tag = get_raw_buffer(tag)
        return self._mac_tag

    def digest(self) -> bytes:
        """Compute the *binary* authentication tag (MAC).

        :Return: the MAC tag, as ``bytes`` (16 or 32, see ``mac_len`` in :func:`new`).
        """

        if Method.DIGEST not in self._next:
            raise TypeError("digest() cannot be called when decrypting or validating a message")
        self._next = (Method.DIGEST,)
        return self._compute_mac()

    def hexdigest(self) -> str:
        """Compute the *printable* authentication tag (MAC).

        This method is like :meth:`digest`.

        :Return: the MAC tag, as a hexadecimal string.
        """

        return self.digest().hex()

    def verify(self, received_mac_tag: Buffer) -> None:
        """Validate the *binary* authentication tag (MAC).

        The receiver invokes this method at the very end, to
        check if the associated data (if any) and the decrypted
        messages are valid.

        :param bytes/bytearray/memoryview received_mac_tag:
            This is the *binary* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if Method.VERIFY not in self._next:
            raise TypeError("verify() cannot be called when encrypting a message")
        self._next = (Method.VERIFY,)

        if not is_buffer(received_mac_tag):
            raise TypeError("The MAC tag must be bytes, bytearray or memoryview")
        if not compare_digest(self._compute_mac(), bytes(received_mac_tag)):
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag: str) -> None:
        """Validate the *printable* authentication tag (MAC).

        This method is like :meth:`verify`.

        :param string hex_mac_tag:
            This is the *printable* MAC.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    @overload
    def encrypt_and_digest(self, plaintext: Buffer) -> tuple[bytes, bytes]: ...

    @overload
    def encrypt_and_digest(
        self, plaintext: Buffer, output: Union[bytearray, memoryview]
    ) -> tuple[None, bytes]: ...

    def encrypt_and_digest(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> tuple[Optional[bytes], bytes]:
        """Perform :meth:`encrypt` and :meth:`digest` in one step.

        Args:
          plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
        Keyword Args:
          output(bytearray/memoryview): The location where the ciphertext
            is written to. If ``None``, the ciphertext is returned.
        Returns:
          a tuple with the ciphertext (as ``bytes``, or ``None`` if ``output``
          is given) and the MAC tag.
        """

        return self.encrypt(plaintext, output=output), self.digest()

    @overload
    def decrypt_and_verify(self, ciphertext: Buffer, received_mac_tag: Buffer) -> bytes: ...

    @overload
    def decrypt_and_verify(
        self, ciphertext: Buffer, received_mac_tag: Buffer, output: Union[bytearray, memoryview]
    ) -> None: ...

    def decrypt_and_verify(
        self,
        ciphertext: Buffer,
        received_mac_tag: Buffer,
        output: Optional[Union[bytearray, memoryview]] = None,
    ) -> Optional[bytes]:
        """Perform :meth:`decrypt` and :meth:`verify` in one step.

        Args:
          ciphertext(bytes/bytearray/memoryview): The data to decrypt, of any size.
          received_mac_tag(bytes/bytearray/memoryview): The *binary* MAC,
            as received from the sender.
        Keyword Args:
          output(bytearray/memoryview): The location where the plaintext
            is written to. If ``None``, the plaintext is returned.
            If the MAC does not match, the location is filled with zeroes.
        Returns:
          If ``output`` is ``None``, the plaintext is returned as ``bytes``.
          Otherwise, ``None``.
        Raises:
          ValueError: if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        plaintext = self.decrypt(ciphertext, output=output)
        try:
            self.verify(received_mac_tag)
        except ValueError:
            # Do not leave unauthenticated plaintext in the output
            if output is not None:
                output[:] = bytes(len(output))
            raise
        return plaintext


def new(
    key: Buffer,
    mode: Literal[1, 2],
    *,
    nonce: Optional[Buffer] = None,
    mac_len: int = 16,
) -> AegisCipher:
    """Create a new AEGIS cipher object, for authenticated encryption.

    Args:
      key (bytes/bytearray/memoryview):
        The secret key: 16 bytes for AEGIS-128L, 32 bytes for AEGIS-256.
        It must be random (for instance, from :func:`Crypto.Random.get_random_bytes`).
      mode:
        :data:`MODE_128L` (AEGIS-128L) or :data:`MODE_256` (AEGIS-256).

    Keyword Args:
      nonce (bytes/bytearray/memoryview):
        A value that must never be reused for any other encryption
        done with this key: 16 bytes for AEGIS-128L, 32 bytes for AEGIS-256.
        If not provided, a random nonce is generated
        (you can find it back in the ``nonce`` attribute).
      mac_len (integer):
        The length of the authentication tag, in bytes: 16 (default) or 32.
        With a 32-byte tag, it is also infeasible to find another key and nonce
        for which the same associated data, ciphertext and tag are valid.

    Returns:
      an :class:`AegisCipher` object
    """

    if mode not in _names:
        raise ValueError("Unknown AEGIS mode: %r" % (mode,))
    if not is_buffer(key):
        raise TypeError("key must be bytes, bytearray or memoryview")
    key_size = _key_sizes[mode]
    if len(key) != key_size:
        raise ValueError("%s requires a key of %d bytes" % (_names[mode], key_size))

    if nonce is None:
        nonce = get_random_bytes(key_size)
    elif not is_buffer(nonce):
        raise TypeError("nonce must be bytes, bytearray or memoryview")
    if len(nonce) != key_size:
        raise ValueError("%s requires a nonce of %d bytes" % (_names[mode], key_size))

    if mac_len not in (16, 32):
        raise ValueError("The MAC tag must be 16 or 32 bytes long")

    return AegisCipher(key, mode, nonce, mac_len, _default_backend)
