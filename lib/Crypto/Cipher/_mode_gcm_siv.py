# SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
AES-GCM-SIV mode (RFC 8452).
"""

from __future__ import annotations

from binascii import unhexlify
from hmac import compare_digest
from struct import pack
from typing import TYPE_CHECKING, Any, Optional, Union, overload

__all__ = ["GcmSivMode"]

from Crypto import MessageTooLongError
from Crypto.Cipher._mode_gcm import (
    _GHASH,
    _ghash_clmul,
    _ghash_portable,
)
from Crypto.Cipher._state_machine import Method
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util._raw_api import is_buffer
from Crypto.Util._threads import threads_param
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor

if TYPE_CHECKING:
    from types import ModuleType

Buffer = Union[bytes, bytearray, memoryview]


# See RFC 8452, Section 6 (the ciphertext is 16 bytes longer, because of the tag)
_MAX_MSG_LEN = 2**36
_MAX_AAD_LEN = 2**36


def _mul_x_ghash(element: bytes) -> bytes:
    """Multiply an element of the GHASH field by x (RFC 8452, Appendix A)"""

    value = bytes_to_long(element)
    return long_to_bytes((value >> 1) ^ ((value & 1) * (0xE1 << 120)), 16)


class _Polyval:
    """POLYVAL function defined in RFC 8452, Section 3.

    It is computed with GHASH (Appendix A), which works in the same field but
    with the bits and the bytes of each element in the opposite order:

      POLYVAL(H, X_1, .., X_n) =
        ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), .., ByteReverse(X_n)))

    The C code takes care of reversing the blocks: GHASH must byte-swap each block
    for the carry-less multiplication, so here that step and the reversal cancel out.

    The input can be split in pieces of any size.
    """

    def __init__(self, subkey: bytes, ghash_c: Any, threads: int = 1) -> None:
        self._ghash = _GHASH(_mul_x_ghash(subkey[::-1]), ghash_c, threads, reversed_blocks=True)
        self._cache = b""

    def update(self, data: Buffer) -> None:
        view = memoryview(data)

        if self._cache:
            filler = 16 - len(self._cache)
            self._cache += bytes(view[:filler])
            view = view[filler:]
            if len(self._cache) < 16:
                return
            self._ghash.update(self._cache)
            self._cache = b""

        end = len(view) // 16 * 16
        if end > 0:
            self._ghash.update(view[:end])
        self._cache = bytes(view[end:])

    def pad(self) -> None:
        """Pad the data so far with zeroes, up to the next block boundary"""

        if self._cache:
            self.update(bytes(16 - len(self._cache)))

    def digest(self) -> bytes:
        assert not self._cache
        return self._ghash.digest()[::-1]


class GcmSivMode:
    """AES-GCM-SIV.

    This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
    It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed, and it will
    still be subject to authentication. The decryption step tells the receiver
    if the message comes from a source that really knows the secret key.
    Additionally, decryption detects if any part of the message - including the
    header - has been modified or corrupted.

    Unlike GCM, accidental reuse of a nonce is not catastrophic: the only
    effect is that an attacker can tell when the same plaintext (and same
    associated data) is protected with the same key and nonce.

    The nonce is always 12 bytes long, and the MAC tag 16 bytes.
    The key is 16 bytes long (*AES-128*) or 32 bytes long (*AES-256*).

    See `RFC8452`_.

    .. _RFC8452: https://www.rfc-editor.org/rfc/rfc8452
    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    """

    def __init__(
        self,
        factory: ModuleType,
        key: Buffer,
        nonce: Buffer,
        cipher_params: dict,
        ghash_c: Any,
        threads: int = 1,
    ) -> None:
        self.block_size = factory.block_size
        """The block size of the underlying cipher, in bytes."""

        if len(key) not in (16, 32):
            raise ValueError("Incorrect AES-GCM-SIV key length (%d bytes)" % len(key))

        if not is_buffer(nonce):
            raise TypeError("Nonce must be bytes, bytearray or memoryview")

        if len(nonce) != 12:
            raise ValueError("The nonce must be 12 bytes long")

        self.nonce = bytes(nonce)
        """The nonce originally used to create the object."""

        self._factory = factory
        self._cipher_params = cipher_params
        self._threads = threads_param(threads)
        self._tag: Optional[bytes] = None

        # Length of associated data
        self._auth_len = 0

        # RFC 8452, Section 4: the keys for this nonce are the first
        # 8 bytes of each encrypted block, 4 blocks for AES-128 and 6 for AES-256
        blocks = 4 if len(key) == 16 else 6
        kdf_in = b"".join(i.to_bytes(4, "little") + self.nonce for i in range(blocks))
        kdf_out = factory.new(key, factory.MODE_ECB, **cipher_params).encrypt(kdf_in)
        derived = b"".join(kdf_out[i * 16 : i * 16 + 8] for i in range(blocks))

        self._signer = _Polyval(derived[:16], ghash_c, self._threads)
        self._enc_key = derived[16:]

        # Allowed transitions after initialization
        self._next = [Method.UPDATE, Method.ENCRYPT, Method.DECRYPT, Method.DIGEST, Method.VERIFY]

    def _compute_tag(self, plaintext: Buffer) -> bytes:
        """Compute the tag (RFC 8452, Section 4). It can only be done once."""

        msg_len = len(plaintext)

        self._signer.pad()
        self._signer.update(plaintext)
        self._signer.pad()
        self._signer.update(pack("<QQ", self._auth_len * 8, msg_len * 8))
        s_s = self._signer.digest()

        tag_in = strxor(s_s[:12], self.nonce) + s_s[12:15] + bytes([s_s[15] & 0x7F])
        cipher = self._factory.new(self._enc_key, self._factory.MODE_ECB, **self._cipher_params)
        return cipher.encrypt(tag_in)

    def _create_ctr_cipher(self, tag: bytes) -> Any:
        """Create the cipher for the message (RFC 8452, Section 4).

        The counter is made up by the first 4 bytes of the block, in
        little endian. It starts at an arbitrary value, and it wraps around
        to zero (the limit on the size of the message guarantees that
        no counter value is used twice)."""

        counter = Counter.new(
            32,
            suffix=tag[4:15] + bytes([tag[15] | 0x80]),
            initial_value=int.from_bytes(tag[:4], "little"),
            little_endian=True,
        )
        return self._factory.new(
            self._enc_key,
            self._factory.MODE_CTR,
            counter=counter,
            threads=self._threads,
            **self._cipher_params,
        )

    def update(self, assoc_data: Buffer) -> GcmSivMode:
        """Protect associated data

        If there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt_and_verify`` or ``encrypt_and_digest``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        Args:
            assoc_data (bytes/bytearray/memoryview):
                A piece of associated data.
                In total, it cannot exceed 2\\ :sup:`36` bytes.
        """

        if Method.UPDATE not in self._next:
            raise TypeError("update() can only be called immediately after initialization")

        if self._auth_len + len(assoc_data) > _MAX_AAD_LEN:
            raise MessageTooLongError("Associated data exceeds maximum length")

        self._signer.update(assoc_data)
        self._auth_len += len(assoc_data)

        return self

    def encrypt(self, plaintext: Buffer) -> bytes:
        """
        For AES-GCM-SIV, encryption and MAC authentication must take place at the
        same point. This method shall not be used.

        Use `encrypt_and_digest` instead.
        """

        raise TypeError("encrypt() not allowed for GCM-SIV mode. Use encrypt_and_digest() instead.")

    def decrypt(self, ciphertext: Buffer) -> bytes:
        """
        For AES-GCM-SIV, decryption and verification must take place at the
        same point. This method shall not be used.

        Use `decrypt_and_verify` instead.
        """

        raise TypeError("decrypt() not allowed for GCM-SIV mode. Use decrypt_and_verify() instead.")

    def digest(self) -> bytes:
        """Compute the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        Returns:
            the MAC, as a byte string.
        """

        if Method.DIGEST not in self._next:
            raise TypeError("digest() cannot be called when decrypting or validating a message")
        self._next = [Method.DIGEST]

        if self._tag is None:
            self._tag = self._compute_tag(b"")
        return self._tag

    def hexdigest(self) -> str:
        """Compute the *printable* MAC tag.

        This method is like `digest`.

        Returns:
            the MAC, as a hexadecimal string.
        """
        return self.digest().hex()

    def verify(self, received_mac_tag: Buffer) -> None:
        """Validate the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method checks if the decrypted message is indeed valid
        (that is, if the key is correct) and it has not been
        tampered with while in transit.

        Args:
            received_mac_tag (bytes/bytearray/memoryview):
                This is the *binary* MAC, as received from the sender.
        Raises:
            ValueError:
                if the MAC does not match. The message has been tampered with
                or the key is incorrect.
        """

        if Method.VERIFY not in self._next:
            raise TypeError("verify() cannot be called when encrypting a message")
        self._next = [Method.VERIFY]

        if self._tag is None:
            self._tag = self._compute_tag(b"")

        if not compare_digest(self._tag, received_mac_tag):
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag: str) -> None:
        """Validate the *printable* MAC tag.

        This method is like `verify`.

        Args:
            hex_mac_tag (string):
                This is the *printable* MAC, as received from the sender.
        Raises:
            ValueError:
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
        """Perform encrypt() and digest() in one step.

        Args:
            plaintext (bytes/bytearray/memoryview):
                The data to encrypt.
                It cannot be longer than 2\\ :sup:`36` bytes.
        Keyword Args:
            output (bytearray/memoryview):
                The location where the ciphertext must be written to.
                If ``None``, the ciphertext is returned.
        Returns:
            The tuple ``(ciphertext, tag)``, both ``bytes``.
            The ciphertext is ``None`` when the ``output`` parameter
            specified a location for the result.
        """

        if Method.ENCRYPT not in self._next:
            raise TypeError("encrypt_and_digest() can only be called after initialization or an update()")
        if not is_buffer(plaintext):
            raise TypeError("The plaintext must be bytes, bytearray or memoryview")
        if len(plaintext) > _MAX_MSG_LEN:
            raise MessageTooLongError("Plaintext exceeds maximum length")
        self._next = [Method.DIGEST]

        self._tag = self._compute_tag(plaintext)

        return self._create_ctr_cipher(self._tag).encrypt(plaintext, output=output), self._tag

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
        """Perform decryption and verification in one step.

        Args:
            ciphertext (bytes/bytearray/memoryview):
                The data to decrypt, without the tag.
            received_mac_tag (bytes/bytearray/memoryview):
                This is the *binary* MAC, as received from the sender.
        Keyword Args:
            output (bytearray/memoryview):
                The location where the plaintext must be written to.
                If ``None``, the plaintext is returned.
                If the MAC does not match, the location is filled with zeroes.
        Returns:
            the plaintext as ``bytes`` or ``None`` when the ``output``
            parameter specified a location for the result.
        Raises:
            ValueError:
                if the MAC does not match. The message has been tampered with
                or the key is incorrect.
        """

        if Method.DECRYPT not in self._next:
            raise TypeError("decrypt_and_verify() can only be called after initialization or an update()")
        if not is_buffer(ciphertext) or not is_buffer(received_mac_tag):
            raise TypeError("The ciphertext and the MAC must be bytes, bytearray or memoryview")
        if len(ciphertext) > _MAX_MSG_LEN:
            raise MessageTooLongError("Ciphertext exceeds maximum length")

        # No further call is allowed if the MAC does not match
        self._next = []

        # The output may overlap with the MAC
        tag = bytes(received_mac_tag)
        if len(tag) != 16:
            raise ValueError("MAC check failed")

        plaintext = self._create_ctr_cipher(tag).decrypt(ciphertext, output=output)

        computed_tag = self._compute_tag(plaintext if output is None else output)
        if not compare_digest(computed_tag, tag):
            # RFC 8452, Section 9: unauthenticated plaintext must not be released
            if output is not None:
                output[:] = bytes(len(output))
            raise ValueError("MAC check failed")

        self._tag = computed_tag
        self._next = [Method.VERIFY]

        return plaintext


def _create_gcm_siv_cipher(factory, **kwargs):
    """Create a new AES cipher, configured in GCM-SIV mode.

    Args:
        factory (module):
            The module ``Crypto.Cipher.AES``.

    Keyword Args:
        key (bytes/bytearray/memoryview):
            The secret key to use in the symmetric cipher.
            It must be 16 (*AES-128*) or 32 (*AES-256*) bytes long.

        nonce (bytes/bytearray/memoryview):
            A value that should not be reused for any other encryption
            with this key. It must be 12 bytes long.

            If not provided, a 12 byte nonce will be randomly created.

        threads (integer):
            The maximum number of threads used to encrypt or decrypt long data
            (default: 1, no extra threads; 0 for all CPU cores).
    """

    try:
        key = kwargs.pop("key")
    except KeyError as e:
        raise TypeError("Missing parameter: " + str(e))

    nonce = kwargs.pop("nonce", None)
    if nonce is None:
        nonce = get_random_bytes(12)
    threads = kwargs.pop("threads", 1)

    # Not documented - only used for testing
    use_clmul = kwargs.pop("use_clmul", True)
    if use_clmul and _ghash_clmul:
        ghash_c = _ghash_clmul
    else:
        ghash_c = _ghash_portable

    return GcmSivMode(factory, key, nonce, kwargs, ghash_c, threads)
