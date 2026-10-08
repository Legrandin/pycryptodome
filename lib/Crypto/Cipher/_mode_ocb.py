# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
Offset Codebook (OCB) mode.

OCB is Authenticated Encryption with Associated Data (AEAD) cipher mode
designed by Prof. Phillip Rogaway and specified in `RFC7253`_.

The algorithm provides both authenticity and privacy, it is very efficient,
it uses only one key and it can be used in online mode (so that encryption
or decryption can start before the end of the message is available).

This module implements the third and last variant of OCB (OCB3) and it only
works in combination with a 128-bit block symmetric cipher, like AES.

OCB was patented in USA but the author eventually `abandoned`_ the patents.

Example:
    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = get_random_bytes(32)
    >>> cipher = AES.new(key, AES.MODE_OCB)
    >>> plaintext = b"Attack at dawn"
    >>> ciphertext, mac = cipher.encrypt_and_digest(plaintext)
    >>> # Deliver cipher.nonce, ciphertext and mac
    ...
    >>> cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    >>> try:
    >>>     plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    >>> except ValueError:
    >>>     print "Invalid message"
    >>> else:
    >>>     print plaintext

:undocumented: __package__

.. _RFC7253: http://www.rfc-editor.org/info/rfc7253
.. _abandoned: https://mailarchive.ietf.org/arch/msg/cfrg/qLTveWOdTJcLn4HP3ev-vrj05Vg/
"""

from __future__ import annotations

from binascii import unhexlify
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from Crypto.Cipher._state_machine import Method
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes
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
    load_pycryptodome_raw_lib,
)
from Crypto.Util._threads import range_boundaries, run_in_threads, threads_param
from Crypto.Util.strxor import strxor

if TYPE_CHECKING:
    from types import ModuleType

Buffer = Union[bytes, bytearray, memoryview]

_raw_ocb_lib = load_pycryptodome_raw_lib(
    "Crypto.Cipher._raw_ocb",
    """
                                    int OCB_start_operation(void *cipher,
                                        const uint8_t *nonce,
                                        size_t nonce_len,
                                        size_t tag_len,
                                        void **pState);
                                    int OCB_encrypt(void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                                    int OCB_decrypt(void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                                    int OCB_update(void *state,
                                        const uint8_t *in,
                                        size_t data_len);
                                    int OCB_encrypt_at(const void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t offset,
                                        size_t data_len,
                                        uint8_t *checksum);
                                    int OCB_decrypt_at(const void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t offset,
                                        size_t data_len,
                                        uint8_t *checksum);
                                    int OCB_skip(void *state,
                                        size_t data_len,
                                        const uint8_t *checksum);
                                    int OCB_digest(void *state,
                                        uint8_t *tag,
                                        size_t tag_len);
                                    int OCB_stop_operation(void *state);
                                    """,
)

# Minimum amount of data (1 MiB) that each thread must process:
# with less, starting the thread costs more than what it saves.
_MIN_BYTES_PER_THREAD = 1024 * 1024


def _process_threaded(
    state: Any, at_func: Callable[..., int], in_ptr: Any, out_ptr: Any, data_len: int, threads: int
) -> int:
    """Encrypt or decrypt ``data_len`` bytes by splitting them into ``threads``
    contiguous ranges, which are processed in parallel.
    Each range starts at a block boundary: if ``data_len`` is not a multiple
    of 16, the last range ends with the last piece of the message.

    ``at_func`` (``OCB_encrypt_at`` or ``OCB_decrypt_at``) processes one range,
    without changing the state, and returns its share of the checksum,
    which is an XOR over all blocks. Then, the state moves past all ranges.

    :return: the error code of the C library (0 for success)

    ``state``, ``in_ptr`` and ``out_ptr`` are C pointers, whose types depend
    on the backend (cffi or ctypes): see :mod:`Crypto.Util._raw_api`.
    """

    bounds = range_boundaries(data_len, threads, 16)
    partials = [create_string_buffer(16) for _ in range(threads)]

    def worker(i: int) -> int:
        start, end = bounds[i], bounds[i + 1]
        return at_func(state, in_ptr, out_ptr, c_size_t(start), c_size_t(end - start), partials[i])

    results: list[int] = []
    try:
        results = run_in_threads(worker, threads)
    finally:
        # Move the state forward even after an error in a thread (some ranges
        # may be processed already), so that the same offsets are not used again
        checksum = bytes(16)
        for partial in partials:
            checksum = strxor(checksum, get_raw_buffer(partial))
        skip_result = _raw_ocb_lib.OCB_skip(state, c_size_t(data_len), checksum)

    # Report the first error of a thread, if any
    for result in results:
        if result:
            return result
    return skip_result


class OcbMode:
    """Offset Codebook (OCB) mode.

    :undocumented: __init__
    """

    def __init__(
        self, factory: ModuleType, nonce: Buffer, mac_len: int, cipher_params: dict, threads: int = 1
    ) -> None:
        if factory.block_size != 16:
            raise ValueError("OCB mode is only available for ciphers that operate on 128 bits blocks")

        self.block_size = 16
        """The block size of the underlying cipher, in bytes."""

        self.nonce = bytes(nonce)
        """Nonce used for this session."""
        if len(nonce) not in range(1, 16):
            raise ValueError("Nonce must be at most 15 bytes long")
        if not is_buffer(nonce):
            raise TypeError("Nonce must be bytes, bytearray or memoryview")

        self._mac_len = mac_len
        self._threads = threads_param(threads)
        if not 8 <= mac_len <= 16:
            raise ValueError("MAC tag must be between 8 and 16 bytes long")

        # Cache for MAC tag
        self._mac_tag: Optional[bytes] = None

        # Cache for unaligned associated data
        self._cache_A = b""

        # Cache for unaligned ciphertext/plaintext
        self._cache_P = b""

        # Allowed transitions after initialization
        self._next = [Method.UPDATE, Method.ENCRYPT, Method.DECRYPT, Method.DIGEST, Method.VERIFY]

        # Create low-level cipher instance
        raw_cipher = factory._create_base_cipher(cipher_params)
        if cipher_params:
            raise TypeError("Unknown keywords: " + str(cipher_params))

        state = VoidPointer()
        result = _raw_ocb_lib.OCB_start_operation(
            raw_cipher.get(),
            self.nonce,
            c_size_t(len(self.nonce)),
            c_size_t(self._mac_len),
            state.address_of(),
        )
        if result:
            raise ValueError("Error %d while instantiating the OCB mode" % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the cipher mode
        self._state = SmartPointer(state.get(), _raw_ocb_lib.OCB_stop_operation)

        # Memory allocated for the underlying block cipher is now owed
        # by the cipher mode
        raw_cipher.release()

    def _update(self, assoc_data: memoryview) -> None:
        assoc_data_ptr, assoc_data_len = c_uint8_ptr_len(assoc_data)
        result = _raw_ocb_lib.OCB_update(self._state.get(), assoc_data_ptr, c_size_t(assoc_data_len))
        if result:
            raise ValueError("Error %d while computing MAC in OCB mode" % result)

    def update(self, assoc_data: Buffer) -> OcbMode:
        """Process the associated data.

        If there is any associated data, the caller has to invoke
        this method one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver shall still able to detect modifications.

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : bytes/bytearray/memoryview
            A piece of associated data.
        """

        if Method.UPDATE not in self._next:
            raise TypeError("update() can only be called immediately after initialization")

        self._next = [Method.ENCRYPT, Method.DECRYPT, Method.DIGEST, Method.VERIFY, Method.UPDATE]

        if len(self._cache_A) > 0:
            filler = min(16 - len(self._cache_A), len(assoc_data))
            self._cache_A += bytes(assoc_data[:filler])
            assoc_data = assoc_data[filler:]

            if len(self._cache_A) < 16:
                return self

            # Clear the cache, and proceeding with any other aligned data
            self._cache_A, seg = b"", self._cache_A
            self.update(seg)

        update_len = len(assoc_data) // 16 * 16
        self._cache_A = bytes(assoc_data[update_len:])
        # The view locks the buffer, but another thread may have shrunk it
        # after update_len was computed: the view is then shorter
        view = memoryview(assoc_data)[:update_len]
        if len(view) != update_len:
            raise ValueError("The associated data changed while being processed")
        self._update(view)
        return self

    def _process_all(self, in_data, in_data_len, c_func, c_desc):
        """Encrypt or decrypt all the in_data_len bytes at once, into a new
        buffer (unlike _process_incremental, no bytes are kept for later).
        If in_data_len is not a multiple of 16, they end with the last
        piece of the message."""

        out_data = create_output_buffer(in_data_len)
        threads = min(self._threads, in_data_len // _MIN_BYTES_PER_THREAD)
        with c_uint8_ptr_out(out_data) as out_data_ptr:
            if threads > 1:
                at_func = getattr(_raw_ocb_lib, "OCB_%s_at" % c_desc)
                result = _process_threaded(
                    self._state.get(), at_func, in_data, out_data_ptr, in_data_len, threads
                )
            else:
                result = c_func(self._state.get(), in_data, out_data_ptr, c_size_t(in_data_len))
        if result:
            raise ValueError("Error %d while %sing in OCB mode" % (result, c_desc))
        return get_raw_buffer(out_data)

    def _process_incremental(self, in_data, c_func, c_desc):
        """Encrypt or decrypt the next piece of the message.
        Only whole blocks are processed: the bytes left over are kept
        until the next call. With in_data None (the end of the message),
        process the bytes left over."""

        # Last piece to encrypt/decrypt
        if in_data is None:
            out_data = self._process_all(self._cache_P, len(self._cache_P), c_func, c_desc)
            self._cache_P = b""
            return out_data

        # Try to fill up the cache, if it already contains something
        prefix = b""
        if len(self._cache_P) > 0:
            filler = min(16 - len(self._cache_P), len(in_data))
            self._cache_P += bytes(in_data[:filler])
            in_data = in_data[filler:]

            if len(self._cache_P) < 16:
                # We could not manage to fill the cache, so there is certainly
                # no output yet.
                return b""

            # Clear the cache, and proceeding with any other aligned data
            prefix = self._process_all(self._cache_P, len(self._cache_P), c_func, c_desc)
            self._cache_P = b""

        # Process data in multiples of the block size
        in_data_ptr, in_data_len = c_uint8_ptr_len(in_data)
        whole_blocks_len = in_data_len // 16 * 16
        result = self._process_all(in_data_ptr, whole_blocks_len, c_func, c_desc)
        if prefix:
            result = prefix + result

        # Left-over
        self._cache_P = bytes(in_data[whole_blocks_len:])

        return result

    def encrypt(self, plaintext: Optional[Buffer] = None) -> bytes:
        """Encrypt the next piece of plaintext.

        After the entire plaintext has been passed (but before `digest`),
        you **must** call this method one last time with no arguments to collect
        the final piece of ciphertext.

        If possible, use the method `encrypt_and_digest` instead.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The next piece of data to encrypt or ``None`` to signify
            that encryption has finished and that any remaining ciphertext
            has to be produced.
        :Return:
            the ciphertext, as a byte string.
            Its length may not match the length of the *plaintext*.
        """

        if Method.ENCRYPT not in self._next:
            raise TypeError("encrypt() can only be called after initialization or an update()")

        if plaintext is None:
            self._next = [Method.DIGEST]
        else:
            self._next = [Method.ENCRYPT]
        return self._process_incremental(plaintext, _raw_ocb_lib.OCB_encrypt, "encrypt")

    def decrypt(self, ciphertext: Optional[Buffer] = None) -> bytes:
        """Decrypt the next piece of ciphertext.

        After the entire ciphertext has been passed (but before `verify`),
        you **must** call this method one last time with no arguments to collect
        the remaining piece of plaintext.

        If possible, use the method `decrypt_and_verify` instead.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The next piece of data to decrypt or ``None`` to signify
            that decryption has finished and that any remaining plaintext
            has to be produced.
        :Return:
            the plaintext, as a byte string.
            Its length may not match the length of the *ciphertext*.
        """

        if Method.DECRYPT not in self._next:
            raise TypeError("decrypt() can only be called after initialization or an update()")

        if ciphertext is None:
            self._next = [Method.VERIFY]
        else:
            self._next = [Method.DECRYPT]
        return self._process_incremental(ciphertext, _raw_ocb_lib.OCB_decrypt, "decrypt")

    def _compute_mac_tag(self):
        if self._mac_tag is not None:
            return

        if self._cache_A:
            self._update(memoryview(self._cache_A))
            self._cache_A = b""

        mac_tag = create_string_buffer(16)
        result = _raw_ocb_lib.OCB_digest(self._state.get(), mac_tag, c_size_t(len(mac_tag)))
        if result:
            raise ValueError("Error %d while computing digest in OCB mode" % result)
        self._mac_tag = get_raw_buffer(mac_tag)[: self._mac_len]

    def digest(self) -> bytes:
        """Compute the *binary* MAC tag.

        Call this method after the final `encrypt` (the one with no arguments)
        to obtain the MAC tag.

        The MAC tag is needed by the receiver to determine authenticity
        of the message.

        :Return: the MAC, as a byte string.
        """

        if Method.DIGEST not in self._next:
            raise TypeError("digest() cannot be called now for this cipher")

        assert len(self._cache_P) == 0

        self._next = [Method.DIGEST]

        if self._mac_tag is None:
            self._compute_mac_tag()

        assert self._mac_tag is not None
        return self._mac_tag

    def hexdigest(self) -> str:
        """Compute the *printable* MAC tag.

        This method is like `digest`.

        :Return: the MAC, as a hexadecimal string.
        """
        return "".join(["%02x" % x for x in self.digest()])

    def verify(self, received_mac_tag: Buffer) -> None:
        """Validate the *binary* MAC tag.

        Call this method after the final `decrypt` (the one with no arguments)
        to check if the message is authentic and valid.

        :Parameters:
          received_mac_tag : bytes/bytearray/memoryview
            This is the *binary* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if Method.VERIFY not in self._next:
            raise TypeError("verify() cannot be called now for this cipher")

        assert len(self._cache_P) == 0

        self._next = [Method.VERIFY]

        if self._mac_tag is None:
            self._compute_mac_tag()

        secret = get_random_bytes(16)
        mac1 = BLAKE2s.new(digest_bits=160, key=secret, data=self._mac_tag)
        mac2 = BLAKE2s.new(digest_bits=160, key=secret, data=received_mac_tag)

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag: str) -> None:
        """Validate the *printable* MAC tag.

        This method is like `verify`.

        :Parameters:
          hex_mac_tag : string
            This is the *printable* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    def encrypt_and_digest(self, plaintext: Buffer) -> tuple[bytes, bytes]:
        """Encrypt the message and create the MAC tag in one step.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The entire message to encrypt.
        :Return:
            a tuple with two byte strings:

            - the encrypted data
            - the MAC
        """

        if Method.ENCRYPT in self._next and not self._cache_P:
            # The whole message in one go, into a single buffer
            # (it avoids copying the ciphertext to add the last piece)
            self._next = [Method.DIGEST]
            in_ptr, in_len = c_uint8_ptr_len(plaintext)
            ciphertext = self._process_all(in_ptr, in_len, _raw_ocb_lib.OCB_encrypt, "encrypt")
            return ciphertext, self.digest()

        return self.encrypt(plaintext) + self.encrypt(), self.digest()

    def decrypt_and_verify(self, ciphertext: Buffer, received_mac_tag: Buffer) -> bytes:
        """Decrypted the message and verify its authenticity in one step.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The entire message to decrypt.
          received_mac_tag : byte string
            This is the *binary* MAC, as received from the sender.

        :Return: the decrypted data (byte string).
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if Method.DECRYPT in self._next and not self._cache_P:
            # The whole message in one go (see encrypt_and_digest)
            self._next = [Method.VERIFY]
            in_ptr, in_len = c_uint8_ptr_len(ciphertext)
            plaintext = self._process_all(in_ptr, in_len, _raw_ocb_lib.OCB_decrypt, "decrypt")
        else:
            plaintext = self.decrypt(ciphertext) + self.decrypt()
        self.verify(received_mac_tag)
        return plaintext


def _create_ocb_cipher(factory, **kwargs):
    """Create a new block cipher, configured in OCB mode.

    :Parameters:
      factory : module
        A symmetric cipher module from `Crypto.Cipher`
        (like `Crypto.Cipher.AES`).

    :Keywords:
      nonce : bytes/bytearray/memoryview
        A  value that must never be reused for any other encryption.
        Its length can vary from 1 to 15 bytes.
        If not specified, a random 15 bytes long nonce is generated.

      mac_len : integer
        Length of the MAC, in bytes.
        It must be in the range ``[8..16]``.
        The default is 16 (128 bits).

      threads : integer
        The maximum number of threads used to encrypt or decrypt long data
        (default: 1, no extra threads; 0 for all CPU cores).

    Any other keyword will be passed to the underlying block cipher.
    See the relevant documentation for details (at least ``key`` will need
    to be present).
    """

    try:
        nonce = kwargs.pop("nonce", None)
        if nonce is None:
            nonce = get_random_bytes(15)
        mac_len = kwargs.pop("mac_len", 16)
        threads = kwargs.pop("threads", 1)
    except KeyError as e:
        raise TypeError("Keyword missing: " + str(e))

    return OcbMode(factory, nonce, mac_len, kwargs, threads)
