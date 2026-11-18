AEGIS-128L and AEGIS-256
========================

.. currentmodule:: Crypto.Cipher.AEGIS

AEGIS is a family of authenticated ciphers with associated data (AEAD),
specified in `RFC 10032`_. It is built on the AES round function,
and it is very fast on CPUs with AES instructions.

This module supports the two variants of RFC 10032 that use a single AES state
(AEGIS-128X and AEGIS-256X, specialized for wide vector registers, are not supported):

.. csv-table::
    :header: Variant, Constant, Key (bytes), Nonce (bytes), Random nonces with the same key
    :class: compact-table

    "AEGIS-128L", ":data:`AEGIS.AEGIS_128L <Crypto.Cipher.AEGIS.AEGIS_128L>`", "16", "16", "Up to 2\ :sup:`48` messages"
    "AEGIS-256", ":data:`AEGIS.AEGIS_256 <Crypto.Cipher.AEGIS.AEGIS_256>`", "32", "32", "No practical limit"

The authentication tag is 16 bytes (default) or 32 bytes long (parameter ``mac_len``).
With a 32-byte tag, it is also infeasible to find a different key and nonce
for which the same associated data, ciphertext and tag are valid (*key commitment*,
see Section 9.1.2 of `RFC 10032`_).
Use ``mac_len=32`` when the key may be derived from a password, or when the ciphertext
must not be valid under several keys.

.. warning::

    A nonce **must never** be reused with the same key, not even with a different
    tag length: it reveals the internal state, which allows decrypting the messages
    and forging new ones.

The message and the associated data can be up to 2\ :sup:`61` - 1 bytes long each.

The API of the cipher and its finite state machine are the same as for the
:doc:`modern modes of operation of block ciphers <modern>`.
As with GCM and ChaCha20-Poly1305, :meth:`AegisCipher.decrypt` returns the plaintext
*before* the tag is checked: do not use it until :meth:`AegisCipher.verify` succeeds,
or use :meth:`AegisCipher.decrypt_and_verify`.

The implementation uses the AES instructions of the CPU (AES-NI on x86,
the ARMv8 Cryptography Extensions on 64-bit ARM) when present.
AEGIS is then considerably faster than :doc:`chacha20_poly1305`.

Without them, it uses a bitsliced AES round, which runs in constant time,
and uses SIMD instructions such as NEON on ARM and SSE2 on x86 when available.
With NEON, , AEGIS-128L is then faster than ChaCha20-Poly1305,
and AEGIS-256 about as fast; on x86, both are slower.

Without AES instructions, ChaCha20-Poly1305 is the better choice, except on ARM with NEON.

This is an example of encryption with AEGIS-256::

    >>> from Crypto.Cipher import AEGIS
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> header = b"header"
    >>> data = b"secret"
    >>> key = get_random_bytes(32)
    >>> cipher = AEGIS.new(key, AEGIS.AEGIS_256)
    >>> cipher.update(header)
    >>> ciphertext, tag = cipher.encrypt_and_digest(data)
    >>> nonce = cipher.nonce

The 32-byte nonce is generated randomly, and it is in the ``nonce`` attribute:
it must be sent along with the ciphertext and the tag.

This is how the receiver decrypts the data and checks its authenticity::

    >>> from Crypto.Cipher import AEGIS
    >>>
    >>> # We assume that the key was securely shared beforehand
    >>> cipher = AEGIS.new(key, AEGIS.AEGIS_256, nonce=nonce)
    >>> cipher.update(header)
    >>> try:
    ...     plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    ...     print("The message was: " + plaintext.decode())
    ... except ValueError:
    ...     print("Incorrect decryption")

.. _RFC 10032: https://www.rfc-editor.org/rfc/rfc10032.html

.. automodule:: Crypto.Cipher.AEGIS

.. autofunction:: new

.. autodata:: AEGIS_128L

.. autodata:: AEGIS_256

.. autoclass:: AegisCipher
    :members:
