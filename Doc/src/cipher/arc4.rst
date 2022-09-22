ARC4
====

.. warning::
   ARC4 is not secure.
   Use :doc:`chacha20_poly1305` or :doc:`aes` (AEX or GCM mode) instead.
   This module is provided only for legacy purposes.

ARC4_ (Alleged RC4) is an implementation of RC4 (Rivest's Cipher version 4),
a symmetric stream cipher designed by Ron Rivest in 1987.

The cipher started as a proprietary design, that was reverse engineered and
anonymously posted on Usenet in 1994. The company that owns RC4 (RSA Data
Inc.) never confirmed the correctness of the leaked algorithm.

Unlike RC2, the company has never published the full specification of RC4,
of which it still holds the trademark.

ARC4 keys can vary in length from 8 to 2048 bits.

One problem of ARC4 is that it does not take a nonce or an IV.
If it is required to encrypt multiple messages with the same long-term key, a
distinct independent nonce must be created for each message, and a short-term
key must be derived from the combination of the long-term key and the nonce.
Due to the weak key scheduling algorithm of ARC4, the combination must be
carried out with a complex function (e.g. a cryptographic hash) and not by
simply concatenating key and nonce.

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import ARC4
    >>> from Crypto.Hash import SHA256, HMAC
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = b'Very long and confidential key'
    >>> nonce = get_random_bytes(16)
    >>> tempkey = HMAC.new(key, nonce, digestmod=SHA256).digest()
    >>> cipher = ARC4.new(tempkey)
    >>> msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')

.. _ARC4: http://en.wikipedia.org/wiki/RC4

.. automodule:: Crypto.Cipher.ARC4
    :members:
