CAST-128
========

.. warning::
    Use :doc:`aes`. This module is provided only for legacy purposes.

CAST-128_ (or CAST5) is a symmetric block cipher specified in RFC2144_.

It has a fixed data block size of 8 bytes. Its key can vary in length
from 40 to 128 bits.

CAST is deemed to be cryptographically secure, but its usage is not widespread.
Keys of sufficient length should be used to prevent brute force attacks
(128 bits are recommended).

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import CAST
    >>>
    >>> key = b'Sixteen byte key'
    >>> cipher = CAST.new(key, CAST.MODE_OPENPGP)
    >>> plaintext = b'sona si latine loqueris '
    >>> msg = cipher.encrypt(plaintext)
    >>>
    ...
    >>> eiv = msg[:CAST.block_size+2]
    >>> ciphertext = msg[CAST.block_size+2:]
    >>> cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
    >>> print cipher.decrypt(ciphertext)

.. _CAST-128: http://en.wikipedia.org/wiki/CAST-128
.. _RFC2144: http://tools.ietf.org/html/rfc2144

.. automodule:: Crypto.Cipher.CAST
    :members:
