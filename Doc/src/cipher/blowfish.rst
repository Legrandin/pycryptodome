Blowfish
========

.. warning::
    Use :doc:`aes`. This module is provided only for legacy purposes.

Blowfish_ is a symmetric block cipher designed by Bruce Schneier.

It has a fixed data block size of 8 bytes and its keys can vary in length
from 32 to 448 bits (4 to 56 bytes).

Blowfish is deemed secure and it is fast. However, its keys should be chosen
to be big enough to withstand a brute force attack (e.g. at least 16 bytes).

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import Blowfish
    >>> from struct import pack
    >>>
    >>> bs = Blowfish.block_size
    >>> key = b'An arbitrarily long key'
    >>> cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    >>> plaintext = b'docendo discimus '
    >>> plen = bs - len(plaintext) % bs
    >>> padding = [plen]*plen
    >>> padding = pack('b'*plen, *padding)
    >>> msg = cipher.iv + cipher.encrypt(plaintext + padding)

.. _Blowfish: http://www.schneier.com/blowfish.html

.. automodule:: Crypto.Cipher.Blowfish
    :members:
