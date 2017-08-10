BLAKE2s
=======

`BLAKE2s`_ is an optimized variant of BLAKE, one of the SHA-3 candidates that
made it to the final round of the NIST hash competition.
It is specified in `RFC7693 <https://tools.ietf.org/html/rfc7693>`_.

The algorithm uses 32 bit words, and it therefore works best on
32-bit platforms. The digest size ranges from 8 to 256 bits::

    >>> from Crypto.Hash import BLAKE2s
    >>>
    >>> h_obj = BLAKE2s.new(digest_bits=256)
    >>> h_obj.update(b'Some data')
    >>> print h_obj.hexdigest()

Optionally, BLAKE2s can work as a cryptographic MAC when initialized
with a secret key::

    >>> from Crypto.Hash import BLAKE2s
    >>>
    >>> mac = BLAKE2s.new(digest_bits=128, key=b'secret')
    >>> mac.update(b'Some data')
    >>> print mac.hexdigest()

.. _BLAKE2b: https://blake2.net/

.. automodule:: Crypto.Hash.BLAKE2s
    :members:
