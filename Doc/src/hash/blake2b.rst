BLAKE2b
=======

`BLAKE2b`_ is an optimized variant of BLAKE, one of the SHA-3 candidates that
made it to the final round of the NIST hash competition.
It is specified in `RFC7693 <https://tools.ietf.org/html/rfc7693>`_.

The algorithm uses 64 bit words, and it therefore works best on
64-bit platforms. The digest size ranges from 8 to 512 bits.

    >>> from Crypto.Hash import BLAKE2b
    >>>
    >>> h_obj = BLAKE2b.new(digest_bits=512)
    >>> h_obj.update(b'Some data')
    >>> print h_obj.hexdigest()

Optionally, BLAKE2b can work as a cryptographic MAC when initialized
with a secret key.

    >>> from Crypto.Hash import BLAKE2b
    >>>
    >>> mac = BLAKE2b.new(digest_bits=256, key=b'secret')
    >>> mac.update(b'Some data')
    >>> print mac.hexdigest()

.. _BLAKE2b: https://blake2.net/

.. automodule:: Crypto.Hash.BLAKE2b
    :members:
