Keccak
======

`Keccak`_ is a family of cryptographic hash algorithms that won
the SHA-3 competition organized by NIST.
What eventually became SHA-3 (`FIPS 202`_) is a slight variant: though incompatible
to Keccak, the security principles and margins remain the same.

If you are interested in writing SHA-3 compliant code, you must use
the modules :mod:`Crypto.Hash.SHA3_224`,
:mod:`Crypto.Hash.SHA3_256`, :mod:`Crypto.Hash.SHA3_384` or :mod:`Crypto.Hash.SHA3_512`.

This module implements the Keccak hash functions for the 64 bit word
length (``b=1600``) and the fixed digest sizes of 224, 256, 384 and 512 bits.

This is an example::

    >>> from Crypto.Hash import keccak
    >>>
    >>> keccak_hash = keccak.new(digest_bits=512)
    >>> keccak_hash.update(b'Some data')
    >>> print keccak_hash.hexdigest()

.. _Keccak: http://www.keccak.noekeon.org/Keccak-specifications.pdf
.. _FIPS 202: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

.. automodule:: Crypto.Hash.keccak
    :members:
