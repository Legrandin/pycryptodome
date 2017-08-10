SHAKE128
========

SHAKE128 is an *extendable-output function* (XOF) in the SHA-3 family, as specified in `FIPS 202`_.

As a XOF, SHAKE128 is a generalization of a cryptographic hash function.
Instead of creating a fixed-length digest (e.g. 32 bytes like SHA-2/256),
it can produce outputs of any desidered length.

Output bits do **not** depend of the output length.

The *128* in its name indicates its maximum security level (in bits),
as described in Sections A.1 and A.2 of `FIPS 202`_.

In the following example, the output is 26 bytes (208 bits) long::

    >>> from Crypto.Hash import SHAKE128
    >>> from binascii import hexlify
    >>>
    >>> shake = SHAKE128.new()
    >>> shake.update(b'Some data')
    >>> print hexlify(shake.read(26))

.. _FIPS 202: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

.. _SHA-2: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

.. automodule:: Crypto.Hash.SHAKE128
    :members:
