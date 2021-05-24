cSHAKE256
========

cSHAKE256 is an *extendable-output function* (XOF) in the SHA-3 family, as specified in `SP 800-185`_.

As a XOF, cSHAKE256 is a generalization of a cryptographic hash function.
Instead of creating a fixed-length digest (e.g. 32 bytes like SHA-2/256),
it can produce outputs of any desired length.

Output bits do **not** depend on the output length.

The *256* in its name indicates its maximum security level (in bits),
as described in Section 3.1 `SP 800-185`_.

cSHAKE256 is a customizable version of SHAKE256 and allows for additional domain separation via the two customization strings *function* and *custom*.
If both strings are empty, cSHAKE256 defaults back to SHAKE256.

Note that *function* is reserved for function names defined by NIST.
Hence, user-specific customization should only be done via the *custom* string.
See also Section 3.3 `SP 800-185`_.

In the following example, the output is 26 bytes (208 bits) long::

    >>> from Crypto.Hash import cSHAKE256
    >>> from binascii import hexlify
    >>>
    >>> shake = cSHAKE256.new(function=b'', custom=b'Email Signature')
    >>> shake.update(b'Some data')
    >>> print hexlify(shake.read(26))

.. _SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

.. _SHA-2: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

.. automodule:: Crypto.Hash.cSHAKE256
    :members:
