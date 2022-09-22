cSHAKE128
=========

cSHAKE128 is an *extendable-output function* (XOF) in the SHA-3 family, as specified in `SP 800-185`_.

As a XOF, cSHAKE128 is a generalization of a cryptographic hash function.
It is not limited to creating fixed-length digests (e.g., SHA-256 will always output exactly 32 bytes):
it produces digests of any length, and it can be used as a Pseudo Random Generator (PRG).

Output bits do **not** depend on the output length.

The *128* in its name indicates its maximum security level (in bits),
as described in Section 3.1 of `SP 800-185`_.

cSHAKE128 is a customizable version of SHAKE128 and allows for additional domain separation
via a customization string (``custom`` parameter to :func:`Crypto.Hash.cSHAKE128.new`).

.. hint::

  For instance, if you are using cSHAKE128 in two applications,
  by picking different customization strings you can ensure
  that they will never end up using the same digest in practice.
  The important factor is that the strings are different;
  what the strings say does not matter.

If the customization string is empty, cSHAKE128 defaults back to :doc:`shake128`.
See also Section 3.3 of `SP 800-185`_.

In the following example, we extract 26 bytes (208 bits) from the XOF::

    >>> from Crypto.Hash import cSHAKE128
    >>>
    >>> shake = cSHAKE128.new(custom=b'Email Signature')
    >>> shake.update(b'Some data')
    >>> print(shake.read(26).hex())

.. _SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

.. _SHA-2: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

.. automodule:: Crypto.Hash.cSHAKE128
    :members:
