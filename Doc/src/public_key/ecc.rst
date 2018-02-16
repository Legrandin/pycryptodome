ECC
===

ECC_ (Elliptic Curve Cryptography) is a modern and efficient type of public key cryptography.
Its security is based on the difficulty to solve discrete logarithms
on the field defined by specific equations computed over a curve.

ECC can be used to create digital signatures or encrypting data.

The main benefit of ECC is that the size of a key is significantly smaller
than with more traditional algorithms like RSA or DSA.

For instance, consider the security level equivalent to AES128: an RSA
key of similar strength must have a modulus of 3072 bits (therefore the total size
is 768 bytes, comprising modulus and private exponent).
An ECC private needs as little as 256 bits (32 bytes).

This module provides mechanisms for generating new ECC keys, exporting them
using widely supported formats like PEM or DER and importing them back.

.. note::
    This module currently supports only ECC keys defined over the standard
    **NIST P-256 curve** (see `FIPS 186-4`_, Section D.1.2.3).
    More curves will be added in the future.

The following example demonstrates how to generate a new key, export it,
and subsequentely reload it back into the application::

    >>> from Crypto.PublicKey import ECC
    >>>
    >>> key = ECC.generate(curve='P-256')
    >>>
    >>> f = open('myprivatekey.pem','wt')
    >>> f.write(key.export_key(format='PEM'))
    >>> f.close()
    ...
    >>> f = open('myprivatekey.pem','rt')
    >>> key = ECC.import_key(f.read())

The ECC key can be used to perform or verify ECDSA signatures, using the module
:mod:`Crypto.Signature.DSS`.

.. _ECC: http://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

.. automodule:: Crypto.PublicKey.ECC
    :members:
