ECC
===

ECC_ (Elliptic Curve Cryptography) is a modern and efficient type of public key cryptography.
Its security is based on the difficulty to solve discrete logarithms
on the field defined by specific equations computed over a curve.

ECC can be used to create digital signatures or to perform a key exchange.

Compared to traditional algorithms like RSA, an ECC key
is significantly smaller at the same security level.
For instance, a 3072-bit RSA key takes 768 bytes whereas the equally strong NIST P-256
private key only takes 32 bytes (that is, 256 bits).

This module provides mechanisms for generating new ECC keys, exporting and importing them
using widely supported formats like PEM or DER.

.. _curve_names:
.. csv-table::
   :header: Curve, Possible identifiers
   :widths: 20, 80

   "NIST P-256", "``'NIST P-256'``, ``'p256'``, ``'P-256'``, ``'prime256v1'``, ``'secp256r1'``"
   "NIST P-384", "``'NIST P-384'``, ``'p384'``, ``'P-384'``, ``'prime384v1'``, ``'secp384r1'``"
   "NIST P-521", "``'NIST P-521'``, ``'p521'``, ``'P-521'``, ``'prime521v1'``, ``'secp521r1'``"

For more information about each NIST curve see `FIPS 186-4`_, Section D.1.2.

The following example demonstrates how to generate a new ECC key, export it,
and subsequentely reload it back into the application::

    >>> from Crypto.PublicKey import ECC
    >>>
    >>> key = ECC.generate(curve='P-256')
    >>>
    >>> f = open('myprivatekey.pem','wt')
    >>> f.write(key.export_key()
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
