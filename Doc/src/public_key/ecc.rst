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

With this module you can generate new ECC keys::

    >>> from Crypto.PublicKey import ECC
    >>>
    >>> mykey = ECC.generate(curve='p256')

export an ECC private key and protect it with a password, so that it is
resistant to brute force attacks::

    >>> pwd = b'secret'
    >>> with open("myprivatekey.pem", "wt") as f:
    >>>     data = mykey.export_key(format='PEM'
                                    passphrase=pwd,
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count':131072})
    >>>     f.write(data)

and reimport it later::

    >>> pwd = b'secret'
    >>> with open("myprivatekey.pem", "rt") as f:
    >>>     data = f.read()
    >>>     mykey = ECC.import_key(data, pwd)

You can also export the public key, which is not sensitive::

    >>> with open("mypublickey.pem", "wbt) as f:
    >>>     data = mykey.public_key().export_key()

.. _ECC table:
.. csv-table::
   :header: Curve, Strings accepted for the ``curve`` API parameter
   :widths: 20, 80

   "NIST P-192", "``'NIST P-192'``, ``'p192'``, ``'P-192'``, ``'prime192v1'``, ``'secp192r1'``"
   "NIST P-224", "``'NIST P-224'``, ``'p224'``, ``'P-224'``, ``'prime224v1'``, ``'secp224r1'``"
   "NIST P-256", "``'NIST P-256'``, ``'p256'``, ``'P-256'``, ``'prime256v1'``, ``'secp256r1'``"
   "NIST P-384", "``'NIST P-384'``, ``'p384'``, ``'P-384'``, ``'prime384v1'``, ``'secp384r1'``"
   "NIST P-521", "``'NIST P-521'``, ``'p521'``, ``'P-521'``, ``'prime521v1'``, ``'secp521r1'``"
   "Ed25519",    "``'ed25519'``, ``'Ed25519'``"
   "Ed448",      "``'ed448'``, ``'Ed448'``"

For more information about each NIST curve see `FIPS 186-4`_, Section D.1.2.

The Ed25519 and the Ed448 curves are defined in RFC8032_.

The ECC key can be used to perform or verify signatures, using the modules
:mod:`Crypto.Signature.DSS` (ECDSA; NIST curves only)
or :mod:`Crypto.Signature.eddsa` (EdDSA; Ed25519 and Ed448 curve only).

.. _ECC: http://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
.. _RFC8032: https://datatracker.ietf.org/doc/html/rfc8032

.. automodule:: Crypto.PublicKey.ECC
    :members:
