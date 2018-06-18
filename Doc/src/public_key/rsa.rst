RSA
===

RSA_ is the most widespread and used public key algorithm. Its security is
based on the difficulty of factoring large integers. The algorithm has
withstood attacks for more than 30 years, and it is therefore considered
reasonably secure for new designs.

The algorithm can be used for both confidentiality (encryption) and
authentication (digital signature). It is worth noting that signing and
decryption are significantly slower than verification and encryption.

The cryptograhic strength is primarily linked to the length of the RSA modulus *n*.
In 2017, a sufficient length is deemed to be 2048 bits. For more information,
see the most recent ECRYPT_ report.

Both RSA ciphertexts and RSA signatures are as large as the RSA modulus *n* (256
bytes if *n* is 2048 bit long).

The module :mod:`Crypto.PublicKey.RSA` provides facilities for generating new RSA keys,
reconstructing them from known components, exporting them, and importing them.

As an example, this is how you generate a new RSA key pair, save it in a file
called ``mykey.pem``, and then read it back::

    >>> from Crypto.PublicKey import RSA
    >>>
    >>> key = RSA.generate(2048)
    >>> f = open('mykey.pem','wb')
    >>> f.write(key.export_key('PEM'))
    >>> f.close()
    ...
    >>> f = open('mykey.pem','r')
    >>> key = RSA.import_key(f.read())

.. _RSA: http://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. _ECRYPT: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf

.. automodule:: Crypto.PublicKey.RSA
    :members:
