RSA
===

RSA_ is one of the most widespread and public key algorithms. Its security is
based on the difficulty of factoring large integers. The algorithm has
withstood attacks for more than 30 years, and it is therefore considered
reasonably secure.

However, for new designs, it is recommended to use :doc:`ECC <ecc>`,
because keys are smaller and private key operations are faster.

The RSA algorithm can be used for both confidentiality (encryption) and
authentication (digital signature). Signing and
decryption are significantly slower than verification and encryption.

The cryptographic strength is primarily linked to the length of the RSA modulus *n*.
In 2023, a sufficient length is deemed to be 3072 bits. For more information,
see the most recent NIST_ report.
Both RSA ciphertexts and RSA signatures are as large as the RSA modulus *n* (384
bytes if *n* is 3072 bit long).

With this module you can generate new RSA keys::

    >>> from Crypto.PublicKey import RSA
    >>>
    >>> mykey = RSA.generate(3072)

export an RSA private key and protect it with a password, so that it is
resistant to brute force attacks::

    >>> pwd = b'secret'
    >>> with open("myprivatekey.pem", "wb") as f:
    >>>     data = mykey.export_key(passphrase=pwd,
                                    pkcs=8,
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count':131072})
    >>>     f.write(data)

and reimport it later::

    >>> pwd = b'secret'
    >>> with open("myprivatekey.pem", "rb") as f:
    >>>     data = f.read()
    >>>     mykey = RSA.import_key(data, pwd)

You can also export the public key, which is not sensitive::

    >>> with open("mypublickey.pem", "wb") as f:
    >>>     data = mykey.public_key().export_key()

For signing data with RSA, use a higher level module such as :ref:`rsa_pss`.

For encrypting data with RSA, use :ref:`rsa_oaep`.

.. _RSA: http://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. _NIST: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

.. automodule:: Crypto.PublicKey.RSA
   :members:
