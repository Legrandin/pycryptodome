PKCS#8
======

`PKCS#8`_ is a standard for encoding asymmetric private keys,
such as RSA or ECC, so that they can be stored or exchanged.
The private key can either be encrypted with a passphrase or
left in the clear.

Example of how to encrypt an ECC private key (even though
normally you would use the ``export_key`` method of the key itself)::

    from Crypto.PublicKey import ECC
    from Crypto.IO import PKCS8

    key = ECC.generate(curve='p256')
    pkey = key.export_key(format='DER'),
    passphrase = b'secret santa'
    encrypted_key = PKCS8.wrap(
                    pkey,
                    "1.2.840.10045.2.1",  # unrestricted ECC
                    passphrase=passphrase,
                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                    prot_params={'iteration_count': 210000}
                    )

.. _enc_params:

Encryption parameters
-----------------------

When creating an encrypted PKCS#8 container, the two parameters
``protection`` and ``prot_params`` drive the encryption algorithm:

* ``protection`` (mandatory), a string that defines how the encryption
  key is derived from the passphrase, and which cipher to use.
  The string must follow one of the two patterns:

  #. ``'PBKDF2WithHMAC-'`` + **hash** + ``'And'``  + **cipher**
  #. ``'scryptAnd'`` + **cipher**

  where **hash** is the name of the cryptographic hash
  (recommended: ``'SHA512'``) and **cipher** is the name
  of the cipher mode to use (recommended: ``'AES256-CBC'``).

  Other values for **hash** are ``'SHA1'``, ``'SHA224'``, ``'SHA256'``,
  ``'SHA384'``, ``'SHA512-224'``, ``'SHA512-256'``, ``'SHA3-224'``,
  ``'SHA3-256'``, ``'SHA3-384'``, ``'SHA3-512'``.

  Other values for **cipher** are
  ``'AES128-GCM'``, ``'AES192-GCM'``, ``'AES256-GCM'``,
  ``'AES128-CBC'``, ``'AES192-CBC'`` or ``'DES-EDE3-CBC'``.

* ``prot_params`` (optional), a dictionary to override the parameters of the
  key derivation function:

  +------------------+-----------------------------------------------+
  | Key              | Description                                   |
  +==================+===============================================+
  | iteration_count  | The KDF algorithm is repeated several times to|
  |                  | slow down brute force attacks on passwords    |
  |                  | (called *N* or CPU/memory cost in scrypt).    |
  |                  |                                               |
  |                  | **For PBKDF2 with SHA512 the recommended      |
  |                  | value is 210 000** (default is 1 000).        |
  |                  |                                               |
  |                  | **For scrypt the recommended value is         |
  |                  | 131 072** (default value is 16 384).          |
  +------------------+-----------------------------------------------+
  | salt_size        | Salt is used to thwart dictionary and rainbow |
  |                  | attacks on passwords. The default value is 8  |
  |                  | bytes.                                        |
  +------------------+-----------------------------------------------+
  | block_size       | *(scrypt only)* Memory-cost (r). The default  |
  |                  | value is 8.                                   |
  +------------------+-----------------------------------------------+
  | parallelization  | *(scrypt only)* CPU-cost (p). The default     |
  |                  | value is 1.                                   |
  +------------------+-----------------------------------------------+


Legacy algorithms
-----------------

The following ``protection`` mechanisms are only supported for importing keys.
They are much weaker than the ones listed above, and they are provided
for backward compatibility only:

* ``pbeWithMD5AndRC2-CBC``
* ``pbeWithMD5AndDES-CBC``
* ``pbeWithSHA1AndRC2-CBC``
* ``pbeWithSHA1AndDES-CBC``

.. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt

.. automodule:: Crypto.IO.PKCS8
    :members:
