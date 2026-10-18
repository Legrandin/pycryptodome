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
    pkey = key.export_key(format='DER')
    passphrase = b'secret santa'
    encrypted_key = PKCS8.wrap(
                    pkey,
                    "1.2.840.10045.2.1",  # unrestricted ECC
                    passphrase=passphrase,
                    protection='PBKDF2WithHMAC-SHA256AndAES256-CBC'
                    )

.. _enc_params:

Encryption parameters
-----------------------

When creating an encrypted PKCS#8 container, the two parameters
``protection`` and ``prot_params`` drive the encryption algorithm:

* ``protection`` (optional, the default is ``'PBKDF2WithHMAC-SHA256AndAES256-CBC'``),
  a string that defines how the encryption
  key is derived from the passphrase, and which cipher to use.
  The string must follow one of the two patterns:

  #. ``'PBKDF2WithHMAC-'`` + **hash** + ``'And'``  + **cipher**
  #. ``'scryptAnd'`` + **cipher**

  where **hash** is the name of the cryptographic hash
  (recommended: ``'SHA256'``) and **cipher** is the name
  of the cipher mode to use (recommended: ``'AES256-CBC'``).

  Other values for **hash** are ``'SHA1'``, ``'SHA224'``, ``'SHA256'``,
  ``'SHA384'``, ``'SHA512-224'``, ``'SHA512-256'``, ``'SHA3-224'``,
  ``'SHA3-256'``, ``'SHA3-384'``, ``'SHA3-512'``.

  Other values for **cipher** are
  ``'AES128-GCM'``, ``'AES192-GCM'``, ``'AES256-GCM'``,
  ``'AES128-CBC'``, ``'AES192-CBC'`` or ``'DES-EDE3-CBC'``.

* ``prot_params`` (optional), a dictionary to override the parameters of the
  key derivation function. The defaults meet the
  `OWASP recommendations <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>`_
  for scrypt and for PBKDF2 with SHA-256 or SHA-512 (but not SHA-1, which should not be used):
  there is no need to change them, except to make
  the key cheaper to decrypt (for instance, on a slow device).

  +------------------+-----------------------------------------------+
  | Key              | Description                                   |
  +==================+===============================================+
  | iteration_count  | The KDF algorithm is repeated several times to|
  |                  | slow down brute force attacks on passwords    |
  |                  | (called *N* or CPU/memory cost in scrypt).    |
  |                  |                                               |
  |                  | The default value is 600 000 for PBKDF2       |
  |                  | (whatever the hash), and 131 072 for scrypt.  |
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

With scrypt, the ``parallelization`` parameter (*p*) defines independent
computations, which can run on several CPU cores: use the ``threads`` parameter
of :func:`wrap` and :func:`unwrap`, of ``import_key()`` for RSA, DSA and ECC keys,
and of ``export_key()`` for RSA and ECC keys.
With ``threads=0``, as many threads as the CPU cores available are used.
Each thread needs its own block of memory (128 · *r* · *N* bytes), at the same time.
The result does not depend on the number of threads.


Limits for decryption
---------------------

To protect against malicious keys, :func:`unwrap` rejects keys whose key derivation
is too expensive (parameters ``max_iteration_count`` and ``max_memory``).
See :doc:`kdf_limits` for the default limits and how to change them.

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
.. _`RFC 5958`: https://www.rfc-editor.org/rfc/rfc5958.html

.. automodule:: Crypto.IO.PKCS8
    :members:
