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

With scrypt, the ``parallelization`` parameter (*p*) defines independent
computations, which can run on several CPU cores: use the ``threads`` parameter
of :func:`wrap` and :func:`unwrap`, of ``import_key()`` for RSA, DSA and ECC keys,
and of ``export_key()`` for RSA and ECC keys.
With ``threads=0``, as many threads as the CPU cores available are used.
Each thread needs its own block of memory (128 · *r* · *N* bytes).
The result does not depend on the number of threads.


.. _pkcs8_limits:

Limits for decryption
---------------------

A malicious encrypted key could require an extremely expensive key derivation,
tying up the CPU for hours, or all the memory.
Therefore, :func:`unwrap` and the ``import_key()`` functions of RSA, DSA and ECC keys
reject keys above two limits:

* ``max_iteration_count``, for the time;
* ``max_memory``, for the memory (in bytes).

By default (``max_iteration_count=None``), the limit depends on the key derivation
function and on the hash, so that the derivation takes at most about one minute
on a recent x86-64 laptop:

  +--------------------------------------------+-----------------------------------+
  | Key derivation                             | Default limit                     |
  +============================================+===================================+
  | PBKDF2 with SHA-1 or SHA-256               | 200 000 000 iterations            |
  +--------------------------------------------+-----------------------------------+
  | PBKDF2 with SHA-224, SHA-384, SHA-512      | 100 000 000 iterations            |
  | or SHA-512/256                             |                                   |
  +--------------------------------------------+-----------------------------------+
  | PBKDF2 with SHA-512/224                    | 50 000 000 iterations             |
  +--------------------------------------------+-----------------------------------+
  | PBKDF2 with SHA-3 (any size)               | 1 500 000 iterations              |
  +--------------------------------------------+-----------------------------------+
  | PBKDF1 (legacy algorithms)                 | 20 000 000 iterations             |
  +--------------------------------------------+-----------------------------------+
  | scrypt                                     | *N·r·p/8* up to 2\ :sup:`25`      |
  +--------------------------------------------+-----------------------------------+

An explicit ``max_iteration_count`` is the maximum number of iterations
for PBKDF1 and PBKDF2, whatever the hash, and the maximum *N·r·p/8* for scrypt
(that is, *N* for the usual *r=8* and *p=1*).

Only scrypt needs a significant amount of memory: *128·N·r* bytes for each thread.
By default (``max_memory=None``), the limit is 256 MiB, all threads included.
Fewer threads are used if needed, down to one.

With ``max_iteration_count=0`` or ``max_memory=0``, the corresponding limit does not apply.

When a key is above a limit, :class:`PbesIterationCountError` or :class:`PbesMemoryError`
is raised (both are subclasses of :class:`PbesLimitError`, which is a ``ValueError``).

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
