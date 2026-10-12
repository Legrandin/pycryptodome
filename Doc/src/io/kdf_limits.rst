.. _pkcs8_limits:

Limits when decrypting private keys
===================================

An encrypted private key (`PKCS#8`_, in DER or PEM format) states how expensive
the derivation of its decryption key from the passphrase is:
the iteration count of PBKDF2, or the cost parameters of scrypt.
A malicious key can therefore require an extremely expensive derivation, and tie up
the CPU for hours, or all the memory, before the passphrase is even checked.

For this reason, the functions that decrypt such keys reject the ones above
two limits:

* ``max_iteration_count``, for the time;
* ``max_memory``, for the memory (in bytes).

Both are keyword arguments of:

* :func:`Crypto.IO.PKCS8.unwrap`;
* :func:`Crypto.PublicKey.RSA.import_key`, :func:`Crypto.PublicKey.DSA.import_key`
  and :func:`Crypto.PublicKey.ECC.import_key`.

The limits do not apply when encrypting a key (for instance, with ``export_key()``):
the caller chooses the parameters then.

Default limits
--------------

By default (``max_iteration_count=None`` and ``max_memory=None``),
the limits depend on the key derivation function and on the hash,
so that the derivation takes at most about one minute on a recent x86-64 laptop:

+----------------------------------------------+----------------------------------+
| Key derivation                               | Default ``max_iteration_count``  |
+==============================================+==================================+
| PBKDF2 with HMAC-SHA1 or HMAC-SHA256         | 200,000,000 iterations           |
+----------------------------------------------+----------------------------------+
| PBKDF2 with HMAC-SHA224, HMAC-SHA384,        | 100,000,000 iterations           |
| HMAC-SHA512, HMAC-SHA512/256,                |                                  |
| HMAC-SHA3-256, HMAC-SHA3-384 or              |                                  |
| HMAC-SHA3-512                                |                                  |
+----------------------------------------------+----------------------------------+
| PBKDF2 with HMAC-SHA512/224 or HMAC-SHA3-224 | 50,000,000 iterations            |
+----------------------------------------------+----------------------------------+
| PBKDF1 (legacy PBES1 algorithms)             | 20,000,000 iterations            |
+----------------------------------------------+----------------------------------+
| scrypt                                       | *N·r·p/8* up to 2\ :sup:`25`     |
|                                              | (33,554,432)                     |
+----------------------------------------------+----------------------------------+

+----------------------------------------------+----------------------------------+
| Key derivation                               | Default ``max_memory``           |
+==============================================+==================================+
| scrypt                                       | 256 MiB, for all threads         |
|                                              | together                         |
+----------------------------------------------+----------------------------------+
| PBKDF1, PBKDF2                               | (they need very little memory)   |
+----------------------------------------------+----------------------------------+

These limits are far above the recommended minimum costs for passwords:
for instance, OWASP recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256,
and *N* = 2\ :sup:`17` with *r* = 8 and *p* = 1 for scrypt
(128 MiB, and a cost *N·r·p/8* of 2\ :sup:`17`).

The limits for a hash depend on the time of one iteration, and on the length
of the digest. When the digest is shorter than the key (for instance, the
28 bytes of SHA-512/224 or SHA3-224, for a 32-byte AES-256 key), PBKDF2 has to
compute two blocks of output, each one with the full iteration count:
then, each iteration costs twice as much.

The scrypt cost
---------------

The time that scrypt takes is proportional to *N·r·p*, and for this reason
``max_iteration_count`` limits *N·r·p/8* (rounded up) and not *N* alone.
For the usual *r* = 8 and *p* = 1, it is just *N*.

For instance, the default limit accepts *N* = 2\ :sup:`20` with *r* = 8 and *p* = 32,
or *N* = 2\ :sup:`14` with *r* = 8 and *p* = 1024; it rejects *N* = 2\ :sup:`26` with *r* = 8
and *p* = 1.

Memory and threads
------------------

Only scrypt needs a significant amount of memory: *128·N·r* bytes for **each** thread,
so *t* threads need *t·128·N·r* bytes.
With *p* larger than 1, scrypt can run on up to *p* threads, as requested
with the ``threads`` parameter (see :func:`Crypto.Protocol.KDF.scrypt`).

``max_memory`` limits the **total** of all threads together, not each thread.
If the requested threads do not fit, fewer are used, down to one;
if a single thread does not fit, the key is rejected.

For instance, with the default limit of 256 MiB:

* *N* = 2\ :sup:`17` and *r* = 8 (128 MiB for each thread): at most 2 threads are used,
  even with ``threads=4``;
* *N* = 2\ :sup:`18` and *r* = 8 (256 MiB for each thread): only 1 thread is used;
* *N* = 2\ :sup:`19` and *r* = 8 (512 MiB for one thread): the key is rejected.

Keys created by OpenSSL (at most 32 MiB) and by this library with the default
parameters (16 MiB) are well within the default limit.

Explicit limits
---------------

An explicit ``max_iteration_count`` is the maximum number of iterations
for PBKDF1 and PBKDF2, whatever the hash, and the maximum *N·r·p/8* for scrypt.
An explicit ``max_memory`` is the maximum number of bytes, for all threads together.

With ``max_iteration_count=0`` or ``max_memory=0``, the corresponding limit does not apply.
Only use ``0`` with keys that come from a trusted source.

Both parameters must be integers (or ``None``), and not negative:
otherwise, ``TypeError`` or ``ValueError`` is raised,
even if the key turns out not to be encrypted.

Errors
------

When a key is above a limit, the functions raise:

* :class:`Crypto.IO.PKCS8.PbesIterationCountError`, for ``max_iteration_count``;
* :class:`Crypto.IO.PKCS8.PbesMemoryError`, for ``max_memory``.

Both are subclasses of :class:`Crypto.IO.PKCS8.PbesLimitError`, which is a ``ValueError``.
Their message says which value is too high, and which limit applies.

For instance, to accept a trusted key that needs more memory than the default::

    >>> from Crypto.IO.PKCS8 import PbesMemoryError
    >>> from Crypto.PublicKey import ECC
    >>>
    >>> try:
    >>>     key = ECC.import_key(encrypted_key, passphrase)
    >>> except PbesMemoryError:
    >>>     key = ECC.import_key(encrypted_key, passphrase, max_memory=2**30)

What is not covered
-------------------

* Private keys encrypted with the legacy PEM encryption (``Proc-Type: 4,ENCRYPTED``):
  their key derivation has a fixed, low cost.
* OpenSSH private keys (``-----BEGIN OPENSSH PRIVATE KEY-----``): their bcrypt
  rounds are not limited.

.. _`PKCS#8`: https://datatracker.ietf.org/doc/html/rfc5208
