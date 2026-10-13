.. _pkcs8_limits:

Limits when decrypting private keys
===================================

An encrypted private key (`PKCS#8`_ in DER or PEM format, or OpenSSH) states how expensive
the derivation of its decryption key from the passphrase is:
the iteration count of PBKDF2, the cost parameters of scrypt,
or the number of rounds of bcrypt (for OpenSSH keys).
A malicious key can therefore require an extremely expensive derivation, and tie up
the CPU for hours, or all the memory, before the passphrase is even checked.

For this reason, the functions that decrypt such keys reject the ones above
two limits:

* ``max_iteration_count``, for the time;
* ``max_memory``, for the memory (in bytes).

Both are keyword arguments of:

* :func:`Crypto.IO.PKCS8.unwrap`;
* :func:`Crypto.PublicKey.RSA.import_key`, :func:`Crypto.PublicKey.DSA.import_key`
  and :func:`Crypto.PublicKey.ECC.import_key`
  (for RSA and ECC, also with OpenSSH private keys).

The limits do not apply when encrypting a key (for instance, with ``export_key()``):
the caller chooses the parameters then.

A similar limit, ``max_cost``, protects :func:`Crypto.Protocol.KDF.bcrypt_check`,
when it verifies a password against a bcrypt hash that states its own cost
(see `bcrypt password hashes`_).

Default limits
--------------

By default (``max_iteration_count=None`` and ``max_memory=None``),
the limits depend on the key derivation function,
so that the derivation takes at most about one minute on a recent x86-64 laptop,
with a single thread:

+----------------------------------------------+----------------------------------+
| Key derivation                               | Default ``max_iteration_count``  |
+==============================================+==================================+
| PBKDF2 (with any hash), and PBKDF1           | 50,000,000 iterations            |
| (legacy PBES1 algorithms)                    |                                  |
+----------------------------------------------+----------------------------------+
| scrypt                                       | *N·r·p/8* up to 2\ :sup:`25`     |
|                                              | (33,554,432)                     |
+----------------------------------------------+----------------------------------+
| bcrypt_pbkdf (OpenSSH private keys)          | 16,384 rounds                    |
+----------------------------------------------+----------------------------------+

+----------------------------------------------+----------------------------------+
| Key derivation                               | Default ``max_memory``           |
+==============================================+==================================+
| scrypt                                       | 256 MiB, for all threads         |
|                                              | together                         |
+----------------------------------------------+----------------------------------+
| PBKDF1, PBKDF2, bcrypt_pbkdf                 | (they need very little memory)   |
+----------------------------------------------+----------------------------------+

These limits are far above the recommended minimum costs for passwords:
for instance, OWASP recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256,
and *N* = 2\ :sup:`17` with *r* = 8 and *p* = 1 for scrypt
(128 MiB, and a cost *N·r·p/8* of 2\ :sup:`17`).

With PBKDF2, the time of one iteration depends on the hash, and on the length
of its digest. When the digest is shorter than the key (for instance, the
28 bytes of SHA-512/224 or SHA3-224, for a 32-byte AES-256 key), PBKDF2 has to
compute two blocks of output, each one with the full iteration count:
then, each iteration costs twice as much. These are the slowest cases, and
the ones for which the default limit takes about one minute.

The scrypt cost
---------------

The total work of scrypt (its CPU time) is proportional to *N·r·p*: for this reason,
``max_iteration_count`` limits *N·r·p/8* (rounded up) and not *N* alone.
For the usual *r* = 8 and *p* = 1, it is just *N*.

scrypt also does some work in proportion to *r·p* only, whatever *N* is
(two PBKDF2 steps over *128·r·p* bytes): about as much as with *N* = 128.
To account for it, *N* counts as 1024 in the cost when it is smaller.
This changes nothing for real keys, whose *N* is larger.

The *p* flows of scrypt are independent, and they can run on several threads
(see below). With *t* threads, each one computes at most *⌈p/t⌉* flows,
so the elapsed time is proportional to *N·r·⌈p/t⌉*: that is the best case,
when *t* CPU cores are free. The limit is on the total work instead,
which does not depend on the number of threads, nor on how busy the CPU is.

For instance, the default ``max_iteration_count`` accepts *N* = 2\ :sup:`20` with
*r* = 8 and *p* = 32, or *N* = 2\ :sup:`14` with *r* = 8 and *p* = 2048 (both at the limit);
it rejects *N* = 2\ :sup:`26` with *r* = 8 and *p* = 1.
The memory is limited separately (see below): by default, the first example is rejected
anyway, because each thread would need 1 GiB.
The second example takes about 47 seconds on one thread, and at least 6 seconds
on 8 threads (16 MiB for each one).

Memory and threads
------------------

Only scrypt needs a significant amount of memory:

* *128·(N+2)·r* bytes for **each** thread, so a little more than *128·N·r* bytes;
* *256·r·p* bytes for all the flows together (their input and their output).

With *p* larger than 1, scrypt can run on up to *p* threads, as requested
with the ``threads`` parameter (see :func:`Crypto.Protocol.KDF.scrypt`).

``max_memory`` limits the **total** of all threads together, not each thread.
If the requested threads do not fit, fewer are used, down to one;
if a single thread does not fit, the key is rejected.

For instance, with the default limit of 256 MiB:

* *N* = 2\ :sup:`16` and *r* = 8 (a little more than 64 MiB for each thread):
  at most 3 threads are used, even with ``threads=4``;
* *N* = 2\ :sup:`17` and *r* = 8 (a little more than 128 MiB for each thread):
  only 1 thread is used;
* *N* = 2\ :sup:`18` and *r* = 8 (a little more than 256 MiB for one thread):
  the key is rejected.

Keys created by OpenSSL (at most 32 MiB) and by this library with the default
parameters (16 MiB) are well within the default limit.

OpenSSH keys and bcrypt
-----------------------

An encrypted OpenSSH private key (``-----BEGIN OPENSSH PRIVATE KEY-----``) derives
its key and IV with ``bcrypt_pbkdf``: at every round, it computes two bcrypt hashes
with cost 6 (about 3 ms in total on a recent x86-64 laptop, as the two run
interleaved on a single core).
The key states the number of rounds (up to 2\ :sup:`32`-1), and ``max_iteration_count``
limits it. The default limit of 16,384 rounds takes about one minute,
and it is far above what OpenSSH uses (16 rounds by default, with ``ssh-keygen -a``
to change it).

A key with less than one round is rejected, before any key derivation.
bcrypt needs very little memory (about 8 KiB), so ``max_memory`` does not apply.

bcrypt password hashes
----------------------

:func:`Crypto.Protocol.KDF.bcrypt_check` verifies a password against a bcrypt hash,
which states its own cost, from 4 to 31. The time doubles at every step:
cost 12 takes about 0.2 seconds on a recent x86-64 laptop, but cost 31 about one day.
A hash from an untrusted source (for instance, user accounts imported from elsewhere)
could therefore tie up the CPU.

For this reason, ``bcrypt_check()`` rejects a hash whose cost is above ``max_cost``,
before any hashing, with :class:`Crypto.KdfIterationLimitError` (a ``ValueError``):

* by default (``max_cost=None``), the limit is 20, about one minute;
* an explicit ``max_cost`` is the highest cost allowed;
* with ``max_cost=0``, no limit applies.

The usual costs for passwords (10 to 14) are well within the default limit.

Explicit limits
---------------

An explicit ``max_iteration_count`` is the maximum number of iterations
for PBKDF1 and PBKDF2, whatever the hash, the maximum *N·r·p/8* for scrypt,
and the maximum number of rounds for bcrypt_pbkdf (OpenSSH keys).
An explicit ``max_memory`` is the maximum number of bytes, for all threads together.

.. warning::

    The unit of ``max_iteration_count`` depends on the key derivation, and so does
    the time of one unit: about 0.1 to 1 microseconds for PBKDF2, but 3 milliseconds
    for bcrypt_pbkdf. A value chosen for PBKDF2 (for instance, 10,000,000) would allow
    an OpenSSH key with as many rounds, that is, about 9 hours.
    When the type of the key is not known in advance, keep the default (``None``).

With ``max_iteration_count=0`` or ``max_memory=0``, the corresponding limit does not apply.
Only use ``0`` with keys that come from a trusted source.

Both parameters must be integers (or ``None``), and not negative:
otherwise, ``TypeError`` or ``ValueError`` is raised,
even if the key turns out not to be encrypted.

Invalid parameters
------------------

Keys with parameters that make no sense are rejected with a ``ValueError``,
before any key derivation: an iteration count of PBKDF1 or PBKDF2 lower than 1,
or scrypt parameters other than a power of 2 (and at least 2) for *N*,
and positive values for *r* and *p* (RFC 7914).

The private key inside an RSA `PKCS#8`_ key must be an ``RSAPrivateKey``
(PKCS#1, RFC 8017): another container (for instance, another encrypted PKCS#8 key)
is rejected.

Errors
------

When a key is above a limit, the functions raise:

* :class:`Crypto.KdfIterationLimitError`, for ``max_iteration_count``
  (and :func:`Crypto.Protocol.KDF.bcrypt_check`, for ``max_cost``);
* :class:`Crypto.KdfMemoryLimitError`, for ``max_memory``.

Both are subclasses of :class:`Crypto.KdfLimitError`, which is a ``ValueError``.
Their message says which value is too high, and which limit applies.

For instance, to accept a trusted key that needs more memory than the default::

    >>> from Crypto import KdfMemoryLimitError
    >>> from Crypto.PublicKey import ECC
    >>>
    >>> try:
    ...     key = ECC.import_key(encrypted_key, passphrase)
    ... except KdfMemoryLimitError:
    ...     key = ECC.import_key(encrypted_key, passphrase, max_memory=2**30)

What is not covered
-------------------

* Private keys encrypted with the legacy PEM encryption (``Proc-Type: 4,ENCRYPTED``):
  their key derivation has a fixed, low cost.
* Password hashes checked with :func:`Crypto.Protocol.KDF.bcrypt_check`:
  they have their own limit, ``max_cost`` (see `bcrypt password hashes`_).

.. _`PKCS#8`: https://datatracker.ietf.org/doc/html/rfc5208
