Key Derivation Functions
========================

This module contains a collection of standard key derivation functions.

A key derivation function derives one or more secondary secret keys from
one primary secret (a master key or a pass phrase).

This is typically done to insulate the secondary keys from each other,
to avoid that leakage of a secondary key compromises the security of the
master key, or to thwart attacks on pass phrases (e.g. via rainbow tables).

PBKDF2
+++++++

PBKDF2 is the most widespread algorithm for deriving keys from a password,
originally defined in version 2.0 of the PKCS#5 standard or in `RFC2898 <https://www.ietf.org/rfc/rfc2898.txt>`_.

It is computationally expensive (a property that can be tuned via the ``count`` parameter) so as to thwart dictionary and rainbow tables attacks.
However, it uses a very limited amount of RAM which makes it insufficiently
protected against advanced and motivated adversaries that can leverage GPUs.

New applications and protocols should use :ref:`Argon2id <argon2_func>`, :ref:`scrypt <scrypt_func>`
or :ref:`bcrypt <bcrypt_func>` instead.

Always pass the ``count`` and ``hmac_hash_module`` parameters: their defaults
(1000 iterations and HMAC-SHA1) are weak, deprecated (they emit a :class:`DeprecationWarning`),
and will be removed.

For example, if you need to derive two AES256 keys::

    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
    from Crypto.Random import get_random_bytes

    password = b'my super secret'
    salt = get_random_bytes(16)
    keys = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:32]
    key2 = keys[32:]

.. _pbkdf2_func:

.. autofunction:: Crypto.Protocol.KDF.PBKDF2

.. _argon2_func:

Argon2
+++++++

`Argon2 <https://www.rfc-editor.org/rfc/rfc9106>`_ (RFC 9106) is the winner of the
`Password Hashing Competition <https://www.password-hashing.net/>`_.
It is memory-hard, like scrypt: an attacker needs as much memory as you
for every password they try, which makes GPUs and custom hardware much less effective.

It comes in three variants (:class:`Argon2Variant <Crypto.Protocol.KDF.Argon2Variant>`).
Use **Argon2id**, the default and the variant recommended by RFC 9106.
Argon2d is slightly stronger against cracking hardware, but its memory accesses
depend on the password, so it leaks information through cache timing
to an attacker who can run code on the same machine.
Argon2i avoids that leak, but it is weaker against other attacks;
Argon2id combines the two.

The module offers three functions:

* :func:`argon2() <Crypto.Protocol.KDF.argon2>` derives keys from a password, like :func:`~Crypto.Protocol.KDF.scrypt`;
* :func:`argon2_hash() <Crypto.Protocol.KDF.argon2_hash>` and
  :func:`argon2_check() <Crypto.Protocol.KDF.argon2_check>` store and check passwords,
  like :func:`~Crypto.Protocol.KDF.bcrypt` and :func:`~Crypto.Protocol.KDF.bcrypt_check`, in the PHC string format
  (``$argon2id$v=19$m=65536,t=3,p=4$...``) used by most other implementations.

To store a password, and check it later::

    from Crypto.Protocol.KDF import argon2_check, argon2_hash

    stored = argon2_hash("correct horse battery staple")
    # b'$argon2id$v=19$m=65536,t=3,p=4$...$...'

    try:
        argon2_check("correct horse battery staple", stored)
    except ValueError:
        print("Incorrect password")

The hash contains the parameters and the random salt: you only need to store it.

To derive a key, for instance to encrypt a file::

    from Crypto.Protocol.KDF import Argon2Profile, argon2
    from Crypto.Random import get_random_bytes

    salt = get_random_bytes(16)
    key = argon2("correct horse battery staple", 32, salt=salt,
                 profile=Argon2Profile.RFC9106_2021_64MIB)

You need the same salt (and the same parameters) to derive the same key again,
so store the salt with the encrypted data.

Choosing the parameters
~~~~~~~~~~~~~~~~~~~~~~~

Argon2 has three costs:

* ``memory_cost`` (*m*): the memory, in **KiB**;
* ``time_cost`` (*t*): the number of passes over the memory;
* ``lanes`` (*p*): the number of lanes that the memory is divided into.

They are easier to choose from a *profile*: a member of
:class:`Argon2Profile <Crypto.Protocol.KDF.Argon2Profile>`,
named after the document that recommends it, and the year:

.. argon2-profiles::

A profile never changes, and it is never removed:
``profile=Argon2Profile.RFC9106_2021_64MIB`` derives the same key in every version
of this library. All of them use Argon2id, a 16-byte salt and a 32-byte tag.

Which profile?

* **To store passwords on a server**, the default of :func:`~Crypto.Protocol.KDF.argon2_hash`
  (currently ``RFC9106_2021_64MIB``).
  With many concurrent logins and little memory, ``OWASP_2023_19MIB``.
* **To derive a key to encrypt a file**, ``RFC9106_2021_2GIB`` if 2 GiB are available,
  otherwise ``RFC9106_2021_64MIB``.
* **To derive the same keys as libsodium** (``crypto_pwhash()`` with Argon2id),
  the matching ``LIBSODIUM_2017_*`` profile.

The profiles are generic. RFC 9106 (Section 4) recommends tuning the parameters for
your own hardware instead: choose the largest amount of memory that you can afford,
and then the largest number of passes that fits your time budget.
You can pass the parameters explicitly, or override part of a profile::

    # A profile, on a single lane
    key = argon2(password, 32, salt=salt, profile=Argon2Profile.RFC9106_2021_64MIB, lanes=1)

    # Explicit parameters: all of time_cost, memory_cost and lanes
    key = argon2(password, 32, salt=salt, time_cost=2, memory_cost=512 * 1024, lanes=4)

The parameters of :func:`~Crypto.Protocol.KDF.argon2_hash` are stored in the hash,
so you can raise them later for new passwords, and still check the old ones.
With :func:`~Crypto.Protocol.KDF.argon2`, you must use the same parameters to get the same key.

Lanes and threads
~~~~~~~~~~~~~~~~~

``lanes`` is part of the result, while ``threads`` only decides how fast it comes,
as for scrypt's ``p``. The lanes can be computed in parallel, on up to ``lanes``
threads::

    key = argon2(password, 32, salt=salt, profile=Argon2Profile.RFC9106_2021_64MIB, threads=4)

With ``threads=0``, Argon2 uses as many threads as the CPU cores available to the process.
The output does not depend on the number of threads, and all threads share
the same memory.

Hashes from untrusted sources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An Argon2 hash states its own parameters, so a malicious hash can ask for
terabytes of memory or hours of work. :func:`~Crypto.Protocol.KDF.argon2_check` rejects a hash that
needs more than 256 MiB of memory (``max_memory``, in bytes), or whose passes times
memory exceed :math:`2^{25}` KiB, about one minute on a recent laptop (``max_cost``):
see :ref:`the limits<pkcs8_limits>`.

.. autoclass:: Crypto.Protocol.KDF.Argon2Variant
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: Crypto.Protocol.KDF.Argon2Profile
    :members: RFC9106_2021_2GIB, RFC9106_2021_64MIB, OWASP_2023_19MIB,
              LIBSODIUM_2017_INTERACTIVE, LIBSODIUM_2017_MODERATE, LIBSODIUM_2017_SENSITIVE
    :member-order: bysource

.. autoclass:: Crypto.Protocol.KDF.Argon2Params
    :members:
    :member-order: bysource

.. autodata:: Crypto.Protocol.KDF.ARGON2_DEFAULT_PROFILE
    :no-value:

.. autofunction:: Crypto.Protocol.KDF.argon2
.. autofunction:: Crypto.Protocol.KDF.argon2_hash
.. autofunction:: Crypto.Protocol.KDF.argon2_check

scrypt
+++++++

`scrypt <http://www.tarsnap.com/scrypt.html>`_ is a password-based key derivation function created by Colin Percival,
described in his paper `"Stronger key derivation via sequential memory-hard functions" <http://www.tarsnap.com/scrypt/scrypt.pdf>`_
and in `RFC7914 <https://tools.ietf.org/html/rfc7914>`_.

In addition to being computationally expensive, it is also memory intensive and
therefore more secure against the risk of custom ASICs.

Example::

    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes

    password = b'my super secret'
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 16, N=2**14, r=8, p=1)

With a parallelization parameter ``p`` larger than 1, scrypt computes ``p``
independent flows, which can run on several CPU cores with the ``threads`` parameter::

    key = scrypt(password, salt, 16, N=2**14, r=8, p=4, threads=4)

With ``threads=0``, it uses as many threads as the CPU cores available to the process.
The output does not depend on the number of threads, but each thread
uses its own :math:`128 \cdot r \cdot N` bytes of memory, at the same time:
with 4 threads, scrypt needs 4 times as much memory as with one.

.. _scrypt_func:

.. autofunction:: Crypto.Protocol.KDF.scrypt


bcrypt
+++++++

`bcrypt <https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node1.html>`_ is a password hashing function designed by Niels Provos and David Mazières.

In addition to being computationally expensive, it is also memory intensive and
therefore more secure against the risk of custom ASICs.

This implementation only supports bcrypt hashes with prefix ``$2a``.

By design, ``bcrypt`` only accepts passwords up to 72 byte long.
If you want to hash passwords with no restrictions on their length, it is common practice to apply a cryptographic hash and then BASE64-encode
For instance::

    from base64 import b64encode
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import bcrypt

    password = b"test"
    b64pwd = b64encode(SHA256.new(password).digest())
    bcrypt_hash = bcrypt(b64pwd, 12)

and to check them::

    from base64 import b64encode
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import bcrypt_check

    password_to_test = b"test"
    try:
        b64pwd = b64encode(SHA256.new(password_to_test).digest())
        bcrypt_check(b64pwd, bcrypt_hash)
    except ValueError:
        print("Incorrect password")

The bcrypt hash states its own cost (up to 31), and the time doubles at every step.
To protect against a hash from an untrusted source, :func:`bcrypt_check` rejects
a cost above 20 (about one minute on a recent laptop): use the parameter ``max_cost``
to change this limit (see :ref:`the limits<pkcs8_limits>`).

.. warning::
    The output of ``bcrypt`` is only meant to be stored. It is not meant to be
    used as key material.

.. _bcrypt_func:

.. autofunction:: Crypto.Protocol.KDF.bcrypt
.. autofunction:: Crypto.Protocol.KDF.bcrypt_check

.. _hkdf:

HKDF
+++++

The HMAC-based Extract-and-Expand key derivation function (HKDF) was `designed by Hugo Krawczyk <https://eprint.iacr.org/2010/264.pdf>`_.
It is standardized in `RFC 5869 <https://tools.ietf.org/html/rfc5869>`_ and in `NIST SP-800 56C <http://csrc.nist.gov/publications/nistpubs/800-56C/SP-800-56C.pdf>`_.

This KDF is not suitable for deriving keys from a password or for key stretching.

Example, for deriving two AES256 keys::

    from Crypto.Protocol.KDF import HKDF
    from Crypto.Hash import SHA512
    from Crypto.Random import get_random_bytes

    salt = get_random_bytes(16)
    key1, key2 = HKDF(master_secret, 32, salt, SHA512, 2)

.. autofunction:: Crypto.Protocol.KDF.HKDF

.. _sp800-108-counter:

SP 800-108 Counter Mode
++++++++++++++++++++++++

A KDF can be generically constructed with a pseudorandom function (PRF).
If the PRF has a fixed-length output,
you can evaluate the PRF multiple times and concatenate the results until you collect enough derived keying material.

This function implements such type of KDF, where a counter contributes to each invokation of the PRF, as defined in
`NIST SP 800-108 Rev 1 <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf>`_.
The NIST standard only allows the use of HMAC (recommended) and CMAC (not recommended) as PRF.

This KDF is not suitable for deriving keys from a password.

Example 1 (HMAC as PRF, one AES128 key to derive)::

    >> from Crypto.Hash import SHA256, HMAC
    >>
    >> def prf(s, x):
    >>     return HMAC.new(s, x, SHA256).digest()
    >>
    >> key_derived = SP800_108_Counter(secret, 16, prf, label=b'Key A')

Example 2 (HMAC as PRF, two AES128 keys to derive)::

    >> from Crypto.Hash import SHA256, HMAC
    >>
    >> def prf(s, x):
    >>     return HMAC.new(s, x, SHA256).digest()
    >>
    >> key_A, key_B = SP800_108_Counter(secret, 16, prf, num_keys=2, label=b'Key AB')

Example 3 (CMAC as PRF, two AES256 keys to derive)::

    >> from Crypto.Cipher import AES
    >> from Crypto.Hash import SHA256, CMAC
    >>
    >> def prf(s, x):
    >>     return CMAC.new(s, x, AES).digest()
    >>
    >> key_A, key_B = SP800_108_Counter(secret, 32, prf, num_keys=2, label=b'Key AB')

.. autofunction:: Crypto.Protocol.KDF.SP800_108_Counter

PBKDF1
+++++++

PBKDF1 is an old key derivation function defined in version 2.0 of the PKCS#5 standard (v1.5) or in `RFC2898 <https://www.ietf.org/rfc/rfc2898.txt>`_.

.. warning::
    Newer applications should use the more secure and versatile :ref:`scrypt <scrypt_func>` instead.

.. _pbkdf1_func:

.. autofunction:: Crypto.Protocol.KDF.PBKDF1
