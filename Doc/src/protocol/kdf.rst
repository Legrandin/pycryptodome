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

New applications and protocols should use :ref:`scrypt <scrypt_func>` or :ref:`bcrypt <bcrypt_func>` instead.

For example, if you need to derive two AES256 keys::

    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
    from Crypto.Random import get_random_bytes

    password = b'my super secret'
    salt = get_random_bytes(16)
    keys = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
    key1 = keys[:32]
    key2 = keys[32:]

.. autofunction:: Crypto.Protocol.KDF.PBKDF2

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
    from Crypto.Protocol.KDF import bcrypt

    password_to_test = b"test"
    try:
        b64pwd = b64encode(SHA256.new(password).digest())
        bcrypt_check(b64pwd, bcrypt_hash)
    except ValueError:
        print("Incorrect password")

.. warning:
    The output of ``bcrypt`` is only meant to be stored. It is not meant to be
    used as key material.

.. _bcrypt_func:

.. autofunction:: Crypto.Protocol.KDF.bcrypt
.. autofunction:: Crypto.Protocol.KDF.bcrypt_check

HKDF
+++++

The HMAC-based Extract-and-Expand key derivation function (HKDF) was `designed by Hugo Krawczyk <https://eprint.iacr.org/2010/264.pdf>`_.
It is standardized in `RFC 5869 <https://tools.ietf.org/html/rfc5869>`_ and in `NIST SP-800 56C <http://csrc.nist.gov/publications/nistpubs/800-56C/SP-800-56C.pdf>`_.

This KDF is not suitable for deriving keys from a password or for key stretching.

Example, for deriving two AES256 keys::

    from Crypto.Protocol import HKDF
    from Crypto.Hash import SHA512
    from Crypto.Random import get_random_bytes

    salt = get_random_bytes(16)
    key1, key2 = HKDF(master_secret, 32, salt, SHA512, 2)

.. autofunction:: Crypto.Protocol.KDF.HKDF

PBKDF1
+++++++

PBKDF1 is an old key derivation function defined in version 2.0 of the PKCS#5 standard (v1.5) or in `RFC2898 <https://www.ietf.org/rfc/rfc2898.txt>`_.

.. warning::
    Newer applications should use the more secure and versatile :ref:`scrypt <scrypt_func>` instead.

.. autofunction:: Crypto.Protocol.KDF.PBKDF1
