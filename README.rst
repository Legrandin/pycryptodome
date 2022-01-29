.. image:: https://github.com/Legrandin/pycryptodome/workflows/Integration%20test/badge.svg?branch=master
   :target: https://github.com/Legrandin/pycryptodome/actions

PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives.

It supports Python 2.7, Python 3.5 and newer, and PyPy.

The installation procedure depends on the package you want the library to be in.
PyCryptodome can be used as:

#. **an almost drop-in replacement for the old PyCrypto library**.
   You install it with::

       pip install pycryptodome

   In this case, all modules are installed under the ``Crypto`` package.

   One must avoid having both PyCrypto and PyCryptodome installed
   at the same time, as they will interfere with each other.

   This option is therefore recommended only when you are sure that
   the whole application is deployed in a ``virtualenv``.

#. **a library independent of the old PyCrypto**.
   You install it with::

       pip install pycryptodomex

   In this case, all modules are installed under the ``Cryptodome`` package.
   PyCrypto and PyCryptodome can coexist.

For faster public key operations in Unix, you should install `GMP`_ in your system.

PyCryptodome is a fork of PyCrypto. It brings the following enhancements
with respect to the last official version of PyCrypto (2.6.1):

* Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
* Accelerated AES on Intel platforms via AES-NI
* First class support for PyPy
* Elliptic curves cryptography (NIST curves P-192, P-224, P-256, P-384 and P-521)
* Better and more compact API (`nonce` and `iv` attributes for ciphers,
  automatic generation of random nonces and IVs, simplified CTR cipher mode,
  and more)
* SHA-3 hash algorithms (FIPS 202) and derived functions (NIST SP-800 185):

  - SHAKE128 and SHA256 XOFs
  - cSHAKE128 and cSHAKE256 XOFs
  - KMAC128 and KMAC256
  - TupleHash128 and TupleHash256

* KangarooTwelve XOF (derived from Keccak)
* Truncated hash algorithms SHA-512/224 and SHA-512/256 (FIPS 180-4)
* BLAKE2b and BLAKE2s hash algorithms
* Salsa20 and ChaCha20/XChaCha20 stream ciphers
* Poly1305 MAC
* ChaCha20-Poly1305 and XChaCha20-Poly1305 authenticated ciphers
* scrypt, bcrypt and HKDF derivation functions
* Deterministic (EC)DSA
* Password-protected PKCS#8 key containers
* Shamir's Secret Sharing scheme
* Random numbers get sourced directly from the OS (and not from a CSPRNG in userspace)
* Simplified install process, including better support for Windows
* Cleaner RSA and DSA key generation (largely based on FIPS 186-4)
* Major clean ups and simplification of the code base

PyCryptodome is not a wrapper to a separate C library like *OpenSSL*.
To the largest possible extent, algorithms are implemented in pure Python.
Only the pieces that are extremely critical to performance (e.g. block ciphers)
are implemented as C extensions.

For more information, see the `homepage`_.

For security issues, please send an email to security@pycryptodome.org.

All the code can be downloaded from `GitHub`_.

.. _`homepage`: https://www.pycryptodome.org
.. _`GMP`: https://gmplib.org
.. _GitHub: https://github.com/Legrandin/pycryptodome
