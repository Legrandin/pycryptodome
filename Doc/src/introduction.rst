Introduction
============

PyCryptodome is a self-contained, public domain Python package of low-level
cryptographic primitives.

It supports Python 2.4 or newer, all Python 3 versions and PyPy.

All the code can be downloaded from `GitHub`_.

PyCryptodome is not a wrapper to a separate C library like *OpenSSL*.
To the largest possible extent, algorithms are implemented in pure Python.
Only the pieces that are extremely critical to performance (e.g. block ciphers)
are implemented as C extensions.

News
----

* **9 Sep 2015 (NEW)**. Minor release 3.2.1.
* 6 Sep 2015. Release 3.2.
* 15 Mar 2015. Release 3.1.
* 24 Jun 2014. Release 3.0.

PyCryptodome and PyCrypto
-------------------------

PyCryptodome is a fork of the `PyCrypto <https://www.dlitz.net/software/pycrypto>`_ project.

It brings the following enhancements with respect to the last official version of PyCrypto (2.6.1):

* Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
* Accelerated AES on Intel platforms via AES-NI
* First class support for PyPy
* SHA-3 (including SHAKE XOFs) and BLAKE2 hash algorithms
* Salsa20 stream cipher
* scrypt and HKDF
* Deterministic DSA
* Password-protected PKCS#8 key containers
* Shamir's Secret Sharing scheme
* Random numbers get sourced directly from the OS (and not from a CSPRNG in userspace)
* Simplified install process, including better support for Windows
* FIPS 186-4 compliant RSA key generation
* Major clean ups and simplification of the code base

The fork took place because of the very bad state PyCrypto was in,
and the little maintanance it was receiving.

.. _GitHub: https://github.com/Legrandin/pycryptodome
