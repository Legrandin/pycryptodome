.. image:: https://travis-ci.org/Legrandin/pycryptodome.svg?branch=master
   :target: https://travis-ci.org/Legrandin/pycryptodome

.. image:: https://ci.appveyor.com/api/projects/status/mbxyqdodw9ylfib9/branch/master?svg=true
   :target: https://ci.appveyor.com/project/Legrandin/pycryptodome

PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives.

It supports Python 2.4 or newer, all Python 3 versions and PyPy.

The installation procedure depends on the package you want the library in.
PyCryptodome can be used as:

#. **a drop-in replacement for the old PyCrypto library**.
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

For faster public key operations, you should have `GMP`_ installed in your system
(except on Windows, as the wheel on PyPi already comes bundled with the equivalent
`MPIR`_ library).

PyCryptodome is a fork of PyCrypto. It brings the following enhancements
with respect to the last official version of PyCrypto (2.6.1):

* Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
* Accelerated AES on Intel platforms via AES-NI
* First class support for PyPy
* Elliptic curves cryptography (NIST P-256 curve only)
* Better and more compact API (`nonce` and `iv` attributes for ciphers,
  automatic generation of random nonces and IVs, simplified CTR cipher mode,
  and more)
* SHA-3 (including SHAKE XOFs) and BLAKE2 hash algorithms
* Salsa20 and ChaCha20 stream ciphers
* scrypt and HKDF
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

All the code can be downloaded from `GitHub`_.

News
----

* **17 Oct 2016 (NEW)**. Bugfix release 3.4.3.
* 8 Mar 2016. Bugfix release 3.4.2.
* 21 Feb 2016. Release 3.4.1.
* 7 Feb 2016. Release 3.4.
* Nov 2015. Release 3.3.1.
* 29 Oct 2015. Release 3.3.
* 9 Sep 2015. Minor release 3.2.1.
* 6 Sep 2015. Release 3.2.
* 15 Mar 2015. Release 3.1.
* 24 Jun 2014. Release 3.0.

.. _`homepage`: http://www.pycryptodome.org
.. _`GMP`: https://gmplib.org
.. _`MPIR`: http://mpir.org
.. _GitHub: https://github.com/Legrandin/pycryptodome
