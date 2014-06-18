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

PyCryptodome and PyCrypto
-------------------------

PyCryptodome is a recent fork of the `PyCrypto <https://www.dlitz.net/software/pycrypto>`_ project.
At the time of the fork (May 2014), the last official PyCrypto release was v2.6 and v2.7 was in alpha stage.

The fork took place because PyCrypto had gone almost unmaintained for the past four years.
New features were considered for inclusion on average after more than 1 year they
were originally submitted, even if they concerned fundamental primitives for any modern
security software (PKCS#1 paddings, AEAD modes, tools for importing/exporting keys,
scrypt KDF, etc).

Additionally, it was felt that too little attention was paid to having a good, detailed
API documentation and too much to performance optimizations.

.. _GitHub: https://github.com/Legrandin/pycryptodome
