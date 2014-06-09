PyCryptodome and PyCrypto
-------------------------

PyCryptodome is a recent fork of the `PyCrypto <https://www.dlitz.net/software/pycrypto>`_ project.
At the time of the fork, the last official PyCrypto release was v2.6 and v2.7 was in alpha stage.

The fork took place because PyCrypto had been almost unmaintained for the past four years.
New features were considered for inclusion on average after more than 1 year they
were originally submitted, even if they concerned fundamental primitives for any modern
security software (PKCS#1 paddings, AEAD modes, tools for importing/exporting keys,
scrypt KDF, etc).

Additionally, it was felt that too little attention was paid to having a good, detailed
API documentation and too much to performance optimizations.

.. note::

        PyCryptodome resides in the same namespace of PyCrypto (``Crypto``).
        If your system includes a packaged version of PyCrypto, it is recommended you only install
        PyCryptodome in a *virtualenv* environment.

