PyCryptodome
============

PyCryptodome is a self-contained, public domain Python package of low-level
cryptographic primitives.

It supports Python 2.4 or newer, all Python 3 versions and PyPy.

.. toctree::
   :maxdepth: 2

Features
--------

* Symmetric cipher algorithms:

  - AES
  - Single and Triple DES
  - CAST
  - RC2

* Simple modes of operations for symmetric ciphers:

  - ECB
  - CBC
  - CFB
  - OFB
  - CTR
  - OpenPGP

* AEAD modes of operations for symmetric ciphers:
  
  - CCM (AES only)
  - EAX
  - GCM (AES only)
  - SIV (AES only)

* Stream cipher algorithms:

  - Salsa20
  - RC4

* Hash algorithms:

  - SHA-1
  - SHA-2 family (224, 256, 384, 512)
  - SHA-3 family (224, 256, 384, 512)
  - RIPE-MD160
  - MD5

* Message Authentication Code (MAC) algorithm:
  
  - HMAC
  - CMAC

* Key generation for asymmetric cryptography algorithms:
  
  - RSA
  - DSA
  - ElGamal

* Export and import format for asymmetric keys:
  
  - PEM (clear and encrypted)
  - ASN.1 DER
  - PKCS#8 (clear and encrypted)

* Public Key encryption algorithms:
 
  - PKCS#1
    
    - RSAES-PKCS1-v1_5
    - RSAES-OAEP

* Public Key signature algorithms:
  
  - PKCS#1
    
    - RSASSA-PKCS1-v1_5
    - RSASSA-PSS

  - DSA (FIPS 186-3 and Deterministic)

* Key derivation algorithms:
 
  - PBKDF1
  - PBKDF2
  - scrypt
  - HKDF

* Other cryptographic protocols:
 
  - Shamir Secret Sharing
  - AllOrNothing
  - Chaffing
  - Padding
    
    - PKCS#7
    - ISO-7816
    - X.923

Installation
------------

.. code-block:: console

   $ pip install pycryptodome

API documentation
-----------------

The API can be found `here <http://legrandin.github.com/pycryptodome>`_.

PyCryptodome and PyCrypto
-------------------------
PyCryptodome is a recent fork of the `PyCrypto <https://www.dlitz.net/software/pycrypto>`_ project.
At that time, the last official PyCrypto release was v2.6 but v2.7 was imminent.

PyCryptodome resides in the same namespace of PyCrypto (``Crypto``).
If your system includes a packaged version of PyCrypto, it is recommended you only install
PyCryptodome in a *virtualenv* environment.

Contribute
----------

Support
-------

The PyCryptodome mailing list is hosted on `Google Groups <https://groups.google.com/forum/#!forum/pycryptodome>`_.
You can mail any comment or question to *pycryptodome@googlegroups.com*.

License
-------
The project is released to the public domain.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

