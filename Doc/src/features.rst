Features
--------

This page lists the low-level primitives that PyCryptodome provides.

You are expected to have a solid understanding of cryptography and security
engineering to successfully use them.

You must also be able to recognize that some primitives are obsolete (e.g. TDES)
or even unsecure (RC4). They are provided only to enable backward compatibility
where required by the applications.

A list of useful resources in that area can be found on `Matthew Green's blog`_.

* Symmetric ciphers:

  - AES
  - Single and Triple DES
  - CAST-128
  - RC2

* Traditional modes of operations for symmetric ciphers:

  - ECB
  - CBC
  - CFB
  - OFB
  - CTR
  - OpenPGP (a variant of CFB, RFC4880)

* AEAD modes of operations for symmetric ciphers:
  
  - CCM (AES only)
  - EAX
  - GCM (AES only)
  - SIV (AES only)

* Stream ciphers:

  - Salsa20
  - RC4

* Cryptographic hashes:

  - SHA-1
  - SHA-2 family (224, 256, 384, 512)
  - SHA-3 family (224, 256, 384, 512 - FIPS 202 draft May 2014)
  - RIPE-MD160
  - MD5

* Message Authentication Codes (MAC):
  
  - HMAC
  - CMAC

* Asymmetric key generation:
  
  - RSA
  - DSA
  - ElGamal

* Export and import format for asymmetric keys:
  
  - PEM (clear and encrypted)
  - PKCS#8 (clear and encrypted)
  - ASN.1 DER

* Asymmetric ciphers:
 
  - PKCS#1
    
    - RSAES-PKCS1-v1_5
    - RSAES-OAEP

* Asymmtric digital signatures:
  
  - PKCS#1
    
    - RSASSA-PKCS1-v1_5
    - RSASSA-PSS

  - DSA
    
    - FIPS 186-3
    - Deterministic (RFC6979)

* Key derivation:
 
  - PBKDF1
  - PBKDF2
  - scrypt
  - HKDF

* Other cryptographic protocols:
 
  - Shamir Secret Sharing
  - Padding
    
    - PKCS#7
    - ISO-7816
    - X.923

.. _`Matthew Green's blog`: http://blog.cryptographyengineering.com/p/useful-cryptography-resources.html
