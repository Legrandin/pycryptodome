Features
--------

* Symmetric cipher algorithms:

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

* Stream cipher algorithms:

  - Salsa20
  - RC4

* Hash algorithms:

  - SHA-1
  - SHA-2 family (224, 256, 384, 512)
  - SHA-3 family (224, 256, 384, 512 - FIPS 202 draft May 2014)
  - RIPE-MD160
  - MD5

* Message Authentication Code (MAC) algorithms:
  
  - HMAC
  - CMAC

* Key generation for asymmetric algorithms:
  
  - RSA
  - DSA
  - ElGamal

* Export and import format for asymmetric keys:
  
  - PEM (clear and encrypted)
  - PKCS#8 (clear and encrypted)
  - ASN.1 DER

* Public Key encryption algorithms:
 
  - PKCS#1
    
    - RSAES-PKCS1-v1_5
    - RSAES-OAEP

* Public Key signature algorithms:
  
  - PKCS#1
    
    - RSASSA-PKCS1-v1_5
    - RSASSA-PSS

  - DSA
    
    - FIPS 186-3
    - Deterministic (RFC6979)

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


