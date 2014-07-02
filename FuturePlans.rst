The first release of PyCryptoDome (3.0) is only meant to repackage
the current alpha version of PyCrypto (2.7), add features that
cannot be delayed anymore (``scrypt``, MSVC support, etc) and remove
the most obvious cruft (``autoconf``, user-space CSPRNG, etc).
This is also the right time to break backward compatibility
(no more default ECB mode for ciphers, no ``Crypto.Random.OS`` package,
no more dangerous public key methods, etc).

Future releases will include:

- Break-up blockalgo.py (and if possible block_template.c too)
  in more manageable modules
- Clean up the Crypto.PublicKey API to reduce the call depth
- Add back support for MPIR on Windows, or
  investigate performance of other, smaller arbitrary-precision arithmetic libaries
- Move API documentation from epydoc to sphinx
- Add ability to import keys from X.509 certificates
- Add algorithms:
    - ChaCha20
    - Poly1305
    - BLAKE2
    - Elliptic Curves (ECDSA, ECIES, ECDH)
    - Camellia, GOST
    - OCB cipher mode
    - Diffie-Hellman
    - bcrypt
    - SRP
- Speed up execution on pypy (via ctypes?)
- Add more key management:
    - Export/import of DSA keys
    - Export/import of EC keys
    - JWK
- Add support for CMS/PKCS#7
- Add support for RNG backed by PKCS#11 and/or KMIP
- Add support for Format-Preserving Encryption
- Add the complete set of NIST test vectors for the various algorithms
- Remove dependency on libtomcrypto headers
- Speed up (T)DES with a bitsliced implementation
- Add support for PCLMULQDQ in AES-GCM
- Coverage testing
- Run lint on the C code
- Add (minimal) support for PGP
