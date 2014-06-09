The first release of PyCryptoDome (3.0) is only meant to repackage
the current alpha version of PyCrypto (2.7), add features that
cannot be delayed anymore (``scrypt``, MSVC support, etc) and remove
the most obvious cruft (``autoconf``, user-space CSPRNG, etc).
This is also the right time to break backward compatibility
(no more default ECB mode for ciphers, no ``Crypto.Random.OS`` package,
no more dangerous public key methods, etc).

Future releases will include:

- Clean up the Crypto.PublicKey API to reduce the call depth
- Move API documentation from epydoc to sphinx
- Add algorithms:
    - ChaCha20
    - Poly1305
    - BLAKE2
    - Elliptic Curves (ECDSA, ECIES, ECDH)
    - Camellia, GOST
    - Diffie-Hellman
    - bcrypt
    - SRP
- Add more key management:
    - Export/import of DSA keys
    - Export/import of EC keys
    - JWK
- Add support for CMS/PKCS#7
- Add the complete set of NIST test vectors for the various algorithms
- Add CI (including coverage)
- Remove dependency on libtomcrypto headers
- Speed up (T)DES with a bitsliced implementation
- Add support for PCLMULQDQ in AES-GCM
- Coverage testing
- Run lint on the C code
