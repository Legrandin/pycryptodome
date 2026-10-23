Features
--------

This page lists the low-level primitives that PyCryptodome provides.

You are expected to have a solid understanding of cryptography and security
engineering to successfully use them.

You must also be able to recognize that some primitives are obsolete (e.g. TDES)
or even insecure (e.g. RC4). They are marked as *legacy* below, and they are provided
only to enable backward compatibility where required by the applications.

* Block ciphers:

  - AES
  - Single and Triple DES (legacy)
  - CAST-128 (legacy)
  - RC2 (legacy)
  - Blowfish (legacy)

* Traditional modes of operation for block ciphers:

  - ECB
  - CBC
  - CFB
  - OFB
  - CTR
  - OpenPGP (a variant of CFB, RFC 4880)

* Authenticated encryption:

  - GCM (AES only)
  - CCM (AES only)
  - OCB (AES only)
  - SIV (AES only)
  - EAX
  - ChaCha20-Poly1305 and XChaCha20-Poly1305

* Key wrapping:

  - KW and KWP (AES only, NIST SP 800-38F)

* Stream ciphers:

  - ChaCha20 and XChaCha20
  - Salsa20
  - RC4 (legacy)

* Cryptographic hashes:

  - SHA-2 hashes (224, 256, 384, 512, 512/224, 512/256)
  - SHA-3 hashes (224, 256, 384, 512)
  - BLAKE2b and BLAKE2s
  - TupleHash128 and TupleHash256 (derived from SHA-3)
  - Keccak (original submission to SHA-3)
  - SHA-1 (legacy)
  - RIPEMD-160 (legacy)
  - MD5, MD4 and MD2 (legacy)

* Extendable-output functions (XOF):

  - SHAKE128 and SHAKE256
  - cSHAKE128 and cSHAKE256
  - KangarooTwelve
  - TurboSHAKE128 and TurboSHAKE256

* Message Authentication Codes (MAC):

  - HMAC
  - CMAC
  - KMAC128 and KMAC256
  - Poly1305

* Asymmetric keys (generation, import and export):

  - RSA
  - ECC: NIST P-curves (P-192, P-224, P-256, P-384, P-521), Ed25519 and Ed448,
    Curve25519 (X25519) and Curve448 (X448)
  - ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65 and ML-DSA-87
  - ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768 and ML-KEM-1024
  - Hybrid KEMs: MLKEM768-X25519 (X-Wing)
  - DSA
  - ElGamal (legacy)

* Formats for asymmetric keys:

  - PEM and ASN.1 DER
  - PKCS#8, in clear or encrypted (with PBKDF2 or scrypt)
  - PKCS#1 (RSA) and SEC1 (ECC)
  - X.509 ``SubjectPublicKeyInfo``, and public keys in X.509 certificates (import only)
  - OpenSSH, including encrypted private keys (RSA and ECC)
  - Raw encoding of Ed25519, Ed448, X25519 and X448 keys

* Asymmetric encryption:

  - RSAES-OAEP (PKCS#1)
  - RSAES-PKCS1-v1_5 (PKCS#1, legacy)

* Digital signatures:

  - RSASSA-PSS and RSASSA-PKCS1-v1_5 (PKCS#1)
  - DSA and ECDSA, with random nonces (FIPS 186-3) or deterministic nonces (RFC 6979)
  - EdDSA with Ed25519 and Ed448 (RFC 8032), including the pre-hashed variants
  - ML-DSA and HashML-DSA (FIPS 204), hedged or deterministic

* Key agreement:

  - Elliptic-curve Diffie-Hellman (NIST P-curves, X25519, X448),
    with static or ephemeral keys (NIST SP 800-56A)

* Key derivation:

  - PBKDF2
  - scrypt
  - bcrypt
  - HKDF
  - NIST SP 800-108 (counter mode)
  - PBKDF1 (legacy)

* Other cryptographic protocols:

  - HPKE (RFC 9180), also post-quantum with ML-KEM or the hybrid KEMs (draft-ietf-hpke-pq)
  - Shamir's secret sharing
  - Padding

    - PKCS#7
    - ISO 7816-4
    - X.923

Implementation
~~~~~~~~~~~~~~

* All the code runs in the package itself (C extensions and Python),
  with no system libraries. Randomness comes from the operating system.
* The big integer arithmetic of RSA, DSA, ElGamal and ECC runs in constant time,
  in C. RSA private key operations are blinded, and the scalar multiplications on
  elliptic curves have further countermeasures (scalar blinding, randomized coordinates).
* The CPU extensions are used when present: AES-NI and CLMUL (AES and GCM),
  the SHA extensions (SHA-224 and SHA-256), AVX2 (SHA-3 and the other Keccak-based functions,
  ChaCha20 and Salsa20), and BMI2 and ADX (big integers and NIST curves).
* Long messages can be processed on several CPU cores (parameter ``threads``):
  CTR, GCM and OCB modes, ChaCha20 and XChaCha20, and scrypt.
