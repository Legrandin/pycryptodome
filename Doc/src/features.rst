Features
--------

.. role:: legacy

This page lists the algorithms and formats that PyCryptodome provides.
If you are not sure which one to use, start from the :doc:`guides </src/guides/index>`,
which recommend one for each common task.

These are low-level primitives: combining them into a secure system on your own
requires a good understanding of cryptography.

Some primitives are obsolete (e.g. TDES) or even insecure (e.g. RC4).
They are marked as :legacy:`legacy` below, and they are provided only for backward compatibility.

Block ciphers
~~~~~~~~~~~~~

.. rst-class:: two-columns

* :doc:`AES </src/cipher/aes>`
* :doc:`Single </src/cipher/des>` and :doc:`Triple </src/cipher/des3>` DES :legacy:`legacy`
* :doc:`CAST-128 </src/cipher/cast>` :legacy:`legacy`
* :doc:`RC2 </src/cipher/arc2>` :legacy:`legacy`
* :doc:`Blowfish </src/cipher/blowfish>` :legacy:`legacy`

Traditional modes of operation for block ciphers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :ref:`ECB <ecb_mode>`
* :ref:`CBC <cbc_mode>`
* :ref:`CFB <cfb_mode>`
* :ref:`OFB <ofb_mode>`
* :ref:`CTR <ctr_mode>`
* :ref:`OpenPGP <openpgp_mode>` (a variant of CFB, RFC 4880)

Authenticated encryption
~~~~~~~~~~~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :ref:`GCM <gcm_mode>` (AES only)
* :ref:`CCM <ccm_mode>` (AES only)
* :ref:`OCB <ocb_mode>` (AES only)
* :ref:`SIV <siv_mode>` (AES only)
* :ref:`GCM-SIV <gcm_siv_mode>` (AES only, RFC 8452)
* :ref:`EAX <eax_mode>`
* :doc:`ChaCha20-Poly1305 and XChaCha20-Poly1305 </src/cipher/chacha20_poly1305>`

Key wrapping
~~~~~~~~~~~~

* :ref:`KW <kw_mode>` and :ref:`KWP <kwp_mode>` (AES only, NIST SP 800-38F)

Stream ciphers
~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :doc:`ChaCha20 and XChaCha20 </src/cipher/chacha20>`
* :doc:`Salsa20 </src/cipher/salsa20>`
* :doc:`RC4 </src/cipher/arc4>` :legacy:`legacy`

Cryptographic hashes
~~~~~~~~~~~~~~~~~~~~

* SHA-2 hashes (:doc:`224 </src/hash/sha224>`, :doc:`256 </src/hash/sha256>`,
  :doc:`384 </src/hash/sha384>`, :doc:`512, 512/224, 512/256 </src/hash/sha512>`)
* SHA-3 hashes (:doc:`224 </src/hash/sha3_224>`, :doc:`256 </src/hash/sha3_256>`,
  :doc:`384 </src/hash/sha3_384>`, :doc:`512 </src/hash/sha3_512>`)
* :doc:`BLAKE2b </src/hash/blake2b>` and :doc:`BLAKE2s </src/hash/blake2s>`
* :doc:`TupleHash128 </src/hash/tuplehash128>` and :doc:`TupleHash256 </src/hash/tuplehash256>`
  (derived from SHA-3)
* :doc:`Keccak </src/hash/keccak>` (original submission to SHA-3)
* :doc:`SHA-1 </src/hash/sha1>` :legacy:`legacy`
* :doc:`RIPEMD-160 </src/hash/ripemd160>` :legacy:`legacy`
* :doc:`MD5 </src/hash/md5>`, :doc:`MD4 </src/hash/md4>` and :doc:`MD2 </src/hash/md2>` :legacy:`legacy`

Extendable-output functions (XOF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :doc:`SHAKE128 </src/hash/shake128>` and :doc:`SHAKE256 </src/hash/shake256>`
* :doc:`cSHAKE128 </src/hash/cshake128>` and :doc:`cSHAKE256 </src/hash/cshake256>`
* :doc:`KangarooTwelve </src/hash/k12>`
* :doc:`TurboSHAKE128 and TurboSHAKE256 </src/hash/turboshake>`

Message Authentication Codes (MAC)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :doc:`HMAC </src/hash/hmac>`
* :doc:`CMAC </src/hash/cmac>`
* :doc:`KMAC128 </src/hash/kmac128>` and :doc:`KMAC256 </src/hash/kmac256>`
* :doc:`Poly1305 </src/hash/poly1305>`

Asymmetric keys (generation, import and export)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* :doc:`RSA </src/public_key/rsa>`
* :doc:`ECC </src/public_key/ecc>`: NIST P-curves (P-192, P-224, P-256, P-384, P-521),
  secp256k1, Ed25519 and Ed448, Curve25519 (X25519) and Curve448 (X448)
* :doc:`ML-DSA </src/public_key/mldsa>` (FIPS 204): ML-DSA-44, ML-DSA-65 and ML-DSA-87
* :doc:`ML-KEM </src/public_key/mlkem>` (FIPS 203): ML-KEM-512, ML-KEM-768 and ML-KEM-1024,
  for use with HPKE only (no direct encapsulation or decapsulation)
* :doc:`Hybrid KEM </src/public_key/hybrid>`: MLKEM768-X25519 (X-Wing), for use with HPKE only
* :doc:`DSA </src/public_key/dsa>`
* :doc:`ElGamal </src/public_key/elgamal>` :legacy:`legacy`

Formats for asymmetric keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* :doc:`PEM </src/io/pem>` (also with the legacy encryption of RFC 1423)
  and :doc:`ASN.1 DER </src/util/asn1>`
* :doc:`PKCS#8 </src/io/pkcs8>`, in clear or encrypted (with PBKDF2 or scrypt, and AES in CBC or GCM mode),
  also for ML-DSA and ML-KEM keys
* PKCS#1 (RSA) and SEC1 (ECC)
* X.509 ``SubjectPublicKeyInfo``, and public keys in X.509 certificates (import only)
* OpenSSH: public keys (import and export), and private keys of RSA and ECC,
  also encrypted (import only)
* Raw encoding of Ed25519, Ed448, X25519 and X448 keys

Asymmetric encryption
~~~~~~~~~~~~~~~~~~~~~

* :ref:`HPKE <hpke>` (RFC 9180), in all four modes (base, PSK, auth, auth-PSK), with AES-GCM or ChaCha20-Poly1305,
  also post-quantum with ML-KEM or the hybrid KEM X-Wing (draft-ietf-hpke-pq)
* :doc:`RSAES-OAEP </src/cipher/oaep>` (PKCS#1)
* :doc:`RSAES-PKCS1-v1_5 </src/cipher/pkcs1_v1_5>` (PKCS#1) :legacy:`legacy`

Key encapsulation (only as part of HPKE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* :doc:`ML-KEM </src/public_key/mlkem>` (FIPS 203)
* :doc:`Hybrid KEM </src/public_key/hybrid>`: MLKEM768-X25519 (X-Wing)

Digital signatures
~~~~~~~~~~~~~~~~~~

* :doc:`RSASSA-PSS </src/signature/pkcs1_pss>` and :doc:`RSASSA-PKCS1-v1_5 </src/signature/pkcs1_v1_5>` (PKCS#1)
* :doc:`DSA and ECDSA </src/signature/dsa>`, with random nonces (FIPS 186-3, or SEC 1 for ECDSA)
  or deterministic nonces (RFC 6979) and, for ECDSA, optionally in the low-S form
* :doc:`EdDSA </src/signature/eddsa>` with Ed25519 and Ed448 (RFC 8032), including the pre-hashed variants
* :doc:`ML-DSA and HashML-DSA </src/signature/mldsa>` (FIPS 204), hedged or deterministic, also with external mu

Key agreement
~~~~~~~~~~~~~

* :doc:`Elliptic-curve Diffie-Hellman </src/protocol/dh>` (NIST P-curves, secp256k1, X25519, X448),
  with static or ephemeral keys (NIST SP 800-56A)

Key derivation
~~~~~~~~~~~~~~

.. rst-class:: two-columns

* :ref:`PBKDF2 <pbkdf2_func>`
* :ref:`scrypt <scrypt_func>`
* :ref:`bcrypt <bcrypt_func>`
* :ref:`HKDF <hkdf>`
* :ref:`NIST SP 800-108 <sp800-108-counter>` (counter mode)
* :ref:`PBKDF1 <pbkdf1_func>` :legacy:`legacy`

Secret sharing
~~~~~~~~~~~~~~

* :doc:`Shamir's secret sharing </src/protocol/ss>`

:ref:`Padding <padding_module>` for block ciphers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* PKCS#7
* ISO 7816-4
* X.923

Implementation
~~~~~~~~~~~~~~

* All the code runs in the package itself (C extensions and Python),
  with no system libraries. Randomness comes from the operating system.
* The big integer arithmetic of RSA, DSA, ElGamal and ECC runs in constant time,
  in C. RSA private key operations are blinded, and the scalar multiplications on
  elliptic curves have further countermeasures (scalar blinding, randomized coordinates).
  If the C module for big integers cannot be loaded, the library falls back to
  pure Python, which is not constant time.
* AES uses the hardware instructions of the CPU when present (see below).
  Without them, it uses lookup tables in software, which are not constant time and
  can be exposed to cache-timing attacks from code running on the same machine.
* Long messages can be processed on several CPU cores (parameter ``threads``):
  CTR, GCM, GCM-SIV and OCB modes, ChaCha20 and XChaCha20, KangarooTwelve, and scrypt.

These CPU extensions are used when present:

.. list-table::
    :header-rows: 1
    :widths: 45 55

    * - CPU extension
      - Speeds up
    * - AES-NI and CLMUL
      - AES, GCM, GCM-SIV
    * - ARMv8 Cryptography Extensions (64-bit ARM)
      - AES, GCM, GCM-SIV, SHA-2
    * - NEON (64-bit ARM)
      - KangarooTwelve, ML-KEM, ML-DSA
    * - SHA extensions
      - SHA-224, SHA-256
    * - AVX2
      - SHA-3 and the other Keccak-based functions, ChaCha20, Salsa20, ML-KEM, ML-DSA
    * - BMI2 and ADX
      - Big integers, NIST curves
