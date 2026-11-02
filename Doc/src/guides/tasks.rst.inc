.. list-table::
    :header-rows: 1
    :widths: 40 20 40

    * - I want to…
      - Recommended
      - Guide
    * - Encrypt data with a secret key
      - AES-GCM
      - :doc:`/src/guides/symmetric`
    * - Encrypt data with a password
      - scrypt + AES-GCM
      - :ref:`Work with passwords <guide_passwords>`
    * - Store and check users' passwords
      - bcrypt
      - :ref:`Work with passwords <guide_passwords>`
    * - Encrypt data for a recipient's public key
      - HPKE
      - :doc:`/src/guides/public_key_encryption`
    * - Sign data, or verify a signature
      - Ed25519
      - :doc:`/src/guides/signatures`
    * - Compute a hash of data or of a file
      - SHA-256
      - :doc:`/src/guides/hashing`
    * - Authenticate a message with a secret key (MAC)
      - HMAC-SHA256
      - :doc:`/src/guides/hashing`
    * - Generate, save, and load keys
      - PEM files (PKCS#8)
      - :doc:`/src/guides/keys`
    * - Agree on a secret key with another party
      - ECDH (P-256) + HKDF
      - :doc:`/src/guides/keys`
