.. _guide_passwords:

Work with passwords
===================

Passwords are short and easy to guess, compared to random keys.
Never use a password directly as a cryptographic key,
and never store it as a plain hash (like SHA-256):
an attacker can try billions of candidate passwords per second against it.

Instead, use a *password-based key derivation function*,
which is deliberately slow and memory-hungry, and a random **salt**,
so that the work of the attacker cannot be reused across passwords.

Encrypt data with a password
----------------------------

Derive a key from the password with :ref:`scrypt <scrypt_func>`,
and then encrypt as in :doc:`symmetric`:

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes

    def derive_key(password: str, salt: bytes) -> bytes:
        return scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)

    def encrypt(password: str, plaintext: bytes) -> bytes:
        salt = get_random_bytes(16)
        nonce = get_random_bytes(12)
        cipher = AES.new(derive_key(password, salt), AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return salt + nonce + ciphertext + tag

    def decrypt(password: str, data: bytes) -> bytes:
        salt, nonce = data[:16], data[16:28]
        ciphertext, tag = data[28:-16], data[-16:]
        cipher = AES.new(derive_key(password, salt), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    data = encrypt("correct horse battery staple", b"Attack at dawn")
    assert decrypt("correct horse battery staple", data) == b"Attack at dawn"

You can also derive the key with :ref:`Argon2 <argon2_func>`, in the same way.
Choose a profile, and keep it: a different profile gives a different key.

.. code-block:: python

    from Crypto.Protocol.KDF import Argon2Profile, argon2

    def derive_key(password: str, salt: bytes) -> bytes:
        return argon2(password, 32, salt=salt, profile=Argon2Profile.RFC9106_2021_64MIB)

A wrong password makes ``decrypt_and_verify()`` raise ``ValueError``,
exactly like a modified message.

The salt is not secret, and it is stored next to the ciphertext.
A new random salt for each encryption also means a new key,
so a random nonce never risks being repeated.

Choosing the scrypt parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The parameter ``N`` sets the cost: scrypt needs ``128 * r * N`` bytes of memory
(128 MiB with the values above) and it takes proportionally longer.
Choose the largest value that is acceptable for your users and your hardware,
and measure it on the slowest machine that will run the code.
Typical values are:

* ``N=2**14`` (16 MiB) for interactive logins, where the delay must stay short;
* ``N=2**17`` to ``N=2**20`` (128 MiB to 1 GiB) to encrypt files.

If you might change the parameters in the future,
store them (or a version number) together with the salt.

Store and check passwords for a login
-------------------------------------

To check the password of a user, you don't need to decrypt anything:
store an :ref:`Argon2 <argon2_func>` hash of the password, and compare
the password typed at login against it:

.. code-block:: python

    from Crypto.Protocol.KDF import argon2_check, argon2_hash

    # At registration: store the hash (it includes the salt and the parameters)
    stored_hash = argon2_hash("correct horse battery staple")

    # At login
    try:
        argon2_check("correct horse battery staple", stored_hash)
        print("Welcome back")
    except ValueError:
        print("Incorrect password")

The hash is a string like ``$argon2id$v=19$m=65536,t=3,p=4$...``, which
most other Argon2 libraries can also check.
By default, it uses Argon2id with 64 MiB of memory and 3 passes
(the second recommended option of RFC 9106), which takes a fraction of a second.

Argon2 is memory-hard: every guess costs an attacker as much memory as it costs you,
which makes GPUs and custom hardware much less effective than against bcrypt or PBKDF2.
It accepts passwords of any length.

Choosing the parameters
~~~~~~~~~~~~~~~~~~~~~~~

Pass a ``profile`` (see the :ref:`table of profiles <argon2_func>`) or the costs.
For instance, on a server with many concurrent logins and little memory:

.. code-block:: python

    from Crypto.Protocol.KDF import Argon2Profile

    stored_hash = argon2_hash("correct horse battery staple", profile=Argon2Profile.OWASP_2023_19MIB)

The parameters are stored in each hash: you can raise them later for new passwords,
and still check the old ones.
:func:`~Crypto.Protocol.KDF.argon2_check` rejects a hash that needs more than 256 MiB
of memory, to protect against hashes from untrusted sources
(change the limit with ``max_memory``).

Alternatives to Argon2
~~~~~~~~~~~~~~~~~~~~~~

* **You must check existing bcrypt hashes**, or interoperate with a system that uses them.
  Use :ref:`bcrypt <bcrypt_func>`, which also stores everything in a single string:

  .. code-block:: python

      from Crypto.Protocol.KDF import bcrypt, bcrypt_check

      stored_hash = bcrypt("correct horse battery staple", cost=12)
      bcrypt_check("correct horse battery staple", stored_hash)   # ValueError if wrong

  The ``cost`` doubles the time at each step: 12 takes a fraction of a second.
  bcrypt only accepts passwords of up to 72 bytes, without the zero byte.
  To accept longer passwords, hash them first with SHA-256 and encode the result:

  .. code-block:: python

      from base64 import b64encode
      from Crypto.Hash import SHA256

      def prehash(password: str) -> bytes:
          return b64encode(SHA256.new(password.encode()).digest())

      stored_hash = bcrypt(prehash("a very long passphrase " * 10), cost=12)
      bcrypt_check(prehash("a very long passphrase " * 10), stored_hash)

* **You must comply with FIPS 140**, which only approves PBKDF2.
  It is the weakest option, because it needs no memory:
  use HMAC-SHA256 and at least 600 000 iterations (the OWASP recommendation),
  and store the salt and the iteration count together with the hash.
  Compare the hashes in constant time:

  .. code-block:: python

      import hmac
      from Crypto.Hash import SHA256
      from Crypto.Protocol.KDF import PBKDF2
      from Crypto.Random import get_random_bytes

      salt = get_random_bytes(16)
      h = PBKDF2("correct horse battery staple", salt, dkLen=32,
                 count=600_000, hmac_hash_module=SHA256)

      # At login, with the stored salt and h
      candidate = PBKDF2("correct horse battery staple", salt, dkLen=32,
                         count=600_000, hmac_hash_module=SHA256)
      assert hmac.compare_digest(candidate, h)

Protect a private key with a password
-------------------------------------

To save an RSA or ECC private key to a file encrypted with a password,
pass ``passphrase`` to ``export_key()``. See :doc:`keys`.

See also
--------

* :doc:`../protocol/kdf`, for all key derivation functions
  (including PBKDF2, for compatibility with older systems).
