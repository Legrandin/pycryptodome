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
store a :ref:`bcrypt <bcrypt_func>` hash of the password, and compare
the password typed at login against it:

.. code-block:: python

    from Crypto.Protocol.KDF import bcrypt, bcrypt_check

    # At registration: store the hash (it includes the salt and the cost)
    stored_hash = bcrypt("correct horse battery staple", cost=12)

    # At login
    try:
        bcrypt_check("correct horse battery staple", stored_hash)
        print("Welcome back")
    except ValueError:
        print("Incorrect password")

The ``cost`` doubles the time at each step: 12 takes a fraction of a second.

bcrypt only accepts passwords of up to 72 bytes.
To accept longer passwords, hash them first with SHA-256
(and encode the result, since bcrypt does not accept the zero byte):

.. code-block:: python

    from base64 import b64encode
    from Crypto.Hash import SHA256

    def prehash(password: str) -> bytes:
        return b64encode(SHA256.new(password.encode()).digest())

    stored_hash = bcrypt(prehash("a very long passphrase " * 10), cost=12)
    bcrypt_check(prehash("a very long passphrase " * 10), stored_hash)

Alternatives to bcrypt
~~~~~~~~~~~~~~~~~~~~~~

bcrypt is the easiest choice to use correctly with this library,
because a single string holds everything needed to check a password.
Consider the alternatives when:

* **You want the strongest protection against cracking hardware** (GPUs, ASICs).
  Memory-hard functions like scrypt are more costly to attack than bcrypt,
  which needs little memory.
  With :ref:`scrypt <scrypt_func>`, you must store the salt and the parameters
  yourself, together with the hash, and compare the hashes in constant time:

  .. code-block:: python

      import hmac
      from base64 import b64decode, b64encode
      from Crypto.Protocol.KDF import scrypt
      from Crypto.Random import get_random_bytes

      def hash_password(password: str, N: int = 2**17, r: int = 8, p: int = 1) -> str:
          salt = get_random_bytes(16)
          h = scrypt(password, salt, key_len=32, N=N, r=r, p=p)
          return f"scrypt${N}${r}${p}${b64encode(salt).decode()}${b64encode(h).decode()}"

      def check_password(password: str, stored: str) -> bool:
          _, N, r, p, salt, h = stored.split("$")
          candidate = scrypt(password, b64decode(salt), key_len=32,
                             N=int(N), r=int(r), p=int(p))
          return hmac.compare_digest(candidate, b64decode(h))

      stored = hash_password("correct horse battery staple")
      assert check_password("correct horse battery staple", stored)
      assert not check_password("wrong password", stored)

  Because the parameters are stored with each hash, you can increase them later
  for new passwords, and still check the old ones.
  Only accept stored values from a trusted source: huge parameters make the check very slow.

* **You must comply with FIPS 140**, which only approves PBKDF2.
  It is the weakest option, because it needs no memory:
  use HMAC-SHA256 and at least 600 000 iterations (the OWASP recommendation),
  and store the salt and the iteration count as for scrypt:

  .. code-block:: python

      from Crypto.Hash import SHA256
      from Crypto.Protocol.KDF import PBKDF2

      salt = get_random_bytes(16)
      h = PBKDF2("correct horse battery staple", salt, dkLen=32,
                 count=600_000, hmac_hash_module=SHA256)

Protect a private key with a password
-------------------------------------

To save an RSA or ECC private key to a file encrypted with a password,
pass ``passphrase`` to ``export_key()``. See :doc:`keys`.

See also
--------

* :doc:`../protocol/kdf`, for all key derivation functions
  (including PBKDF2, for compatibility with older systems).
