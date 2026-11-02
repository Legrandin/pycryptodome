.. _guide_symmetric:

Encrypt data with a secret key
==============================

Use this when the same party, or parties that already share a secret key,
encrypt and decrypt the data: for instance, to protect files at rest,
database fields, or messages between two services you control.

* If you have a *password* instead of a key, see :doc:`passwords`.
* If the recipient has a *public key*, see :doc:`public_key_encryption`.

The recommended way: AES-GCM
----------------------------

Encrypt with :doc:`AES <../cipher/aes>` in :ref:`GCM mode <gcm_mode>`.
It is fast (it uses the AES instructions of the CPU), standard, and supported
by virtually every other cryptographic library.

GCM is an *authenticated* mode: in addition to the ciphertext, it produces
a 16-byte **tag**. During decryption, the tag reveals if the ciphertext
was modified or if the key is wrong.

Each message also needs a **nonce**: 12 bytes that must never be reused with the same key.
The nonce is not secret.

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag

    def decrypt(key: bytes, data: bytes) -> bytes:
        nonce, ciphertext, tag = data[:12], data[12:-16], data[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    key = get_random_bytes(32)      # AES-256: keep it secret, and store it safely
    data = encrypt(key, b"Attack at dawn")
    assert decrypt(key, data) == b"Attack at dawn"

The output of ``encrypt()`` is the concatenation of the nonce, the ciphertext,
and the tag: ``data`` is 28 bytes longer than the plaintext.
You can store or transmit it as it is, or encode it
(for instance with :func:`base64.b64encode`) if you need text.

If the data was modified, or the key is not the right one,
``decrypt_and_verify()`` raises ``ValueError``,
and you must treat the message as invalid:

.. code-block:: python

    tampered = data[:-1] + bytes([data[-1] ^ 1])
    try:
        decrypt(key, tampered)
    except ValueError:
        print("The message was modified, or the key is wrong")

Things to know
~~~~~~~~~~~~~~

* **Keys** must be random: generate them with :func:`Crypto.Random.get_random_bytes`
  (16, 24, or 32 bytes for AES-128, AES-192, or AES-256).
  Never use a password or a string directly as a key.
  See :doc:`keys` for how to derive several keys from one.
* **Nonces** must never repeat for the same key, otherwise an attacker can
  decrypt messages and forge new ones.
  A random 12-byte nonce, as above, is safe for up to about 4 billion (2\ :sup:`32`)
  messages per key; rotate the key before that.
* **One message per cipher object**: create a new object (and a new nonce)
  for each message. An object cannot be reused.
* **Size**: a single GCM message can be at most 64 GiB minus 32 bytes
  (a longer one raises :class:`~Crypto.MessageTooLongError`).

Authenticate data that is not encrypted
---------------------------------------

Sometimes part of the data must remain readable, for instance a header with
a version number or a record identifier, but it must still be protected against modification.
Pass it to ``update()`` before encrypting, and pass the same data again before decrypting.
The data itself is not included in the output:

.. code-block:: python

    def encrypt_with_header(key: bytes, header: bytes, plaintext: bytes) -> bytes:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag

    def decrypt_with_header(key: bytes, header: bytes, data: bytes) -> bytes:
        nonce, ciphertext, tag = data[:12], data[12:-16], data[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        return cipher.decrypt_and_verify(ciphertext, tag)

    header = b"user=42"
    data = encrypt_with_header(key, header, b"Attack at dawn")
    assert decrypt_with_header(key, header, data) == b"Attack at dawn"

This is also how you prevent an attacker from swapping two valid encrypted records:
authenticate the identifier of each record together with its content.

Encrypt a large file
--------------------

To encrypt a file that does not fit in memory, call ``encrypt()`` for each chunk,
and ``digest()`` at the end:

.. code-block:: python

    import os

    CHUNK_SIZE = 1024 * 1024

    def encrypt_file(key: bytes, src: str, dst: str) -> None:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            fout.write(nonce)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(cipher.encrypt(chunk))
            fout.write(cipher.digest())

    def decrypt_file(key: bytes, src: str, dst: str) -> None:
        remaining = os.path.getsize(src) - 12 - 16
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            cipher = AES.new(key, AES.MODE_GCM, nonce=fin.read(12))
            while remaining > 0:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                remaining -= len(chunk)
                fout.write(cipher.decrypt(chunk))
            tag = fin.read(16)
        try:
            cipher.verify(tag)
        except ValueError:
            os.remove(dst)
            raise

.. warning::

    ``decrypt()`` returns plaintext *before* the tag is checked.
    Do not use the decrypted file until ``verify()`` succeeds:
    in the example above, the output file is deleted if the tag is not valid.

Alternatives
------------

AES-GCM is the right choice in most cases. Consider the alternatives when:

* **The CPU has no AES instructions** (for instance, some small ARM devices):
  :doc:`ChaCha20-Poly1305 <../cipher/chacha20_poly1305>` is fast in software,
  and it has the same API. With a 24-byte nonce (*XChaCha20-Poly1305*),
  random nonces are safe for any number of messages:

  .. code-block:: python

      from Crypto.Cipher import ChaCha20_Poly1305

      key = get_random_bytes(32)
      nonce = get_random_bytes(24)
      cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
      ciphertext, tag = cipher.encrypt_and_digest(b"Attack at dawn")

* **You cannot guarantee that nonces never repeat** (for instance, many devices
  share a key and have no good random source):
  use :ref:`SIV mode <siv_mode>`, which tolerates a repeated nonce, at the price of speed.

* **You must use the same key to encrypt the same value always to the same ciphertext**
  (for instance, to look up encrypted values in a database):
  SIV mode without a nonce is *deterministic*. It only reveals if two messages are identical.

* **You must interoperate with an existing protocol or file format**:
  use the mode it specifies. If it is a mode without authentication
  (like :ref:`CBC <cbc_mode>` or :ref:`CTR <ctr_mode>`), always combine it with a MAC,
  computed over the nonce or IV and the ciphertext, with a separate key
  (*encrypt-then-MAC*):

  .. code-block:: python

      from Crypto.Hash import HMAC, SHA256

      aes_key = get_random_bytes(16)
      hmac_key = get_random_bytes(32)

      cipher = AES.new(aes_key, AES.MODE_CTR)
      ciphertext = cipher.encrypt(b"Attack at dawn")
      tag = HMAC.new(hmac_key, cipher.nonce + ciphertext, digestmod=SHA256).digest()
      data = cipher.nonce + ciphertext + tag

      # Decryption: verify the MAC first, then decrypt
      nonce, ciphertext, tag = data[:8], data[8:-32], data[-32:]
      HMAC.new(hmac_key, nonce + ciphertext, digestmod=SHA256).verify(tag)  # ValueError if invalid
      plaintext = AES.new(aes_key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)

The pages :doc:`../cipher/aes` and :ref:`modern_cipher_modes` list all modes,
with their parameters and the full API of the cipher objects.
