.. _guide_public_key_encryption:

Encrypt data for a recipient's public key
=========================================

Use this when anybody who knows the recipient's *public key* must be able
to encrypt data, but only the recipient, who has the matching *private key*,
can decrypt it. The two parties don't need to share a secret in advance.

The recommended way: HPKE
-------------------------

:ref:`HPKE <hpke>` (Hybrid Public Key Encryption, RFC 9180) is a standard
that combines a public key algorithm, to agree on a fresh secret key,
with authenticated symmetric encryption (like AES-GCM), to encrypt messages
of any size.

First, the recipient generates a key pair, keeps the private key,
and publishes the public key:

.. code-block:: python

    from Crypto.PublicKey import ECC

    private_key = ECC.generate(curve="curve25519")
    with open("public.pem", "wt") as f:
        f.write(private_key.public_key().export_key(format="PEM"))

See :doc:`keys` for how to save the private key too.

The sender encrypts a message with the recipient's public key.
It must deliver two items to the recipient:
the *encapsulated key* ``enc`` (32 bytes for Curve25519) and the ciphertext:

.. code-block:: python

    from Crypto.Protocol import HPKE

    with open("public.pem", "rt") as f:
        recipient_key = ECC.import_key(f.read())

    encryptor = HPKE.new(receiver_key=recipient_key,
                         aead_id=HPKE.AEAD.AES256_GCM)
    ciphertext = encryptor.seal(b"Attack at dawn")
    data = encryptor.enc + ciphertext

The recipient decrypts with its private key:

.. code-block:: python

    enc, ciphertext = data[:32], data[32:]
    decryptor = HPKE.new(receiver_key=private_key,
                         aead_id=HPKE.AEAD.AES256_GCM,
                         enc=enc)
    plaintext = decryptor.unseal(ciphertext)    # ValueError if invalid
    assert plaintext == b"Attack at dawn"

The sender and the recipient must agree in advance on the AEAD algorithm
(here, ``AES256_GCM``). ``unseal()`` raises ``ValueError`` if the data was modified
or if it was not encrypted for this private key.

Things to know
~~~~~~~~~~~~~~

* With one ``encryptor``, the sender can ``seal()`` several messages: they share
  the same ``enc``, and the recipient must ``unseal()`` them in the same order.
* The recipient does not learn *who* encrypted the message: anybody can use a public key.
  If the recipient must also know that the message comes from a specific sender,
  the sender must also sign it (see :doc:`signatures`), or use the
  authenticated modes of :ref:`HPKE <hpke>`.

Post-quantum encryption
~~~~~~~~~~~~~~~~~~~~~~~

Data encrypted today with ECC keys could be decrypted in the future by a quantum computer.
If that is a concern, the recipient can use a hybrid key, which combines ML-KEM
(post-quantum) and X25519, with the same HPKE API:

.. code-block:: python

    from Crypto.PublicKey import Hybrid

    private_key = Hybrid.generate(param_set=Hybrid.MLKEM768_X25519)

    encryptor = HPKE.new(receiver_key=private_key.public_key(),
                         aead_id=HPKE.AEAD.AES256_GCM)
    ciphertext = encryptor.seal(b"Attack at dawn")

    decryptor = HPKE.new(receiver_key=private_key,
                         aead_id=HPKE.AEAD.AES256_GCM,
                         enc=encryptor.enc)          # enc is 1120 bytes long
    assert decryptor.unseal(ciphertext) == b"Attack at dawn"

See :doc:`../public_key/hybrid` and :doc:`../public_key/mlkem`.

Alternative: RSA
----------------

If the recipient already has an RSA key, or you must interoperate with a system based on RSA,
encrypt a random AES key with :ref:`RSA-OAEP <rsa_oaep>`,
and the data with the AES key:

.. code-block:: python

    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes

    rsa_private_key = RSA.generate(3072)      # the recipient's key
    rsa_public_key = rsa_private_key.public_key()

    # The sender
    session_key = get_random_bytes(16)
    enc_session_key = PKCS1_OAEP.new(rsa_public_key).encrypt(session_key)
    nonce = get_random_bytes(12)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(b"Attack at dawn")
    data = enc_session_key + nonce + ciphertext + tag

    # The recipient
    key_len = rsa_private_key.size_in_bytes()          # 384 bytes for RSA-3072
    enc_session_key, nonce = data[:key_len], data[key_len:key_len + 12]
    ciphertext, tag = data[key_len + 12:-16], data[-16:]
    session_key = PKCS1_OAEP.new(rsa_private_key).decrypt(enc_session_key)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    assert cipher.decrypt_and_verify(ciphertext, tag) == b"Attack at dawn"

RSA-OAEP alone can only encrypt short data (at most 342 bytes with a 3072-bit key),
which is why it is only used for the AES key.
Do not use :doc:`PKCS#1 v1.5 encryption <../cipher/pkcs1_v1_5>` in new designs.
