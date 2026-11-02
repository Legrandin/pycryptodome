.. _guide_signatures:

Sign data and verify signatures
===============================

A digital signature proves that a message was created by the owner of a *private key*,
and that it was not modified afterwards.
Anybody with the matching *public key* can verify the signature.

Signatures do not hide the message: if it must also be confidential,
encrypt it too (see :doc:`public_key_encryption`).

If the two parties share a secret key, a :doc:`MAC <hashing>` is simpler and faster.

The recommended way: Ed25519
----------------------------

:doc:`EdDSA <../signature/eddsa>` with the curve Ed25519 has small keys (32 bytes)
and small signatures (64 bytes), it is fast, and it is hard to misuse.

The signer generates a key pair once, and publishes the public key:

.. code-block:: python

    from Crypto.PublicKey import ECC

    private_key = ECC.generate(curve="ed25519")
    with open("public.pem", "wt") as f:
        f.write(private_key.public_key().export_key(format="PEM"))

See :doc:`keys` for how to save the private key too.

The signer signs a message with the private key:

.. code-block:: python

    from Crypto.Signature import eddsa

    message = b"I give my permission to order #4355"
    signature = eddsa.new(private_key, "rfc8032").sign(message)

The verifier checks the signature with the public key.
``verify()`` raises ``ValueError`` if the signature is not valid:

.. code-block:: python

    with open("public.pem", "rt") as f:
        public_key = ECC.import_key(f.read())

    try:
        eddsa.new(public_key, "rfc8032").verify(message, signature)
        print("The message is authentic")
    except ValueError:
        print("The message is not authentic")

Alternatives
------------

Choose a different algorithm if a protocol or a standard requires it:

* **ECDSA** with the NIST P-256 curve, often required by standards (like FIPS),
  and used in JWT (``ES256``) and in TLS certificates.
  You sign a *hash* of the message, created with :doc:`SHA-256 <../hash/sha256>`:

  .. code-block:: python

      from Crypto.Hash import SHA256
      from Crypto.Signature import DSS

      ecdsa_key = ECC.generate(curve="p256")
      signature = DSS.new(ecdsa_key, "fips-186-3").sign(SHA256.new(message))

      verifier = DSS.new(ecdsa_key.public_key(), "fips-186-3")
      verifier.verify(SHA256.new(message), signature)       # ValueError if invalid

  See :doc:`../signature/dsa`.

* **RSA** keys, when the existing infrastructure uses them.
  Prefer the :doc:`PSS <../signature/pkcs1_pss>` scheme;
  use :doc:`PKCS#1 v1.5 <../signature/pkcs1_v1_5>` only for compatibility:

  .. code-block:: python

      from Crypto.PublicKey import RSA
      from Crypto.Signature import pss

      rsa_key = RSA.generate(3072)
      signature = pss.new(rsa_key).sign(SHA256.new(message))

      verifier = pss.new(rsa_key.public_key())
      verifier.verify(SHA256.new(message), signature)       # ValueError if invalid

* **ML-DSA**, a post-quantum signature scheme standardized in FIPS 204,
  if signatures must remain secure against future quantum computers.
  Keys and signatures are much larger (several kilobytes):

  .. code-block:: python

      from Crypto.PublicKey import MLDSA
      from Crypto.Signature import mldsa

      mldsa_key = MLDSA.generate(param_set=MLDSA.ML_DSA_65)
      signature = mldsa.new(mldsa_key).sign(message)

      mldsa.new(mldsa_key.public_key()).verify(message, signature)  # ValueError if invalid

  See :doc:`../signature/mldsa`.

Sign a large file
-----------------

ECDSA and RSA sign a hash object, so you can hash a large file in chunks first:

.. code-block:: python

    with open("large_file.bin", "rb") as f:
        h = SHA256.new()
        while chunk := f.read(1024 * 1024):
            h.update(chunk)

    signature = pss.new(rsa_key).sign(h)

With Ed25519, pass a :doc:`SHA-512 <../hash/sha512>` object instead of the message
(this variant is called *HashEdDSA*, and it produces a different signature,
so the verifier must do the same).
