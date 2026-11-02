.. _guide_keys:

Generate, save, and load keys
=============================

Secret keys
-----------

A secret key for a symmetric cipher or a MAC is just a string of random bytes.
Generate it with :func:`Crypto.Random.get_random_bytes`, which uses the random
generator of the operating system:

.. code-block:: python

    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)

32 bytes (256 bits) are enough for any algorithm. Do not use the module :mod:`random`
of the Python standard library: it is not secure.

Store secret keys outside the source code and the database they protect:
for instance in a key management service, in a secret store, or
in a file readable only by the application.

Derive several keys from one secret
-----------------------------------

If you have one secret (for instance a key, or the output of a key agreement)
but you need several independent keys, for instance one for encryption and one for a MAC,
use :ref:`HKDF <hkdf>`:

.. code-block:: python

    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF

    master_secret = get_random_bytes(32)
    enc_key, mac_key = HKDF(master_secret, 32, salt=b"", hashmod=SHA256,
                            num_keys=2, context=b"my app, v1")

Different values of ``context`` produce unrelated keys.
HKDF is not suitable for passwords: see :doc:`passwords`.

Public and private keys
-----------------------

For signatures and public key encryption you need a *key pair*.
Generate it once, keep the private key secret, and distribute the public key.
The type of key depends on what you will use it for:

.. code-block:: python

    from Crypto.PublicKey import ECC, RSA

    ed25519_key = ECC.generate(curve="ed25519")       # for signatures (EdDSA)
    x25519_key = ECC.generate(curve="curve25519")     # for encryption (HPKE)
    p256_key = ECC.generate(curve="p256")             # for key agreement (ECDH) and ECDSA
    rsa_key = RSA.generate(3072)                      # RSA, at least 2048 bits

Whatever the type of key, save it in a **PEM** file: a text format that virtually
every other tool and library can read (OpenSSL, and the cryptographic libraries
of Java, Go, .NET, Node.js, and so on).

Encrypt the private key with a password. ``export_key()`` produces
a PKCS#8 structure, protected by default with PBKDF2 and AES-256:

.. code-block:: python

    with open("private.pem", "wt") as f:
        f.write(ed25519_key.export_key(format="PEM", passphrase="my secret password"))

The public key is not secret, and it does not need a password
(the PEM file contains a standard *SubjectPublicKeyInfo* structure):

.. code-block:: python

    with open("public.pem", "wt") as f:
        f.write(ed25519_key.public_key().export_key(format="PEM"))

To load the keys back, use ``import_key()``. It accepts PEM, DER, and other common formats:

.. code-block:: python

    with open("private.pem", "rt") as f:
        private_key = ECC.import_key(f.read(), passphrase="my secret password")

    with open("public.pem", "rt") as f:
        public_key = ECC.import_key(f.read())

An incorrect password raises :class:`~Crypto.IncorrectPassphraseError`.
RSA keys work the same way, with :func:`Crypto.PublicKey.RSA.import_key`,
except that the RSA method ``export_key()`` returns ``bytes``,
so write the file in binary mode (``"wb"``).

If you need a binary encoding instead of text, pass ``format="DER"``:
it contains the same PKCS#8 and *SubjectPublicKeyInfo* structures.

The keys are interoperable with other tools: for instance,
``openssl pkey -in private.pem`` can read the private key.

Agree on a secret key over an insecure channel
----------------------------------------------

Two parties can compute the same secret key without ever transmitting it,
with *Elliptic Curve Diffie-Hellman* (ECDH): each party combines its own private key
with the public key of the other.
Use keys on the NIST P-256 curve.

The raw output of ECDH is not a uniformly random string,
so it must go through a key derivation function: use :ref:`HKDF <hkdf>`.
Both parties must use the same curve and the same KDF parameters (including the ``context``).

.. code-block:: python

    from Crypto.Protocol.DH import key_agreement

    def kdf(shared_secret: bytes) -> bytes:
        return HKDF(shared_secret, 32, salt=b"", hashmod=SHA256, context=b"my app, v1")

    alice_key = ECC.generate(curve="p256")
    bob_key = ECC.generate(curve="p256")

    # Each party uses its private key and the public key of the other
    alice_secret = key_agreement(static_priv=alice_key, static_pub=bob_key.public_key(), kdf=kdf)
    bob_secret = key_agreement(static_priv=bob_key, static_pub=alice_key.public_key(), kdf=kdf)
    assert alice_secret == bob_secret

The public keys must be exchanged in an authenticated way (for instance,
they are signed, or pinned in advance): otherwise, an attacker in the middle
can replace them with its own, and agree on a separate key with each party.

The result is a key for :doc:`symmetric encryption <symmetric>`.
To simply encrypt data for a recipient, :doc:`HPKE <public_key_encryption>` does all of this for you.
See :doc:`../protocol/dh` for ephemeral keys and other options.

See also
--------

* :doc:`../public_key/public_key`, for all key types and formats.
* :doc:`../io/pkcs8`, for the encryption algorithms of private keys.
