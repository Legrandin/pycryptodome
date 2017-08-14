:mod:`Crypto.PublicKey` package
===============================

In a public key cryptography system, senders and receivers do not use the same key.
Instead, the system defines a *key pair*, with one of the keys being
confidential (*private*) and the other not (*public*).

.. csv-table:: 
    :header: Algorithm, "Sender uses..", "Receiver uses..."

    Encryption, "Public key", "Private key"
    Signature, "Private key", "Public key"

Unlike keys meant for symmetric cipher algorithms (typically just
random bit strings), keys for public key algorithms have very specific
properties. This module collects all methods to generate, validate,
store and retrieve public keys.

.. toctree::

    rsa
