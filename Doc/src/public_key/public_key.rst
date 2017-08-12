:mod:`Crypto.PublicKey` package
===============================

In public key cryptography, senders and receivers use different keys.

.. csv-table:: 
    :header: Algorithm, Sender, Receiver

    Encryption, "Public key", "Private key"
    Signature, "Private key", "Public key"

Unlike keys for symmetric cipher algorithms (which typically are just
random bit strings), keys for public key algorithms have very specific
properties. This module collects all methods to generate, validate,
store and retrieve public keys.
