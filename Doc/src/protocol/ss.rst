Secret Sharing Schemes
======================
This file implements secret sharing protocols.

In a *(k, n)* secret sharing protocol, a honest dealer breaks a secret
into multiple shares that are distributed amongst *n* players.

The protocol guarantees that nobody can learn anything about the
secret, unless *k* players gather together to assemble their shares.

.. automodule:: Crypto.Protocol.SecretSharing
    :members:
