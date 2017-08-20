:mod:`Crypto.Signature` package
===============================

The :mod:`Crypto.Signature` package contains algorithms for performing digital
signatures, used to guarantee integrity and non-repudiation.

Digital signatures are based on public key cryptography: the party that signs a
message holds the *private key*, the one that verifies the signature holds the
*public key*.

Signing a message
-----------------

1. You instatiate a new signer object using the :func:`new` method
   in the module of the desired algorithm.
   The first parameter is always the key object (*private* key)
   obtained via the :mod:`Crypto.PublicKey` module.

2. You instatiate a cryptographic hash (see :mod:`Crypto.Hash`) and digest
   the message with it.

3. You call :func:`sign` on the hash object. The output is the signature of the message
   (a byte string).

Verifying a signature
---------------------

1. You instatiate a new verifier object using the :func:`new` method
   in the module of the desired algorithm.
   The first parameter is always the key object (*public* key)
   obtained via the :mod:`Crypto.PublicKey` module.

2. You instatiate a cryptographic hash (see :mod:`Crypto.Hash`) and digest
   the message with it.

3. You call :func:`verify` on the hash object and the incoming signature.
   If the message is not authentic, an :py:exc:`ValueError` is raised.

Available mechanisms
--------------------

* :doc:`pkcs1_v1_5`

* :doc:`pkcs1_pss`

* :doc:`dsa`

