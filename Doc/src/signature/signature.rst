:mod:`Crypto.Signature` package
===============================

The :mod:`Crypto.Signature` package contains algorithms for performing digital
signatures, used to guarantee integrity and non-repudiation.

Digital signatures are based on public key cryptography: the party that signs a
message holds the *private key*, the one that verifies the signature holds the
*public key*.

Signing a message
-----------------

1. Instantiate a new signer object for the desired algorithm,
   for instance with :func:`Crypto.Signature.pkcs1_15.new`.
   The first parameter is the key object (*private* key)
   obtained via the :mod:`Crypto.PublicKey` module.

2. Instantiate a cryptographic hash object, for instance with :func:`Crypto.Hash.SHA384.new`.
   Then, process the message with its :func:`update` method.

3. Invoke the :func:`sign` method on the signer with the hash object as parameter.
   The output is the signature of the message (a byte string).

Verifying a signature
---------------------

1. Instantiate a new verifier object for the desired algorithm,
   for instance with :func:`Crypto.Signature.pkcs1_15.new`.
   The first parameter is the key object (*public* key)
   obtained via the :mod:`Crypto.PublicKey` module.

2. Instantiate a cryptographic hash object, for instance with :func:`Crypto.Hash.SHA384.new`.
   Then, process the message with its :func:`update` method.

3. Invoke the :func:`verify` method on the verifier, with the hash object and the incoming signature as parameters.
   If the message is not authentic, an :py:exc:`ValueError` is raised.

Available mechanisms
--------------------

* :doc:`pkcs1_v1_5`

* :doc:`pkcs1_pss`

* :doc:`dsa`

