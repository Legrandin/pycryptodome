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

API principles
--------------

Asymmetric keys are represented by Python objects. Each object can be either
a *private* key or a *public* key (the method :meth:`has_private` can be used
to distinguish them).

A key object can be created in four ways:

1. :func:`generate` at the module level (e.g. :func:`Crypto.PublicKey.RSA.generate`).
   The key is randomly created each time.
2. :func:`import_key` at the module level (e.g. :func:`Crypto.PublicKey.RSA.import_key`).
   The key is loaded from memory.
3. :func:`construct` at the module level (e.g. :func:`Crypto.PublicKey.RSA.construct`).
   The key will be built from a set of sub-components.
4. :meth:`publickey` at the object level (e.g. :meth:`Crypto.PublicKey.RSA.RsaKey.publickey`).
   The key will be the public key matching the given object.

A key object can be serialized via its :meth:`export_key` method.

Keys objects can be compared via the usual operators ``==`` and ``!=`` (note that the two halves of the same key,
*private* and *public*, are considered as two different keys).

Available key types
-------------------

.. toctree::
    :hidden:

    rsa
    dsa
    ecc

* :doc:`RSA keys <rsa>`
* :doc:`DSA keys <dsa>`
* :doc:`Elliptic Curve keys <ecc>`

Obsolete key type
-----------------

.. toctree::
    :hidden:

    elgamal

* :doc:`ElGamal keys <elgamal>`

