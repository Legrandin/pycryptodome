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
    ecc
    mldsa
    slhdsa
    mlkem
    hybrid
    dsa

* :doc:`RSA keys <rsa>`
* :doc:`Elliptic Curve keys <ecc>`
* :doc:`ML-DSA keys (post-quantum) <mldsa>`
* :doc:`SLH-DSA keys (post-quantum) <slhdsa>`
* :doc:`ML-KEM keys (post-quantum) <mlkem>`
* :doc:`Hybrid keys (post-quantum + traditional) <hybrid>`
* :doc:`DSA keys (obsolete) <dsa>`

Obsolete key type
-----------------

.. toctree::
    :hidden:

    elgamal

* :doc:`ElGamal keys <elgamal>`


.. _nist_security_categories:

NIST security categories
------------------------

Instead of a number of bits, NIST rates the strength of post-quantum
algorithms (ML-KEM, ML-DSA, SLH-DSA) with a *security category* from 1 to 5.
A category means that any attack, by a classical or a quantum computer,
costs at least as much as a reference attack on a symmetric primitive:

.. csv-table::
   :header: Category, "At least as hard as...", "Comparable classical security"
   :widths: 10, 45, 45

   1, "Finding the key of AES-128", "128 bits (P-256, Ed25519, RSA-3072)"
   2, "Finding a collision in SHA-256", "Between 1 and 3"
   3, "Finding the key of AES-192", "192 bits (P-384, RSA-7680)"
   4, "Finding a collision in SHA-384", "Between 3 and 5"
   5, "Finding the key of AES-256", "256 bits (P-521, RSA-15360)"

The comparison with RSA and ECC only holds for classical computers:
a large quantum computer would break RSA and ECC at any key size.

The categories are defined in Section 4.A.5 of the
`NIST PQC Call for Proposals <https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf>`_.
