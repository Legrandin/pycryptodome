Hybrid keys
===========

.. currentmodule:: Crypto.PublicKey.Hybrid

A hybrid key combines a post-quantum key with a traditional one:
the result stays secure as long as at least one of the two algorithms is secure.
It protects against quantum computers (thanks to the post-quantum algorithm)
without relying only on an algorithm that is still relatively new
(the traditional one is still there, should the post-quantum one fail).

The combination is selected by the ``param_set`` argument, one of the members of
the enum :class:`Crypto.PublicKey.Hybrid.ParamSet`
(also available as constants at the module level, for instance ``Hybrid.MLKEM768_X25519``).
The parameter set also decides what the key can be used for.

Currently, hybrid keys can only be generated, and used with :ref:`HPKE <hpke>`:
they cannot be exported or imported.

Hybrid KEMs (ML-KEM + ECDH)
---------------------------

A hybrid KEM combines a post-quantum KEM (:doc:`ML-KEM <mlkem>`) with
a traditional one (ECDH), to agree on a shared secret.
This module implements the hybrid KEM MLKEM768-X25519 of `draft-irtf-cfrg-concrete-hybrid-kems`_,
also used by HPKE (`draft-ietf-hpke-pq`_):

.. csv-table::
   :header: Hybrid KEM, Constant, Components, Public key, Ciphertext
   :widths: 20, 30, 20, 15, 15

   "MLKEM768-X25519", "``Hybrid.MLKEM768_X25519``", "ML-KEM-768 and X25519", "1216 bytes", "1120 bytes"

MLKEM768-X25519 is the same as X-Wing.
The other hybrid KEMs of the draft (MLKEM768-P256 and MLKEM1024-P384)
are not supported yet, as their definition may still change.

A private key is a **seed** of 32 random bytes:
the ML-KEM key and the ECDH key are both derived from it.
The two private keys are never used on their own, or with another algorithm.
The public key is the ML-KEM public key, followed by the X25519 public key (32 bytes).

With this module you can generate a new hybrid KEM key, and get its public key::

    >>> from Crypto.PublicKey import Hybrid
    >>>
    >>> key = Hybrid.generate(param_set=Hybrid.MLKEM768_X25519)
    >>> pub_key = key.public_key()

To encrypt data with these keys, use :ref:`HPKE <hpke>` (:mod:`Crypto.Protocol.HPKE`).

.. _`draft-irtf-cfrg-concrete-hybrid-kems`: https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/
.. _`draft-ietf-hpke-pq`: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/

API
---

.. automodule:: Crypto.PublicKey.Hybrid
    :members:
    :member-order: bysource
