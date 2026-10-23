ML-KEM
======

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is the post-quantum
key encapsulation mechanism standardized by NIST in `FIPS 203`_.
It is derived from CRYSTALS-Kyber.

Its security is based on the hardness of the Module Learning With Errors problem
(Module-LWE), which is believed to be hard even for quantum computers.
Compared to ECC, keys and ciphertexts are much larger.

FIPS 203 defines three parameter sets:

.. csv-table::
   :header: Parameter set, Constant, NIST security category, Public key, Expanded private key, Ciphertext
   :widths: 15, 25, 15, 15, 15, 15

   "ML-KEM-512", "``MLKEM.ML_KEM_512``", "1", "800 bytes", "1632 bytes", "768 bytes"
   "ML-KEM-768", "``MLKEM.ML_KEM_768``", "3", "1184 bytes", "2400 bytes", "1088 bytes"
   "ML-KEM-1024", "``MLKEM.ML_KEM_1024``", "5", "1568 bytes", "3168 bytes", "1568 bytes"

Pass one of these constants as the ``param_set`` argument.
They are the members of the enum :class:`Crypto.PublicKey.MLKEM.ParamSet`,
and the value of each member is the name of its parameter set (for instance, ``'ML-KEM-768'``).
The shared secret is always 32 bytes long.

A private key can be represented in two ways:

* the **seed**: the 64 random bytes the key is generated from
  (:math:`d \| z` in FIPS 203). It is the most compact form,
  and the one recommended by `RFC 9935`_.
* the **expanded private key**: the decapsulation key defined in FIPS 203
  (Algorithm 16). It cannot be converted back to the seed.

The names used in this module follow the specifications,
but avoid *dk* on its own, because the specifications disagree on its meaning:

.. csv-table::
   :header: This module, FIPS 203, `draft-ietf-hpke-pq`_, `RFC 9935`_
   :widths: 25, 25, 25, 25

   "``seed``", ":math:`d \| z`", "``dk``", "``seed``"
   "``expanded_dk``", "``dk``", "``expanded_dk``", "``expandedKey``"
   "``ek``", "``ek``", "``ek``", "public key"

The implementation is based on `mlkem-native`_.

Generation
----------

You can generate a new ML-KEM key::

    >>> from Crypto.PublicKey import MLKEM
    >>>
    >>> key = MLKEM.generate(param_set=MLKEM.ML_KEM_768)
    >>> seed = key.seed       # 64 bytes, keep it secret
    >>> ek = key.ek           # 1184 bytes, the public key

and rebuild it later from its seed (or from the expanded private key),
or get the public key::

    >>> key = MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=seed)
    >>> pub_key = MLKEM.construct(param_set=MLKEM.ML_KEM_768, ek=ek)
    >>> pub_key == key.public_key()
    True

:func:`construct` performs the input checks of FIPS 203:
the *modulus check* on a public key (Section 7.2)
and the *hash check* on an expanded private key (Section 7.3).
Since the hash check does not detect all corrupted expanded private keys,
it also performs a *pairwise consistency check* on an expanded private key
without a seed (an encapsulation with the public key, followed by a decapsulation).

Import and Export
-----------------

You can export an ML-KEM key as defined in `RFC 9935`_:
a public key as an X.509 ``SubjectPublicKeyInfo``, a private key as a
PKCS#8 ``OneAsymmetricKey``, optionally protected with a passphrase.
The encoding is DER (binary, the default) or PEM (text, `RFC 7468`_)::

    >>> with open("myprivatekey.pem", "wt") as f:
    ...     f.write(key.export_key(format="PEM", passphrase="secret"))
    >>>
    >>> with open("mypublickey.der", "wb") as f:
    ...     f.write(key.public_key().export_key())

and import it later (the format is detected automatically)::

    >>> with open("myprivatekey.pem", "rt") as f:
    ...     key = MLKEM.import_key(f.read(), "secret")

The private key in the ``OneAsymmetricKey`` is the seed
or, if the seed is not known, the expanded private key.
It does not contain the public key (the optional ``publicKey`` field of
``OneAsymmetricKey`` version 2), which can always be computed again.
:func:`import_key` accepts all the variants of RFC 9935
(the seed, the expanded private key, or both, with or without the public key),
and it checks that the seed, the expanded private key and the public key match.
It also accepts an X.509 certificate, from which it extracts the public key.

Usage
-----

Currently, ML-KEM keys can only be used with :ref:`HPKE <hpke>`
(:mod:`Crypto.Protocol.HPKE`), alone or combined with ECDH in a
:doc:`hybrid KEM <hybrid>`.

.. _`FIPS 203`: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
.. _mlkem-native: https://github.com/pq-code-package/mlkem-native
.. _`RFC 9935`: https://www.rfc-editor.org/rfc/rfc9935.html
.. _`RFC 7468`: https://www.rfc-editor.org/rfc/rfc7468.html
.. _`draft-ietf-hpke-pq`: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/

API
---

.. automodule:: Crypto.PublicKey.MLKEM
    :members:
    :member-order: bysource
