ML-DSA
======

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the post-quantum
signature algorithm standardized by NIST in `FIPS 204`_.
It is derived from CRYSTALS-Dilithium.

Its security is based on the hardness of lattice problems (Module-LWE and Module-SIS),
which are believed to be hard even for quantum computers.
Compared to RSA and ECC, keys and signatures are much larger.

FIPS 204 defines three parameter sets, which are the members of the enum
:class:`Crypto.PublicKey.MLDSA.ParamSet`:

.. _ML-DSA table:
.. csv-table::
   :header: Parameter set, Enum member, NIST security category, Public key, Expanded private key, Signature
   :widths: 15, 25, 15, 15, 15, 15

   "ML-DSA-44", "``ParamSet.ML_DSA_44``", "2", "1312 bytes", "2560 bytes", "2420 bytes"
   "ML-DSA-65", "``ParamSet.ML_DSA_65``", "3", "1952 bytes", "4032 bytes", "3309 bytes"
   "ML-DSA-87", "``ParamSet.ML_DSA_87``", "5", "2592 bytes", "4896 bytes", "4627 bytes"

The value of each member is the name of the parameter set
(for instance, ``ParamSet('ML-DSA-65')`` is ``ParamSet.ML_DSA_65``).

A private key can be represented in two ways:

* the **seed**: the 32 random bytes the key is generated from
  (:math:`\xi` in FIPS 204). It is the most compact form,
  and the one recommended by `RFC 9881`_.
* the **expanded private key**: the encoding defined in FIPS 204
  (Algorithm 24). It cannot be converted back to the seed.

With this module you can generate a new ML-DSA key::

    >>> from Crypto.PublicKey import MLDSA
    >>> from Crypto.PublicKey.MLDSA import ParamSet
    >>>
    >>> key = MLDSA.generate(param_set=ParamSet.ML_DSA_65)
    >>> seed = key.seed       # 32 bytes, keep it secret
    >>> pk = key.pk           # 1952 bytes

and rebuild it later from its seed (or from the expanded private key),
or get the public key::

    >>> key = MLDSA.construct(param_set=ParamSet.ML_DSA_65, seed=seed)
    >>> pub_key = MLDSA.construct(param_set=ParamSet.ML_DSA_65, pk=pk)
    >>> pub_key == key.public_key()
    True

.. note::

    The signature schemes (ML-DSA and HashML-DSA) will be available in a
    dedicated module in :mod:`Crypto.Signature`.
    The import and export of keys (PKCS#8 and X.509, as in `RFC 9881`_)
    are not supported yet either.

The implementation is based on `mldsa-native`_ (portable C code only).

.. _`FIPS 204`: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
.. _`RFC 9881`: https://www.rfc-editor.org/rfc/rfc9881.html
.. _mldsa-native: https://github.com/pq-code-package/mldsa-native

.. automodule:: Crypto.PublicKey.MLDSA
    :members:
