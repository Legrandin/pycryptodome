ML-DSA
======

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the post-quantum
signature algorithm standardized by NIST in `FIPS 204`_.
It is derived from CRYSTALS-Dilithium.

Its security is based on the hardness of lattice problems (Module-LWE and Module-SIS),
which are believed to be hard even for quantum computers.
Compared to RSA and ECC, keys and signatures are much larger.

FIPS 204 defines three parameter sets:

.. _ML-DSA table:
.. csv-table::
   :header: Parameter set, Constant, NIST security category, Public key, Expanded private key, Signature
   :widths: 15, 25, 15, 15, 15, 15

   "ML-DSA-44", "``MLDSA.ML_DSA_44``", "2", "1312 bytes", "2560 bytes", "2420 bytes"
   "ML-DSA-65", "``MLDSA.ML_DSA_65``", "3", "1952 bytes", "4032 bytes", "3309 bytes"
   "ML-DSA-87", "``MLDSA.ML_DSA_87``", "5", "2592 bytes", "4896 bytes", "4627 bytes"

Pass one of these constants as the ``param_set`` argument.
They are the members of the enum :class:`Crypto.PublicKey.MLDSA.ParamSet`,
and the value of each member is the name of its parameter set (for instance, ``'ML-DSA-65'``).

A private key can be represented in two ways:

* the **seed**: the 32 random bytes the key is generated from
  (:math:`\xi` in FIPS 204). It is the most compact form,
  and the one recommended by `RFC 9881`_.
* the **expanded private key**: the encoding defined in FIPS 204
  (Algorithm 24). It cannot be converted back to the seed.

With this module you can generate a new ML-DSA key::

    >>> from Crypto.PublicKey import MLDSA
    >>>
    >>> key = MLDSA.generate(param_set=MLDSA.ML_DSA_65)
    >>> seed = key.seed       # 32 bytes, keep it secret
    >>> pk = key.pk           # 1952 bytes

and rebuild it later from its seed (or from the expanded private key),
or get the public key::

    >>> key = MLDSA.construct(param_set=MLDSA.ML_DSA_65, seed=seed)
    >>> pub_key = MLDSA.construct(param_set=MLDSA.ML_DSA_65, pk=pk)
    >>> pub_key == key.public_key()
    True

You can export an ML-DSA key as defined in `RFC 9881`_:
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
    ...     key = MLDSA.import_key(f.read(), "secret")

By default, the private key in the ``OneAsymmetricKey`` is the seed.
With the parameter ``private_format``, it can also be the expanded private key
(``'expanded'``) or both (``'both'``), for other implementations that require it.
The parameter ``include_public_key`` adds the public key too.
:func:`import_key` accepts all these variants, and it checks that the seed,
the expanded private key and the public key match.

.. note::

    The signature schemes (ML-DSA and HashML-DSA) will be available in a
    dedicated module in :mod:`Crypto.Signature`.

The implementation is based on `mldsa-native`_ (portable C code only).

.. _`FIPS 204`: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
.. _`RFC 9881`: https://www.rfc-editor.org/rfc/rfc9881.html
.. _mldsa-native: https://github.com/pq-code-package/mldsa-native
.. _`RFC 7468`: https://www.rfc-editor.org/rfc/rfc7468.html

.. automodule:: Crypto.PublicKey.MLDSA
    :members:
