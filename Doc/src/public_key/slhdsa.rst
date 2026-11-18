SLH-DSA
=======

.. currentmodule:: Crypto.PublicKey.SLHDSA

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is the post-quantum
signature algorithm standardized by NIST in `FIPS 205`_.
It is derived from SPHINCS\ :sup:`+`.

This module generates, builds, imports and exports SLH-DSA keys.
To sign messages and verify signatures with them, use :mod:`Crypto.Signature.slhdsa`
(see `Usage`_).

Its security only depends on the properties of the underlying hash function
(SHA-2 or SHAKE), which makes it a conservative choice.
Compared to ML-DSA, keys are very small, but signatures are much larger and
signing is much slower.

FIPS 205 defines twelve parameter sets: for each
:ref:`NIST security category <nist_security_categories>`, there are
two hash families (SHA2 or SHAKE), and a choice between *small* signatures (``s``)
or *fast* signing (``f``):

.. _SLH-DSA table:
.. csv-table::
   :header: Parameter set, Constant, NIST security category, "Public key (bytes)", "Private key (bytes)", "Signature (bytes)"
   :class: compact-table

   "SLH-DSA-SHA2-128s", "``SLHDSA.SLH_DSA_SHA2_128s``", "1", "32", "64", "7856"
   "SLH-DSA-SHAKE-128s", "``SLHDSA.SLH_DSA_SHAKE_128s``", "1", "32", "64", "7856"
   "SLH-DSA-SHA2-128f", "``SLHDSA.SLH_DSA_SHA2_128f``", "1", "32", "64", "17088"
   "SLH-DSA-SHAKE-128f", "``SLHDSA.SLH_DSA_SHAKE_128f``", "1", "32", "64", "17088"
   "SLH-DSA-SHA2-192s", "``SLHDSA.SLH_DSA_SHA2_192s``", "3", "48", "96", "16224"
   "SLH-DSA-SHAKE-192s", "``SLHDSA.SLH_DSA_SHAKE_192s``", "3", "48", "96", "16224"
   "SLH-DSA-SHA2-192f", "``SLHDSA.SLH_DSA_SHA2_192f``", "3", "48", "96", "35664"
   "SLH-DSA-SHAKE-192f", "``SLHDSA.SLH_DSA_SHAKE_192f``", "3", "48", "96", "35664"
   "SLH-DSA-SHA2-256s", "``SLHDSA.SLH_DSA_SHA2_256s``", "5", "64", "128", "29792"
   "SLH-DSA-SHAKE-256s", "``SLHDSA.SLH_DSA_SHAKE_256s``", "5", "64", "128", "29792"
   "SLH-DSA-SHA2-256f", "``SLHDSA.SLH_DSA_SHA2_256f``", "5", "64", "128", "49856"
   "SLH-DSA-SHAKE-256f", "``SLHDSA.SLH_DSA_SHAKE_256f``", "5", "64", "128", "49856"

Pass one of these constants as the ``param_set`` argument.
They are the members of the enum :class:`ParamSet`,
and the value of each member is the name of its parameter set (for instance, ``'SLH-DSA-SHA2-128s'``).
The six parameter sets of `SP 800-230`_ are also members, but their support is **experimental**
and they must not be used in production (see `SP 800-230 parameter sets`_).

On a recent x86-64 CPU, signing takes from a few tens of milliseconds (``f`` sets)
to about a second (``s`` sets, slower with SHAKE than with SHA2), and
verifying a few milliseconds. Generating a key (or building it from a private key)
takes from about a millisecond (``f``) to a few hundred milliseconds (``s``).

The private key (:attr:`SLHDSAKey.sk`) and the public key (:attr:`SLHDSAKey.pk`)
are encoded as in FIPS 205: the private key is made of four values of *n* bytes
(SK.seed, SK.prf, PK.seed, PK.root), and the public key is its second half
(PK.seed and PK.root).

The implementation follows FIPS 205 in Python, with the functions that compute most of the
hashes in C (on top of the SHA-2 and SHAKE code of PyCryptodome).
On CPUs with the Intel SHA extensions, SHA-256 uses them.
On CPUs with AVX2 and BMI2, the SHAKE parameter sets compute 4 hashes at once.

.. _SP 800-230 parameter sets:

Parameter sets with at most 2\ :sup:`24` signatures
----------------------------------------------------

.. warning::

    **The support for these parameter sets is experimental: do not use them in production.**

    They come from the initial public draft of NIST `SP 800-230`_
    (April 2026), which is not final yet: they may still change.
    Keys and signatures made with them may not be compatible with the final standard,
    nor with future versions of this module, which may change or remove these parameter sets
    without a deprecation period.

    The security of a key relies on it signing **at most 2**\ :sup:`24` **messages**
    (about 16 million), across all the devices that share it, for its entire lifetime.
    Use them only if you can guarantee that.

SP 800-230 defines six more parameter sets, with smaller signatures and faster
verification than FIPS 205, for applications that sign rarely and verify often
(like software, firmware and certificates).
They have a single XMSS tree (*d* = 1), with *w* = 4 or 8 instead of 16:

.. _SP 800-230 table:
.. csv-table::
   :header: Parameter set, Constant, NIST security category, "Public key (bytes)", "Private key (bytes)", "Signature (bytes)"
   :class: compact-table

   "SLH-DSA-SHA2-128-24", "``SLHDSA.SLH_DSA_SHA2_128_24``", "1", "32", "64", "3856"
   "SLH-DSA-SHAKE-128-24", "``SLHDSA.SLH_DSA_SHAKE_128_24``", "1", "32", "64", "3856"
   "SLH-DSA-SHA2-192-24", "``SLHDSA.SLH_DSA_SHA2_192_24``", "3", "48", "96", "7752"
   "SLH-DSA-SHAKE-192-24", "``SLHDSA.SLH_DSA_SHAKE_192_24``", "3", "48", "96", "7752"
   "SLH-DSA-SHA2-256-24", "``SLHDSA.SLH_DSA_SHA2_256_24``", "5", "64", "128", "14944"
   "SLH-DSA-SHAKE-256-24", "``SLHDSA.SLH_DSA_SHAKE_256_24``", "5", "64", "128", "14944"

The price is the time to generate a key (or to build it from a private key) and to sign:
about a billion hashes each, which takes several minutes on one CPU core.
Use the ``threads`` parameter of :func:`generate`, :func:`construct` and
:func:`Crypto.Signature.slhdsa.new` to spread the work over several cores.

SP 800-230 also allows an implementation to store parts of the hypertree to sign faster:
this module does not do that.

Generation
----------

You can generate a new SLH-DSA key::

    >>> from Crypto.PublicKey import SLHDSA
    >>>
    >>> key = SLHDSA.generate(param_set=SLHDSA.SLH_DSA_SHA2_128s)
    >>> sk = key.sk           # 64 bytes, keep it secret
    >>> pk = key.pk           # 32 bytes, the public key

and rebuild it later from its private key, or get the public key::

    >>> key = SLHDSA.construct(param_set=SLHDSA.SLH_DSA_SHA2_128s, sk=sk)
    >>> pub_key = SLHDSA.construct(param_set=SLHDSA.SLH_DSA_SHA2_128s, pk=pk)
    >>> pub_key == key.public_key()
    True

:func:`construct` checks that the private key is consistent (that PK.root matches the other values).
With the `SP 800-230 parameter sets`_, :func:`generate` and :func:`construct`
take several minutes: use their ``threads`` parameter (for instance, ``threads=0`` for all CPU cores).

To store a private key, prefer :meth:`SLHDSAKey.export_key` with a passphrase
(see the next section): the raw private key is not protected.

Import and Export
-----------------

You can export an SLH-DSA key as defined in `RFC 9909`_:
a public key as an X.509 ``SubjectPublicKeyInfo``, a private key as a
PKCS#8 ``OneAsymmetricKey``, optionally protected with a passphrase.
These are the usual formats for public and private keys.
The encoding is DER (binary, the default) or PEM (text, `RFC 7468`_)::

    with open("myprivatekey.pem", "wt") as f:
        f.write(key.export_key(format="PEM", passphrase="secret"))

    with open("mypublickey.der", "wb") as f:
        f.write(key.public_key().export_key())

and import it later (the format is detected automatically)::

    with open("myprivatekey.pem", "rt") as f:
        key = SLHDSA.import_key(f.read(), "secret")

:func:`import_key` also accepts X.509 certificates.
Like :func:`construct`, it checks that a private key is consistent, which takes
as long as generating a key (use its ``threads`` parameter).

Only the keys for pure SLH-DSA (with the OIDs ``id-slh-dsa-*``) are supported,
not those restricted to HashSLH-DSA (``id-hash-slh-dsa-*``).
The keys of the SP 800-230 parameter sets cannot be exported or imported:
there are no OIDs for them yet.

Usage
-----

To sign messages and verify signatures with SLH-DSA keys,
use :mod:`Crypto.Signature.slhdsa`.

.. _`FIPS 205`: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
.. _`SP 800-230`: https://csrc.nist.gov/pubs/sp/800/230/ipd
.. _`RFC 9909`: https://www.rfc-editor.org/rfc/rfc9909.html
.. _`RFC 7468`: https://www.rfc-editor.org/rfc/rfc7468.html

API
---

.. automodule:: Crypto.PublicKey.SLHDSA
    :members:
    :member-order: bysource
