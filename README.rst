.. image:: https://github.com/Legrandin/pycryptodome/workflows/Integration%20test/badge.svg
   :target: https://github.com/Legrandin/pycryptodome/actions

.. image:: https://badge.fury.io/py/pycryptodome.svg
   :target: https://pypi.org/project/pycryptodome

PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives: one ``pip install``, no system libraries,
and a broad, consistent API from AES and RSA to HPKE, KangarooTwelve and post-quantum ML-DSA.

It supports Python 3.9 and newer, and PyPy.

You install it with::

    pip install pycryptodome

All modules are installed under the ``Crypto`` package.

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)         # a random nonce is generated
    ciphertext, tag = cipher.encrypt_and_digest(b"attack at dawn")

    receiver = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
    plaintext = receiver.decrypt_and_verify(ciphertext, tag)  # raises ValueError if tampered

.. note::
    Up to version 3.x, the library was also released as the ``pycryptodomex``
    project, installed under the ``Cryptodome`` package.
    Starting with version 4.0, ``pycryptodomex`` is no longer released and
    ``Crypto`` is the only package name.
    To migrate, replace ``Cryptodome`` with ``Crypto`` in your imports.

Why PyCryptodome
----------------

* **Self-contained.** No runtime dependencies and no system libraries:
  all the C code ships with the package, so there is nothing else to install,
  patch, or keep in sync. Building from source only needs a C compiler.
  Binary wheels are available for Linux, macOS and Windows, on x86 and ARM,
  for CPython and PyPy.
* **Broad.** Mainstream and specialized algorithms behind one consistent API,
  including many that are hard to find elsewhere in Python: SIV and OCB modes,
  AES key wrap (KW, KWP), HPKE, KMAC, TupleHash, TurboSHAKE, KangarooTwelve,
  Ed448 and X448, ML-DSA, ML-KEM, and Shamir's secret sharing.
* **Easy to use correctly.** Authenticated encryption and verification are a
  single call, nonces and IVs are generated for you, randomness comes straight
  from the operating system, and keys are imported and exported in the
  standard formats (PEM, DER, PKCS#8, OpenSSH).
* **Side-channel aware.** The big integer arithmetic on private keys runs in
  constant time, in C. RSA decryption is blinded, and elliptic curve scalar
  multiplications are blinded and use randomized coordinates.
* **Fast where it counts.** AES-NI, CLMUL, the SHA extensions, AVX2 and
  BMI2/ADX are used when the CPU has them, selected at runtime:
  the same wheel runs everywhere, at full speed on recent hardware.
* **Well tested.** Checked against the NIST and Wycheproof test vectors,
  on Linux, macOS and Windows, x86 and ARM, CPython and PyPy.
* **Permissive license.** BSD 2-Clause, and public domain for the oldest code.

For the full list of algorithms and formats, see the `features page`_.
For everything else, see the `homepage`_.

For security issues, please send an email to security@pycryptodome.org.

All the code can be downloaded from `GitHub`_.

.. _`homepage`: https://www.pycryptodome.org
.. _`features page`: https://www.pycryptodome.org/src/features
.. _GitHub: https://github.com/Legrandin/pycryptodome
