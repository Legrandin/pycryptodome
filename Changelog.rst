Changelog
=========

3.4.3 (17 October 2016)
+++++++++++++++++++++++

Resolved issues
---------------

* Undefined warning was raised with libgmp version < 5
* Forgot inclusion of ``alloca.h``
* Fixed a warning about type mismatch raised by recent versions of cffi

3.4.2 (8 March 2016)
+++++++++++++++++++


Resolved issues
---------------

* Fix renaming of package for ``install`` command.


3.4.1 (21 February 2016)
+++++++++++++++++++

New features
------------

* Added option to install the library under the ``Cryptodome`` package
  (instead of ``Crypto``).

3.4 (7 February 2016)
+++++++++++++++++++

New features
------------

* Added ``Crypto.PublicKey.ECC`` module (NIST P-256 curve only), including export/import of ECC keys.
* Added support for ECDSA (FIPS 186-3 and RFC6979).
* For CBC/CFB/OFB/CTR cipher objects, ``encrypt()`` and ``decrypt()`` cannot be intermixed.
* CBC/CFB/OFB, the cipher objects have both ``IV`` and ``iv`` attributes.
  ``new()`` accepts ``IV`` as well as ``iv`` as parameter.
* For CFB/OPENPGP cipher object, ``encrypt()`` and ``decrypt()`` do not require the plaintext
  or ciphertext pieces to have length multiple of the CFB segment size.
* Added dedicated tests for all cipher modes, including NIST test vectors
* CTR/CCM/EAX/GCM/SIV/Salsa20/ChaCha20 objects expose the ``nonce`` attribute.
* For performance reasons, CCM cipher optionally accepted a pre-declaration of
  the length of the associated data, but never checked if the actual data passed
  to the cipher really matched that length. Such check is now enforced.
* CTR cipher objects accept parameter ``nonce`` and possibly ``initial_value`` in
  alternative to ``counter`` (which is deprecated).
* All ``iv``/``IV`` and ``nonce`` parameters are optional. If not provided,
  they will be randomly generated (exception: ``nonce`` for CTR mode in case
  of block sizes smaller than 16 bytes).
* Refactored ARC2 cipher.
* Added ``Crypto.Cipher.DES3.adjust_key_parity()`` function.
* Added ``RSA.import_key`` as an alias to the deprecated ``RSA.importKey``
  (same for the ``DSA`` module).
* Added ``size_in_bits()`` and ``size_in_bytes()`` methods to ``RsaKey``.

Resolved issues
---------------

* RSA key size is now returned correctly in ``RsaKey.__repr__()`` method (kudos to *hannesv*).
* CTR mode does not modify anymore ``counter`` parameter passed to ``new()`` method.
* CTR raises ``OverflowError`` instead of ``ValueError`` when the counter wraps around.
* PEM files with Windows newlines could not be imported.
* ``Crypto.IO.PEM`` and ``Crypto.IO.PKCS8`` used to accept empty passphrases.
* GH#6: NotImplementedError now raised for unsupported methods ``sign``, ``verify``,
  ``encrypt``, ``decrypt``, ``blind``, ``unblind`` and ``size`` in objects ``RsaKey``, ``DsaKey``,
  ``ElGamalKey``.

Breaks in compatibility
-----------------------

* Parameter ``segment_size`` cannot be 0 for the CFB mode.
* For OCB ciphers, a final call without parameters to ``encrypt`` must end a sequence
  of calls to ``encrypt`` with data (similarly for ``decrypt``).
* Key size for ``ARC2``, ``ARC4`` and ``Blowfish`` must be at least 40 bits long (still very weak).
* DES3 (Triple DES module) does not allow keys that degenerate to Single DES.
* Removed method ``getRandomNumber`` in ``Crypto.Util.number``.
* Removed module ``Crypto.pct_warnings``.
* Removed attribute ``Crypto.PublicKey.RSA.algorithmIdentifier``.

3.3.1 (1 November 2015)
+++++++++++++++++++

New features
------------

* Opt-in for ``update()`` after ``digest()`` for SHA-3, keccak, BLAKE2 hashes

Resolved issues
------------

* Removed unused SHA-3 and keccak test vectors, therefore significantly reducing
  the package from 13MB to 3MB.

Breaks in compatibility
-----------------------

* Removed method ``copy()`` from BLAKE2 hashes
* Removed ability to ``update()`` a BLAKE2 hash after the first call to ``(hex)digest()``

3.3 (29 October 2015)
+++++++++++++++++++

New features
------------

* Windows wheels bundle the MPIR library
* Detection of faults occuring during secret RSA operations
* Detection of non-prime (weak) q value in DSA domain parameters
* Added original Keccak hash family (b=1600 only).
  In the process, simplified the C code base for SHA-3.
* Added SHAKE128 and SHAKE256 (of SHA-3 family)

Resolved issues
---------------

* GH#3: gcc 4.4.7 unhappy about double typedef

Breaks in compatibility
-----------------------

* Removed method ``copy()`` from all SHA-3 hashes
* Removed ability to ``update()`` a SHA-3 hash after the first call to ``(hex)digest()``

3.2.1 (9 September 2015)
+++++++++++++++++++

New features
------------

* Windows wheels are automatically built on Appveyor

3.2 (6 September 2015)
+++++++++++++++++++

New features
------------

* Added hash functions BLAKE2b and BLAKE2s.
* Added stream cipher ChaCha20.
* Added OCB cipher mode.
* CMAC raises an exception whenever the message length is found to be
  too large and the chance of collisions not negligeable.
* New attribute ``oid`` for Hash objects with ASN.1 Object ID
* Added ``Crypto.Signature.pss`` and ``Crypto.Signature.pkcs1_15``
* Added NIST test vectors (roughly 1200) for PKCS#1 v1.5 and PSS signatures.

Resolved issues
---------------

* tomcrypt_macros.h asm error #1

Breaks in compatibility
-----------------------

* Removed keyword ``verify_x509_cert`` from module method ``importKey`` (RSA and DSA).
* Reverted to original PyCrypto behavior of method ``verify`` in ``PKCS1_v1_5``
  and ``PKCS1_PSS``.

3.1 (15 March 2015)
+++++++++++++++++++

New features
------------

* Speed up execution of Public Key algorithms on PyPy, when backed
  by the Gnu Multiprecision (GMP) library.
* GMP headers and static libraries are not required anymore at the time
  PyCryptodome is built. Instead, the code will automatically use the
  GMP dynamic library (.so/.DLL) if found in the system at runtime.
* Reduced the amount of C code by almost 40% (4700 lines).
  Modularized and simplified all code (C and Python) related to block ciphers.
  Pycryptodome is now free of CPython extensions.
* Add support for CI in Windows via Appveyor.
* RSA and DSA key generation more closely follows FIPS 186-4 (though it is
  not 100% compliant).

Resolved issues
---------------

* None

Breaks in compatibility
-----------------------

* New dependency on ctypes with Python 2.4.
* The ``counter`` parameter of a CTR mode cipher must be generated via
  ``Crypto.Util.Counter``. It cannot be a generic callable anymore.
* Removed the ``Crypto.Random.Fortuna`` package (due to lack of test vectors).
* Removed the ``Crypto.Hash.new`` function.
* The ``allow_wraparound`` parameter of ``Crypto.Util.Counter`` is ignored.
  An exception is always generated if the counter is reused.
* ``DSA.generate``, ``RSA.generate`` and ``ElGamal.generate`` do not
  accept the ``progress_func`` parameter anymore.
* Removed ``Crypto.PublicKey.RSA.RSAImplementation``.
* Removed ``Crypto.PublicKey.DSA.DSAImplementation``.
* Removed ambiguous method ``size()`` from RSA, DSA and ElGamal keys.

3.0 (24 June 2014)
++++++++++++++++++

New features
------------

* Initial support for PyPy.
* SHA-3 hash family based on the April 2014 draft of FIPS 202.
  See modules ``Crypto.Hash.SHA3_224/256/384/512``.
  Initial Keccak patch by Fabrizio Tarizzo.
* Salsa20 stream cipher. See module ``Crypto.Cipher.Salsa20``.
  Patch by Fabrizio Tarizzo.
* Colin Percival's ``scrypt`` key derivation function (``Crypto.Protocol.KDF.scrypt``).
* Proper interface to FIPS 186-3 DSA. See module ``Crypto.Signature.DSS``.
* Deterministic DSA (RFC6979). Again, see ``Crypto.Signature.DSS``.
* HMAC-based Extract-and-Expand key derivation function
  (``Crypto.Protocol.KDF.HKDF``, RFC5869).
* Shamir's Secret Sharing protocol, compatible with *ssss* (128 bits only).
  See module ``Crypto.Protocol.SecretSharing``.
* Ability to generate a DSA key given the domain parameters.
* Ability to test installation with a simple ``python -m Crypto.SelfTest``.

Resolved issues
---------------

* LP#1193521: ``mpz_powm_sec()`` (and Python) crashed when modulus was odd.
* Benchmarks work again (they broke when ECB stopped working if
  an IV was passed. Patch by Richard Mitchell.
* LP#1178485: removed some catch-all exception handlers.
  Patch by Richard Mitchell.
* LP#1209399: Removal of Python wrappers caused HMAC to silently
  produce the wrong data with SHA-2 algorithms.
* LP#1279231: remove dead code that does nothing in SHA-2 hashes.
  Patch by Richard Mitchell.
* LP#1327081: AESNI code accesses memory beyond buffer end.
* Stricter checks on ciphertext and plaintext size for textbook RSA
  (kudos to sharego).

Breaks in compatibility
-----------------------

* Removed support for Python < 2.4.
* Removed the following methods from all 3 public key object types (RSA, DSA, ElGamal):

  - ``sign``
  - ``verify``
  - ``encrypt``
  - ``decrypt``
  - ``blind``
  - ``unblind``

  Code that uses such methods is doomed anyway. It should be fixed ASAP to
  use the algorithms available in ``Crypto.Signature`` and ``Crypto.Cipher``.
* The 3 public key object types (RSA, DSA, ElGamal) are now unpickable.
* Symmetric ciphers do not have a default mode anymore (used to be ECB).
  An expression like ``AES.new(key)`` will now fail. If ECB is the desired mode,
  one has to explicitly use ``AES.new(key, AES.MODE_ECB)``.
* Unsuccessful verification of a signature will now raise an exception [reverted in 3.2].
* Removed the ``Crypto.Random.OSRNG`` package.
* Removed the ``Crypto.Util.winrandom`` module.
* Removed the ``Crypto.Random.randpool`` module.
* Removed the ``Crypto.Cipher.XOR`` module.
* Removed the ``Crypto.Protocol.AllOrNothing`` module.
* Removed the ``Crypto.Protocol.Chaffing`` module.
* Removed the parameters ``disabled_shortcut`` and ``overflow`` from ``Crypto.Util.Counter.new``.

Other changes
-------------

* ``Crypto.Random`` stops being a userspace CSPRNG. It is now a pure wrapper over ``os.urandom``.
* Added certain resistance against side-channel attacks for GHASH (GCM) and DSA.
* More test vectors for ``HMAC-RIPEMD-160``.
* Update ``libtomcrypt`` headers and code to v1.17 (kudos to Richard Mitchell).
* RSA and DSA keys are checked for consistency as they are imported.
* Simplified build process by removing autoconf.
* Speed optimization to PBKDF2.
* Add support for MSVC.
* Replaced HMAC code with a BSD implementation. Clarified that starting from the fork,
  all contributions are released under the BSD license.
