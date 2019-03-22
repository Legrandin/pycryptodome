Changelog
=========

3.8.0 (23 March 2019)
+++++++++++++++++++++++

New features
------------

* Speed-up ECC performance. ECDSA is 33 times faster on the NIST P-256 curve.
* Added support for NIST P-384 and P-521 curves.
* ``EccKey`` has new methods ``size_in_bits()`` and ``size_in_bytes()``.
* Support HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 in PBE2/PBKDF2.

Resolved issues
---------------

* DER objects were not rejected if their length field had a leading zero.
* Allow legacy RC2 ciphers to have 40-bit keys.
* ASN.1 Object IDs did not allow the value 0 in the path.

Breaks in compatibility
-----------------------

* ``point_at_infinity()`` becomes an instance method for ``Crypto.PublicKey.ECC.EccKey``, from a static one.

3.7.3 (19 January 2019)
+++++++++++++++++++++++

Resolved issues
---------------

* GH#258: False positive on PSS signatures when externally provided salt is too long.
* Include type stub files for ``Crypto.IO`` and ``Crypto.Util``.

3.7.2 (26 November 2018)
++++++++++++++++++++++++

Resolved issues
---------------

* GH#242: Fixed compilation problem on ARM platforms.

3.7.1 (25 November 2018)
++++++++++++++++++++++++

New features
------------

* Added type stubs to enable static type checking with mypy. Thanks to Michael Nix.
* New ``update_after_digest`` flag for CMAC.

Resolved issues
---------------

* GH#232: Fixed problem with gcc 4.x when compiling ``ghash_clmul.c``.
* GH#238: Incorrect digest value produced by CMAC after cloning the object.
* Method ``update()`` of an EAX cipher object was returning the underlying CMAC object,
  instead of the EAX object itself.
* Method ``update()`` of a CMAC object was not throwing an exception after the digest
  was computed (with ``digest()`` or ``verify()``).

3.7.0 (27 October 2018)
+++++++++++++++++++++++

New features
------------

* Added support for Poly1305 MAC (with AES and ChaCha20 ciphers for key derivation).
* Added support for ChaCha20-Poly1305 AEAD cipher.
* New parameter ``output`` for ``Crypto.Util.strxor.strxor``, ``Crypto.Util.strxor.strxor_c``,
  ``encrypt`` and ``decrypt`` methods in symmetric ciphers (``Crypto.Cipher`` package).
  ``output`` is a pre-allocated buffer (a ``bytearray`` or a writeable ``memoryview``)
  where the result must be stored.
  This requires less memory for very large payloads; it is also more efficient when
  encrypting (or decrypting) several small payloads.

Resolved issues
---------------

* GH#266: AES-GCM hangs when processing more than 4GB at a time on x86 with PCLMULQDQ instruction.

Breaks in compatibility
-----------------------

* Drop support for Python 3.3.
* Remove ``Crypto.Util.py3compat.unhexlify`` and ``Crypto.Util.py3compat.hexlify``.
* With the old Python 2.6, use only ``ctypes`` (and not ``cffi``) to interface to native code.

3.6.6 (17 August 2018)
++++++++++++++++++++++

Resolved issues
---------------

* GH#198: Fix vulnerability on AESNI ECB with payloads smaller than 16 bytes (CVE-2018-15560).

3.6.5 (12 August 2018)
++++++++++++++++++++++

Resolved issues
---------------

* GH#187: Fixed incorrect AES encryption/decryption with AES acceleration on x86
  due to gcc's optimization and strict aliasing rules.
* GH#188: More prime number candidates than necessary where discarded as composite
  due to the limited way D values were searched in the Lucas test.
* Fixed ResouceWarnings and DeprecationWarnings.
* Workaround for Python 3.7.0 bug on Windows (https://bugs.python.org/issue34108).

3.6.4 (10 July 2018)
+++++++++++++++++++++

New features
------------

* Build Python 3.7 wheels on Linux, Windows and Mac.

Resolved issues
---------------

* GH#178: Rename ``_cpuid`` module to make upgrades more robust.
* More meaningful exceptions in case of mismatch in IV length (CBC/OFB/CFB modes).
* Fix compilation issues on Solaris 10/11.

3.6.3 (21 June 2018)
+++++++++++++++++++++

Resolved issues
---------------

* GH#175: Fixed incorrect results for CTR encryption/decryption with more than 8 blocks.

3.6.2 (19 June 2018)
+++++++++++++++++++++

New features
------------
* ChaCha20 accepts 96 bit nonces (in addition to 64 bit nonces)
  as defined in RFC7539.
* Accelerate AES-GCM on x86 using PCLMULQDQ instruction.
* Accelerate AES-ECB and AES-CTR on x86 by pipelining AESNI instructions.
* As result of the two improvements above, on x86 (Broadwell):

  - AES-ECB and AES-CTR are 3x faster
  - AES-GCM is 9x faster

Resolved issues
---------------

* On Windows, MPIR library was stilled pulled in if renamed to ``gmp.dll``.

Breaks in compatibility
-----------------------

* In ``Crypto.Util.number``, functions ``floor_div`` and ``exact_div``
  have been removed. Also, ``ceil_div`` is limited to non-negative terms only.

3.6.1 (15 April 2018)
+++++++++++++++++++++

New features
------------
* Added Google Wycheproof tests (https://github.com/google/wycheproof)
  for RSA, DSA, ECDSA, GCM, SIV, EAX, CMAC.
* New parameter ``mac_len`` (length of MAC tag) for CMAC.

Resolved issues
---------------

* In certain circumstances (at counter wrapping, which happens on average after
  32 GB) AES GCM produced wrong ciphertexts.
* Method ``encrypt()`` of AES SIV cipher could be still called,
  whereas only ``encrypt_and_digest()`` is allowed.

3.6.0 (8 April 2018)
++++++++++++++++++++

New features
------------
* Introduced ``export_key`` and deprecated ``exportKey`` for DSA and RSA key
  objects.
* Ciphers and hash functions accept ``memoryview`` objects in input.
* Added support for SHA-512/224 and SHA-512/256.

Resolved issues
---------------

* Reintroduced ``Crypto.__version__`` variable as in PyCrypto.
* Fixed compilation problem with MinGW.

3.5.1 (8 March 2018)
++++++++++++++++++++

Resolved issues
---------------

* GH#142. Fix mismatch with declaration and definition of addmul128.

3.5.0 (7 March 2018)
++++++++++++++++++++

New features
------------
* Import and export of ECC curves in compressed form.
* The initial counter for a cipher in CTR mode can be a byte string
  (in addition to an integer).
* Faster PBKDF2 for HMAC-based PRFs (at least 20x for short passwords,
  more for longer passwords). Thanks to Christian Heimes for pointing
  out the implementation was under-optimized.
* The salt for PBKDF2 can be either a string or bytes (GH#67).
* Ciphers and hash functions accept data as `bytearray`, not just
  binary strings.
* The old SHA-1 and MD5 hash functions are available even when Python's
  own `hashlib` does not include them.

Resolved issues
---------------

* Without libgmp, modular exponentiation (since v3.4.8) crashed
  on 32-bit big-endian systems.

Breaks in compatibility
-----------------------

* Removed support for Python < 2.6.

3.4.12 (5 February 2018)
++++++++++++++++++++++++

Resolved issues
---------------

* GH#129. pycryptodomex could only be installed via wheels.

3.4.11 (5 February 2018)
++++++++++++++++++++++++

Resolved issues
---------------

* GH#121. the record list was still not correct due to PEP3147
  and __pycache__ directories. Thanks again to John O'Brien.

3.4.10 (2 February 2018)
++++++++++++++++++++++++

Resolved issues
---------------

* When creating ElGamal keys, the generator wasn't a square residue:
  ElGamal encryption done with those keys cannot be secure under
  the DDH assumption. Thanks to Weikeng Chen.

3.4.9 (1 February 2018)
+++++++++++++++++++++++

New features
------------
* More meaningful error messages while importing an ECC key.

Resolved issues
---------------

* GH#123 and #125. The SSE2 command line switch was not always passed on 32-bit x86 platforms.
* GH#121. The record list (--record) was not always correctly filled for the
  pycryptodomex package. Thanks to John W. O'Brien.

3.4.8 (27 January 2018)
+++++++++++++++++++++++

New features
------------

* Added a native extension in pure C for modular exponentiation, optimized for SSE2 on x86.
  In the process, we drop support for the arbitrary arithmetic library MPIR
  on Windows, which is painful to compile and deploy.
  The custom  modular exponentiation is 130% (160%) slower on an Intel CPU in 32-bit (64-bit) mode,
  compared to MPIR. Still, that is much faster that CPython's own `pow()` function which
  is 900% (855%) slower than MPIR. Support for the GMP library on Unix remains.
* Added support for *manylinux* wheels.
* Support for Python 3.7.

Resolved issues
---------------

* The DSA parameter 'p' prime was created with 255 bits cleared
  (but still with the correct strength).
* GH#106. Not all docs were included in the tar ball.
  Thanks to Christopher Hoskin.
* GH#109. ECDSA verification failed for DER encoded signatures.
  Thanks to Alastair Houghton.
* Human-friendly messages for padding errors with ECB and CBC.

3.4.7 (26 August 2017)
++++++++++++++++++++++

New features
------------

* API documentation is made with sphinx instead of epydoc.
* Start using ``importlib`` instead of ``imp`` where available.

Resolved issues
---------------

* GH#82. Fixed PEM header for RSA/DSA public keys.

3.4.6 (18 May 2017)
+++++++++++++++++++++++

Resolved issues
---------------

* GH#65. Keccak, SHA3, SHAKE and the seek functionality for ChaCha20 were
  not working on big endian machines. Fixed. Thanks to Mike Gilbert.
* A few fixes in the documentation.

3.4.5 (6 February 2017)
+++++++++++++++++++++++

Resolved issues
---------------

* The library can also be compiled using MinGW.

3.4.4 (1 February 2017)
+++++++++++++++++++++++

Resolved issues
---------------

* Removed use of ``alloca()``.
* [Security] Removed implementation of deprecated "quick check" feature of PGP block cipher mode.
* Improved the performance of ``scrypt`` by converting some Python to C.

3.4.3 (17 October 2016)
+++++++++++++++++++++++

Resolved issues
---------------

* Undefined warning was raised with libgmp version < 5
* Forgot inclusion of ``alloca.h``
* Fixed a warning about type mismatch raised by recent versions of cffi

3.4.2 (8 March 2016)
++++++++++++++++++++


Resolved issues
---------------

* Fix renaming of package for ``install`` command.


3.4.1 (21 February 2016)
++++++++++++++++++++++++

New features
------------

* Added option to install the library under the ``Cryptodome`` package
  (instead of ``Crypto``).

3.4 (7 February 2016)
+++++++++++++++++++++

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
+++++++++++++++++++++++

New features
------------

* Opt-in for ``update()`` after ``digest()`` for SHA-3, keccak, BLAKE2 hashes

Resolved issues
---------------

* Removed unused SHA-3 and keccak test vectors, therefore significantly reducing
  the package from 13MB to 3MB.

Breaks in compatibility
-----------------------

* Removed method ``copy()`` from BLAKE2 hashes
* Removed ability to ``update()`` a BLAKE2 hash after the first call to ``(hex)digest()``

3.3 (29 October 2015)
+++++++++++++++++++++

New features
------------

* Windows wheels bundle the MPIR library
* Detection of faults occurring during secret RSA operations
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
++++++++++++++++++++++++

New features
------------

* Windows wheels are automatically built on Appveyor

3.2 (6 September 2015)
++++++++++++++++++++++

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
