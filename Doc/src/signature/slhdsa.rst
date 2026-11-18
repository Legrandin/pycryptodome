Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)
==========================================================

SLH-DSA is the post-quantum, hash-based digital signature scheme standardized by NIST in
`FIPS 205 <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf>`_.
Its keys are in :mod:`Crypto.PublicKey.SLHDSA`.

FIPS 205 defines two variants:

* *SLH-DSA*, where the message is signed directly (recommended).
* *HashSLH-DSA*, where the message is first hashed, and only the resulting digest is signed.
  This should only be used by applications that cannot process the whole message
  at once when signing, because it requires a hash function with enough
  collision resistance.

This module supports both variants, with any of the twelve parameter sets of FIPS 205,
and the six parameter sets of the draft SP 800-230, whose support is **experimental**:
do not use them in production (see :mod:`Crypto.PublicKey.SLHDSA`).

A signature also depends on a *context*: up to 255 bytes that separate
different protocols or applications using the same key (empty by default).
The same context must be used to sign and to verify.

By default, the signature is *hedged*: it also depends on fresh random bytes,
which protects against fault and side-channel attacks.
With ``deterministic=True``, it only depends on the key, the context and the message.
Both kinds of signatures are verified in the same way.

A sender can use a *private* key (loaded from a file) to sign a message::

        from Crypto.PublicKey import SLHDSA
        from Crypto.Signature import slhdsa

        message = b'I give my permission to order #4355'
        key = SLHDSA.import_key(open("private_slhdsa.pem").read())
        signer = slhdsa.new(key)
        signature = signer.sign(message)

The receiver can use the matching *public* key to verify the authenticity of the received message::

        from Crypto.PublicKey import SLHDSA
        from Crypto.Signature import slhdsa

        message = b'I give my permission to order #4355'
        key = SLHDSA.import_key(open("public_slhdsa.pem").read())
        verifier = slhdsa.new(key)
        try:
            verifier.verify(message, signature)
            print("The message is authentic")
        except ValueError:
            print("The message is not authentic")

For *HashSLH-DSA*, pass a hash object that has processed the message,
instead of the message itself::

        from Crypto.Hash import SHA256
        from Crypto.PublicKey import SLHDSA
        from Crypto.Signature import slhdsa

        message = b'I give my permission to order #4355'
        key = SLHDSA.import_key(open("private_slhdsa.pem").read())
        signer = slhdsa.new(key, context=b'my application')
        signature = signer.sign(SHA256.new(message))

The hash function can be SHA-2 (:mod:`Crypto.Hash.SHA224`, :mod:`Crypto.Hash.SHA256`,
:mod:`Crypto.Hash.SHA384`, :mod:`Crypto.Hash.SHA512`, also truncated),
SHA-3 (:mod:`Crypto.Hash.SHA3_224`, :mod:`Crypto.Hash.SHA3_256`,
:mod:`Crypto.Hash.SHA3_384`, :mod:`Crypto.Hash.SHA3_512`) or SHAKE
(:mod:`Crypto.Hash.SHAKE128` and :mod:`Crypto.Hash.SHAKE256`, with 256 and 512 bits of output).
To keep the security level of the key, FIPS 205 (Section 10.2.2) asks for a function with
at least as much collision resistance as the parameter set: for instance, SHA-256 or
SHAKE128 for the parameter sets of category 1, and SHA-512 or SHAKE256 for those of category 5.

Signing is slow, especially with the ``s`` parameter sets of FIPS 205,
and even more with those of SP 800-230 (several minutes): with ``threads``,
:func:`new` can use several CPU cores (``threads=0`` for all of them).
The signature is the same with any number of threads.

.. automodule:: Crypto.Signature.slhdsa
    :members:
