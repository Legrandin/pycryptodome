Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
=========================================================

ML-DSA is the post-quantum digital signature scheme standardized by NIST in
`FIPS 204 <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>`_.
Its keys are in :mod:`Crypto.PublicKey.MLDSA`.

FIPS 204 defines two variants:

* *ML-DSA*, where the message is signed directly (recommended).
* *HashML-DSA*, where the message is first hashed, and only the resulting digest is signed.
  This should only be used by applications that cannot process the whole message
  at once when signing, because it requires a hash function with enough
  collision resistance.

This module supports both variants, with any of the three parameter sets
(ML-DSA-44, ML-DSA-65 and ML-DSA-87).

A signature also depends on a *context*: up to 255 bytes that separate
different protocols or applications using the same key (empty by default).
The same context must be used to sign and to verify.

By default, the signature is *hedged*: it also depends on fresh random bytes,
which protects against fault and side-channel attacks.
With ``deterministic=True``, it only depends on the key, the context and the message.
Both kinds of signatures are verified in the same way.

A sender can use a *private* key (loaded from a file) to sign a message::

        from Crypto.PublicKey import MLDSA
        from Crypto.Signature import mldsa

        message = b'I give my permission to order #4355'
        key = MLDSA.import_key(open("private_mldsa.pem").read())
        signer = mldsa.new(key)
        signature = signer.sign(message)

The receiver can use the matching *public* key to verify the authenticity of the received message::

        from Crypto.PublicKey import MLDSA
        from Crypto.Signature import mldsa

        message = b'I give my permission to order #4355'
        key = MLDSA.import_key(open("public_mldsa.pem").read())
        verifier = mldsa.new(key)
        try:
            verifier.verify(message, signature)
            print("The message is authentic")
        except ValueError:
            print("The message is not authentic")

For *HashML-DSA*, pass a hash object that has processed the message,
instead of the message itself::

        from Crypto.Hash import SHA512
        from Crypto.PublicKey import MLDSA
        from Crypto.Signature import mldsa

        message = b'I give my permission to order #4355'
        key = MLDSA.import_key(open("private_mldsa.pem").read())
        signer = mldsa.new(key, b'my application')
        signature = signer.sign(SHA512.new(message))

The hash function can be SHA-2 (:mod:`Crypto.Hash.SHA224`, :mod:`Crypto.Hash.SHA256`,
:mod:`Crypto.Hash.SHA384`, :mod:`Crypto.Hash.SHA512`, also truncated),
SHA-3 (:mod:`Crypto.Hash.SHA3_224`, :mod:`Crypto.Hash.SHA3_256`,
:mod:`Crypto.Hash.SHA3_384`, :mod:`Crypto.Hash.SHA3_512`) or SHAKE
(:mod:`Crypto.Hash.SHAKE128` and :mod:`Crypto.Hash.SHAKE256`, with 256 and 512 bits of output).
To keep the security level of the key, FIPS 204 (Section 5.4) asks for a function with
at least 128 bits of collision resistance for ML-DSA-44 (like SHA-256),
192 bits for ML-DSA-65 (like SHA-384) and 256 bits for ML-DSA-87 (like SHA-512).

To process a large message in pieces with *ML-DSA* (not *HashML-DSA*),
use an :class:`MLDSAMuHash`. It computes the message representative :math:`\mu`
of FIPS 204 (*external mu*) for a given key and context, and it can be passed
to :meth:`MLDSASigScheme.sign` and :meth:`MLDSASigScheme.verify` instead of the message.
The signature is the same as for the whole message::

        from Crypto.PublicKey import MLDSA
        from Crypto.Signature import mldsa

        key = MLDSA.import_key(open("private_mldsa.pem").read())
        mu_hash = mldsa.MLDSAMuHash(key, context=b'my application')
        for chunk in message_chunks:
            mu_hash.update(chunk)
        signature = mldsa.new(key).sign(mu_hash)

        # The receiver can verify with the whole message too
        mldsa.new(key.public_key(), b'my application').verify(message, signature)

The context belongs to the :class:`MLDSAMuHash`: the signature object must
then be created without one.
An :class:`MLDSAMuHash` only needs the public key: :math:`\mu` can also be computed
apart from the private key (see :meth:`MLDSAMuHash.digest`).

.. automodule:: Crypto.Signature.mldsa
    :members:
