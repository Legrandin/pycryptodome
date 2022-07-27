Edwards-curve Digital Signature Algorithm (EdDSA)
=================================================

EdDSA is a deterministic digital signature scheme
based on twisted Edwards elliptic curves (Ed25519 and Ed448).
It is specified in `RFC8032 <https://datatracker.ietf.org/doc/html/rfc8032>`_,
as two variants:

* *PureEdDSA*, where the message is signed directly.
* *HashEdDSA*, where the message is first hashed, and only the resulting digest is signed.
  This should only be used by streaming applications because it avoids double passess
  on messages.

This module supports signatures for both variants (*PureEdDSA* and *HashEdDSA*),
on the Ed25519 curve (with a 128-bit security level), and
on the Ed448 curve (with a 224-bit security level).

For *HashEdDSA*, the hash function must be SHA-512 in case of Ed25519,
and SHAKE256 for Ed448.

A sender can use a *private* key (loaded from a file) to sign a message::

        from Crypto.PublicKey import ECC
        from Signature import eddsa

        message = b'I give my permission to order #4355'
        key = ECC.import_key(open("private_ed25519.pem").read()))
        signer = eddsa.new(key, 'rfc8032')
        signature = signer.sign(message)

The receiver can use the matching *public* key to verify authenticity of the received message::

        from Crypto.PublicKey import ECC
        from Signature import eddsa

        message = b'I give my permission to order #4355'
        key = ECC.import_key(open("public_ed25519.pem").read()))
        verifier = eddsa.new(key, 'rfc8032')
        try:
            verifier.verify(message, signature)
            print("The message is authentic")
        except ValueError:
            print("The message is not authentic")

Alternatively the *HashedEdDSA* variant can be used to sign a message with Ed25519::

        from Crypto.PublicKey import ECC
        from Signature import eddsa
        from Crypto.Hash import SHA512

        message = b'I give my permission to order #4355'
        prehashed_message = SHA512.new(message)
        key = ECC.import_key(open("private_ed25519.pem").read()))
        signer = eddsa.new(key, 'rfc8032')
        signature = signer.sign(prehashed_message)

*HashedEdDSA* also exists for Ed448::

        from Crypto.PublicKey import ECC
        from Signature import eddsa
        from Crypto.Hash import SHAKE256

        message = b'I give my permission to order #4355'
        prehashed_message = SHAKE256.new(message)
        key = ECC.import_key(open("private_ed448.pem").read()))
        signer = eddsa.new(key, 'rfc8032')
        signature = signer.sign(prehashed_message)


.. automodule:: Crypto.Signature.eddsa
    :members:
