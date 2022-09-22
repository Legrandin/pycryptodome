Digital Signature Algorithm (DSA and ECDSA)
===========================================

DSA and ECDSA are U.S. federal standards for digital signatures, specified in `FIPS PUB 186-4`__.

Their security relies on the discrete logarithm problem in a prime finite field (the original DSA,
now deprecated) or in an elliptic curve field (ECDSA, faster and with smaller keys,
to be used in new applications).

A sender can use a *private* key (loaded from a file) to sign a message::

        >>> from Crypto.Hash import SHA256
        >>> from Crypto.PublicKey import ECC
        >>> from Crypto.Signature import DSS
        >>>
        >>> message = b'I give my permission to order #4355'
        >>> key = ECC.import_key(open('privkey.der').read())
        >>> h = SHA256.new(message)
        >>> signer = DSS.new(key, 'fips-186-3')
        >>> signature = signer.sign(h)

The receiver can use the matching *public* key to verify authenticity of the received message::

        >>> from Crypto.Hash import SHA256
        >>> from Crypto.PublicKey import ECC
        >>> from Crypto.Signature import DSS
        >>>
        >>> key = ECC.import_key(open('pubkey.der').read())
        >>> h = SHA256.new(received_message)
        >>> verifier = DSS.new(key, 'fips-186-3')
        >>> try:
        >>>     verifier.verify(h, signature)
        >>>     print "The message is authentic."
        >>> except ValueError:
        >>>     print "The message is not authentic."

.. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

.. automodule:: Crypto.Signature.DSS
    :members:
