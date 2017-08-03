PKCS#1 PSS (RSA)
================

A probabilistic digital signature scheme based on RSA.

It is more formally called ``RSASSA-PSS``
in `Section 8.1 of RFC8017`__.

The following example shows how the sender can create the signature of
a message using their own *private* key (loaded from a file)::

    >>> from Crypto.Signature import pss
    >>> from Crypto.Hash import SHA256
    >>> from Crypto.PublicKey import RSA
    >>> from Crypto import Random
    >>>
    >>> message = 'To be signed'
    >>> key = RSA.importKey(open('privkey.der').read())
    >>> h = SHA256.new(message)
    >>> signature = pss.new(key).sign(h)

At the receiver side, verification can be done using the matching *public* RSA key::

    >>> key = RSA.importKey(open('pubkey.der').read())
    >>> h = SHA256.new(message)
    >>> verifier = pss.new(key)
    >>> try:
    >>>     verifier.verify(h, signature):
    >>>     print "The signature is authentic."
    >>> except (ValueError, TypeError):
    >>>     print "The signature is not authentic."

.. __: https://tools.ietf.org/html/rfc8017#section-8.1

.. automodule:: Crypto.Signature.pss
    :members:
