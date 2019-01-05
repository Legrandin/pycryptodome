PKCS#1 v1.5 (RSA)
=================

An old but still solid digital signature scheme based on RSA.

It is more formally called ``RSASSA-PKCS1-v1_5``
in `Section 8.2 of RFC8017`__.

The following example shows how the a *private* RSA key (loaded from a file)
can be used to compute the signature of a message::

        >>> from Crypto.Signature import pkcs1_15
        >>> from Crypto.Hash import SHA256
        >>> from Crypto.PublicKey import RSA
        >>>
        >>> message = 'To be signed'
        >>> key = RSA.import_key(open('private_key.der').read())
        >>> h = SHA256.new(message)
        >>> signature = pkcs1_15.new(key).sign(h)

At the other end, the receiver can verify the signature (and therefore
the authenticity of the message) using the matching *public* RSA key::

        >>> key = RSA.import_key(open('public_key.der').read())
        >>> h = SHA.new(message)
        >>> try:
        >>>     pkcs1_15.new(key).verify(h, signature)
        >>>     print "The signature is valid."
        >>> except (ValueError, TypeError):
        >>>    print "The signature is not valid."

.. __: https://tools.ietf.org/html/rfc8017

.. automodule:: Crypto.Signature.pkcs1_15
    :members:
