PKCS#1 v1.5 encryption (RSA)
============================

.. warning::
    Use :doc:`oaep` instead. This module is provided only for legacy purposes.

See RFC8017__ or the `original RSA Labs specification`__ .

This scheme is more properly called ``RSAES-PKCS1-v1_5``.

As an example, a sender may encrypt a message in this way::

        >>> from Crypto.Cipher import PKCS1_v1_5
        >>> from Crypto.PublicKey import RSA
        >>> from Crypto.Hash import SHA
        >>>
        >>> message = b'To be encrypted'
        >>> h = SHA.new(message)
        >>>
        >>> key = RSA.importKey(open('pubkey.der').read())
        >>> cipher = PKCS1_v1_5.new(key)
        >>> ciphertext = cipher.encrypt(message+h.digest())

At the receiver side, decryption can be done using the private part of
the RSA key::

        >>> From Crypto.Hash import SHA
        >>> from Crypto import Random
        >>>
        >>> key = RSA.importKey(open('privkey.der').read())
        >>>
        >>> dsize = SHA.digest_size
        >>> sentinel = Random.new().read(15+dsize)      # Let's assume that average data length is 15
        >>>
        >>> cipher = PKCS1_v1_5.new(key)
        >>> message = cipher.decrypt(ciphertext, sentinel)
        >>>
        >>> digest = SHA.new(message[:-dsize]).digest()
        >>> if digest==message[-dsize:]:                # Note how we DO NOT look for the sentinel
        >>>     print "Encryption was correct."
        >>> else:
        >>>     print "Encryption was not correct."

.. __: https://tools.ietf.org/html/rfc8017
.. __: http://www.rsa.com/rsalabs/node.asp?id=2125.

.. automodule:: Crypto.Cipher.PKCS1_v1_5
    :members:
