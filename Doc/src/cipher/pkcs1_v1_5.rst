PKCS#1 v1.5 encryption (RSA)
============================

.. warning::
    Use :doc:`oaep` instead. This module is provided only for legacy purposes.

See RFC8017__ or the `original RSA Labs specification`__ .

This scheme is more properly called ``RSAES-PKCS1-v1_5``.

As an example, a sender may encrypt a secret AES key in this way::

        >>> from Crypto.Cipher import PKCS1_v1_5
        >>> from Crypto.PublicKey import RSA
        >>> from Crypto.Random import get_random_bytes
        >>>
        >>> aes_key = get_random_bytes(16)
        >>>
        >>> rsa_key = RSA.importKey(open('pubkey.der').read())
        >>> cipher = PKCS1_v1_5.new(rsa_key)
        >>> ciphertext = cipher.encrypt(aes_key)

At the receiver side, decryption can be done using the private part of
the RSA key::

        >>> from Crypto.Random import get_random_bytes
        >>>
        >>> rsa_key = RSA.importKey(open('privkey.der').read())
        >>>
        >>> sentinel = get_random_bytes(16)
        >>>
        >>> cipher = PKCS1_v1_5.new(rsa_key)
        >>> aes_key = cipher.decrypt(ciphertext, sentinel, expected_pt_len=16)
        >>>
        >>> # The AES key is the random sentinel in case of error

.. __: https://tools.ietf.org/html/rfc8017
.. __: http://www.rsa.com/rsalabs/node.asp?id=2125.

.. automodule:: Crypto.Cipher.PKCS1_v1_5
    :members:
