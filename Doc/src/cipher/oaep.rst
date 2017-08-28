PKCS#1 OAEP (RSA)
=================

PKCS#1 OAEP is an asymmetric cipher based on RSA and the OAEP padding.
It is described in `RFC8017 <https://tools.ietf.org/html/rfc8017>`_
where it is called ``RSAES-OAEP``.

It can only encrypt messages slightly shorter than the RSA modulus (a few
hundred bytes).

The following example shows how you encrypt data by means of
the recipient's **public key** (here assumed to be
available locally in a file called ``public.pem``)::

        >>> from Crypto.Cipher import PKCS1_OAEP
        >>> from Crypto.PublicKey import RSA
        >>>
        >>> message = b'You can attack now!'
        >>> key = RSA.importKey(open('public.pem').read())
        >>> cipher = PKCS1_OAEP.new(key)
        >>> ciphertext = cipher.encrypt(message)

The recipient uses its own **private key** to decrypt the message.
We assume the key is stored in a file called ``private.pem``::

        >>> key = RSA.importKey(open('private.pem').read())
        >>> cipher = PKCS1_OAEP.new(key)
        >>> message = cipher.decrypt(ciphertext)

.. warning::
   PKCS#1 OAEP does not guarantee authenticity of the message you decrypt.
   Since the public key is not secret, everybody could have created
   the encrypted message.
   Asymmetric encryption is typically paired with a digital signature.

.. note::
   This module does not generate nor load RSA keys.
   Refer to the :mod:`Crypto.PublicKey.RSA` module.

.. automodule:: Crypto.Cipher.PKCS1_OAEP
    :members:
