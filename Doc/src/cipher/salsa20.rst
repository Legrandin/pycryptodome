Salsa20
========

`Salsa20`_ is a stream cipher designed by Daniel J. Bernstein.
The secret key is by preference 256 bits long, but it can also
work with 128 bit keys.

This is an example of how ``Salsa20`` can encrypt data:

    >>> from Crypto.Cipher import Salsa20
    >>>
    >>> plaintext = b'Attack at dawn'
    >>> secret = b'*Thirty-two byte (256 bits) key*'
    >>> cipher = Salsa20.new(key=secret)
    >>> msg = cipher.nonce + cipher.encrypt(plaintext)

And this is how you would decrypt it:

    >>> from Crypto.Cipher import Salsa20
    >>>
    >>> secret = b'*Thirty-two byte (256 bits) key*'
    >>> msg_nonce = msg[:8]
    >>> ciphertext = msg[8:]
    >>> cipher = Salsa20.new(key=secret, nonce=msg_nonce)
    >>> plaintext = cipher.decrypt(ciphertext)

.. warning::

    ``Salsa20`` does not guarantee authenticity of the data you decrypt!
    In other words, an attacker may manipulate the data in transit.
    In order to prevent that, you must also use a *Message Authentication
    Code* (such as :doc:`HMAC <../hash/hmac>`) to authenticate the ciphertext
    (*encrypt-then-mac*).

.. _Salsa20: http://cr.yp.to/snuffle/spec.pdf

.. automodule:: Crypto.Cipher.Salsa20
    :members:
