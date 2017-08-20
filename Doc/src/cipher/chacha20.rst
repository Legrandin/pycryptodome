ChaCha20
========

`ChaCha20`_ is a stream cipher designed by Daniel J. Bernstein.
The secret key is 256 bits long.

This is an example of how ``ChaCha20`` can encrypt data:

    >>> from Crypto.Cipher import ChaCha20
    >>>
    >>> plaintext = b'Attack at dawn'
    >>> secret = b'*Thirty-two byte (256 bits) key*'
    >>> cipher = ChaCha20.new(key=secret)
    >>> msg = cipher.nonce + cipher.encrypt(plaintext)

And this is how you would decrypt it:

    >>> from Crypto.Cipher import ChaCha20
    >>>
    >>> secret = b'*Thirty-two byte (256 bits) key*'
    >>> msg_nonce = msg[:8]
    >>> ciphertext = msg[8:]
    >>> cipher = ChaCha20.new(key=secret, nonce=msg_nonce)
    >>> plaintext = cipher.decrypt(ciphertext)

.. warning::

    ``ChaCha20`` does not guarantee authenticity of the data you decrypt!
    In other words, an attacker may manipulate the data in transit.
    In order to prevent it, you must couple it with a *Message Authentication
    Code* (such as HMAC).

.. _ChaCha20: http://http://cr.yp.to/chacha.html

.. automodule:: Crypto.Cipher.ChaCha20
    :members:
