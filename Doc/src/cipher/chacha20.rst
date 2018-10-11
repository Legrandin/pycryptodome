ChaCha20
========

`ChaCha20`_ is a stream cipher designed by Daniel J. Bernstein.
The secret key is 256 bits long.

The algorithm requires a nonce of either 8 bytes (original definition of ChaCha20)
or 12 bytes (newer definition published in `RFC7539`_).
A nonce value must never be reused across encryptions performed with the same key.

Using a 12 bytes nonce limits the amount of data that can be encrypted to 256BG only.
No practical limitation exists when the nonce is 8 bytes long.

You create a new cipher by calling :meth:`Crypto.Cipher.ChaCha20.new`.

This is an example of how `ChaCha20`_ can encrypt data::

    >>> import json
    >>> from base64 import b64encode
    >>> from Crypto.Cipher import ChaCha20
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> plaintext = b'Attack at dawn'
    >>> key = get_random_bytes(32)
    >>> cipher = ChaCha20.new(key=key)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>>
    >>> nonce = b64encode(cipher.nonce).decode('utf-8')
    >>> ct = b64encode(ciphertext).decode('utf-8')
    >>> result = json.dumps({'nonce':nonce, 'ciphertext':ct})
    >>> print(result)
    {"nonce": "IZScZh28fDo=", "ciphertext": "ZatgU1f30WDHriaN8ts="}

And this is how you decrypt it::

    >>> import json
    >>> from base64 import b64decode
    >>> from Crypto.Cipher import ChaCha20
    >>>
    >>> # We assume that the key was somehow securely shared
    >>> try:
    >>>     b64 = json.loads(json_input)
    >>>     nonce = b64decode(b64['nonce'])
    >>>     ciphertext = b64decode(b64['ciphertext'])
    >>>     cipher = ChaCha20.new(key=key, nonce=nonce)
    >>>     plaintext = cipher.decrypt(ciphertext)
    >>>     print("The message was " + plaintext)
    >>> except ValueError, KeyError:
    >>>     print("Incorrect decryption")

The examples above implicitly generate a 64 bit (8 byte) nonce.

In order to have a `RFC7539`_-compliant ChaCha20 cipher,
you need to explicitly generate and pass a 96 bit (12 byte) ``nonce`` parameter to ``new()``::

    nonce_rfc7539 = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce_rfc7539)

.. warning::

    ``ChaCha20`` does not guarantee authenticity of the data you decrypt!
    In other words, an attacker may manipulate the data in transit.
    In order to prevent that, you must also use a *Message Authentication
    Code* (such as :doc:`HMAC <../hash/hmac>`) to authenticate the ciphertext
    (*encrypt-then-mac*). Alternatively, you can use :doc:`ChaCha20_Poly1305 <chacha20_poly1305>`.

.. _ChaCha20: http://http://cr.yp.to/chacha.html
.. _RFC7539: https://tools.ietf.org/html/rfc7539

.. automodule:: Crypto.Cipher.ChaCha20
    :members:
