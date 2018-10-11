ChaCha20-Poly1305
=================

ChaCha20-Poly1305 is an authenticated cipher with associated data (AEAD) defined in `RFC7539`_.
Its API and finite state machine are the same as for the :doc:`modern modes of operation of block ciphers <modern>`.

The secret key is 256 bits (32 bytes) long.

The algorithm requires a nonce of either 8 bytes or 12 bytes.
A nonce value must never be reused across encryptions performed with the same key.

An ChaCha20-Poly1305 cipher can only encrypt up to 256GB (no matter how long the nonce is).

You create a new cipher by calling :meth:`Crypto.Cipher.ChaCha20_Poly1305.new`.

This is an example of how `ChaCha20-Poly1305`_ can encrypt and authenticate data::

    >>> import json
    >>> from base64 import b64encode
    >>> from Crypto.Cipher import ChaCha20_Poly1305
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> header = b"header"
    >>> plaintext = b'Attack at dawn'
    >>> key = get_random_bytes(32)
    >>> cipher = ChaCha20_Poly1305.new(key=key)
    >>> cipher.update(header)
    >>> ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    >>>
    >>> jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    >>> jv = [ b64encode(x).decode('utf-8') for x in cipher.nonce, header, ciphertext, tag ]
    >>> result = json.dumps(dict(zip(jk, jv)))
    >>> print(result)
    {"nonce": "4EE/9uqhoZ3mQXmm", "header": "aGVhZGVy", "ciphertext": "Wmmo4Vzn+eS3tUPv2a8=", "tag": "/FgVbM8qhzssPRY80T0iVA=="}

In the example above, a 96 bit (12 byte) nonce is automatically created.
It can be accessed as the ``nonce`` member in the ``cipher`` object.

This is how you decrypt the data and check its authenticity::

    >>> import json
    >>> from base64 import b64decode
    >>> from Crypto.Cipher import ChaCha20_Poly1305
    >>>
    >>> # We assume that the key was securely shared beforehand
    >>> try:
    >>>     b64 = json.loads(json_input)
    >>>     jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    >>>     jv = {k:b64decode(b64[k]) for k in jk}
    >>>
    >>>     cipher = ChaCha20_Poly1305.new(key=key, nonce=jv['nonce'])
    >>>     cipher.update(jv['header'])
    >>>     plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    >>>     print("The message was: " + plaintext)
    >>> except ValueError, KeyError:
    >>>     print("Incorrect decryption")

.. _RFC7539: https://tools.ietf.org/html/rfc7539

.. automodule:: Crypto.Cipher.ChaCha20_Poly1305
    :members:
