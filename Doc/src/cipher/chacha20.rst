ChaCha20 and XChaCha20
======================

`ChaCha20`_ is a stream cipher designed by Daniel J. Bernstein.
The secret key is 256 bits long (32 bytes).
The cipher requires a nonce, which **must not** be reused
across encryptions performed with the same key.

There are three variants, defined by the length of the nonce:

.. csv-table::
    :header: Nonce length, Description, Max data, If random nonce and same key
    :widths: 5, 50, 20, 20

    "8 bytes (default)", "The original ChaCha20 designed by Bernstein.", "No limitations", "Max 200 000 messages"
    "12 bytes", "The TLS ChaCha20 as defined in `RFC7539`_.", "256 GB", "Max 13 billions messages"
    "24 bytes", "XChaCha20, still in `draft stage <https://tools.ietf.org/html/draft-arciszewski-xchacha-03>`_.", "256 GB", "No limitations"

.. see probability p=10⁻⁶ in table https://en.wikipedia.org/wiki/Birthday_problem#Probability_table

This is an example of how `ChaCha20`_ (Bernstein's version) can encrypt data::

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
