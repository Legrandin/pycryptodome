ChaCha20-Poly1305 and XChaCha20-Poly1305
========================================

ChaCha20-Poly1305 is an authenticated cipher with associated data (AEAD).
It works with a 32 byte secret key and a nonce
which **must never** be reused across encryptions performed under the same key.
The cipher produces a 16 byte tag that the receiver must use to validate the message.

There are three variants of the algorithm, defined by the length of the nonce:

.. csv-table::
    :header: Nonce length, Description, Max plaintext, If random nonce and same key
    :widths: 5, 50, 20, 20

    "8 bytes", "The ChaCha20-Poly1305 of `RFC8439`_, with the nonce prefixed by 4 zero bytes (see Section 2.6 of `RFC8439`_).", "256 GB", "Max 200 000 messages"
    "12 bytes (default)", "Version used in TLS and specified in `RFC8439`_.", "256 GB", "Max 13 billion messages"
    "24 bytes", "XChaCha20-Poly1305, specified in the expired draft `draft-irtf-cfrg-xchacha-03`_ (it never became an RFC).", "256 GB", "No limitations"

.. see probability p=10⁻⁹ in table https://en.wikipedia.org/wiki/Birthday_problem#Probability_table

All variants follow `RFC8439`_. With an 8-byte nonce, the cipher is **not** the original
ChaCha20-Poly1305 (defined in draft-agl-tls-chacha20poly1305, and implemented for instance as
``crypto_aead_chacha20poly1305`` in libsodium), which computes a different tag:
it is compatible with the RFC version (``crypto_aead_chacha20poly1305_ietf`` in libsodium)
with the nonce prefixed by 4 zero bytes.

The API of the cipher and its finite state machine are the same as for the :doc:`modern modes of operation of block ciphers <modern>`.

You create a new cipher by calling :meth:`Crypto.Cipher.ChaCha20_Poly1305.new`.

This is an example of how ChaCha20-Poly1305 (TLS version) can encrypt and authenticate data::

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
    >>> jv = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
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
    ...     b64 = json.loads(json_input)
    ...     jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    ...     jv = {k:b64decode(b64[k]) for k in jk}
    >>>
    ...     cipher = ChaCha20_Poly1305.new(key=key, nonce=jv['nonce'])
    ...     cipher.update(jv['header'])
    ...     plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    ...     print("The message was: " + plaintext.decode())
    ... except (ValueError, KeyError):
    ...     print("Incorrect decryption")

.. _RFC8439: https://datatracker.ietf.org/doc/html/rfc8439
.. _draft-irtf-cfrg-xchacha-03: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

.. automodule:: Crypto.Cipher.ChaCha20_Poly1305
    :members:
