AES
===

AES `(Advanced Encryption Standard)`__ is a symmetric block cipher standardized
by NIST_ . It has a fixed data block size of 16 bytes.
Its keys can be 128, 192, or 256 bits long.

AES is very fast and secure, and it is the de facto standard for symmetric
encryption.

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import AES
    >>>
    >>> key = b'Sixteen byte key'
    >>> cipher = AES.new(key, AES.MODE_EAX)
    >>>
    >>> nonce = cipher.nonce
    >>> ciphertext, tag = cipher.encrypt_and_digest(data)

The recipient can obtain the original message using the same key
and the incoming triple ``(nonce, ciphertext, tag)``::

    >>> from Crypto.Cipher import AES
    >>>
    >>> key = b'Sixteen byte key'
    >>> cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> try:
    >>>     cipher.verify(tag)
    >>>     print("The message is authentic:", plaintext)
    >>> except ValueError:
    >>>     print("Key incorrect or message corrupted")

.. __: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _NIST: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

.. automodule:: Crypto.Cipher.AES
    :members:
