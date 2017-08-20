:mod:`Crypto.Util` package
==========================

Useful modules that don't belong in any other package.

.. toctree::
    :hidden:
    
    asn1

:mod:`Crypto.Util.Padding` module
---------------------------------

This module provides minimal support for adding and removing standard padding
from data.

.. automodule:: Crypto.Util.Padding
    :members:

:mod:`Crypto.Util.RFC1751` module
---------------------------------

.. automodule:: Crypto.Util.RFC1751
    :members:

:mod:`Crypto.Util.strxor` module
--------------------------------

Fast XOR for byte strings.

.. automodule:: Crypto.Util.strxor
    :members:

:mod:`Crypto.Util.Counter` module
---------------------------------

Fast counter functions for CTR cipher modes.

CTR is a chaining mode for symmetric block encryption or decryption.
Messages are divideded into blocks, and the cipher operation takes
place on each block using the secret key and a unique *counter block*.

The most straightforward way to fulfil the uniqueness property is
to start with an initial, random *counter block* value, and increment it as
the next block is processed.

The block ciphers from :mod:`Crypto.Cipher` (when configured in *MODE_CTR* mode)
invoke a callable object (the *counter* parameter) to get the next *counter block*.
Unfortunately, the Python calling protocol leads to major performance degradations.

The counter functions instantiated by this module will be invoked directly
by the ciphers in :mod:`Crypto.Cipher`. The fact that the Python layer is bypassed
lead to more efficient (and faster) execution of CTR cipher modes.

An example of usage is the following::

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Util import Counter
    >>> from Crypto import Random
    >>>
    >>> nonce = Random.get_random_bytes(8)
    >>> ctr = Counter.new(64, nonce)
    >>> key = b'AES-128 symm key'
    >>> plaintext = b'X'*1000000
    >>> cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    >>> ciphertext = cipher.encrypt(plaintext)

.. automodule:: Crypto.Util.Counter
    :members:

:mod:`Crypto.Util.number` module
--------------------------------

.. automodule:: Crypto.Util.number
    :members:
