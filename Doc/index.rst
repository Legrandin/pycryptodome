PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives, for Python 3.9 and newer.
It needs no system libraries: install it with ``pip install pycryptodome``.

For instance, this is how to encrypt and authenticate a message
with AES in GCM mode, and then decrypt it:

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(b"Attack at dawn")

    # The receiver needs the key, the nonce, the ciphertext and the tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

Where to go next:

* :doc:`src/installation`, for the details of the installation.
* :doc:`src/api`, for all the algorithms, grouped by package.
* :doc:`src/examples`, for complete examples of common tasks.
* :doc:`src/faq`, for the most frequent questions.

.. toctree::
   :hidden:
   :caption: Contents

   src/introduction
   src/features
   src/installation
   src/api
   src/exceptions
   src/examples
   src/faq
   src/contribute_support
   src/changelog
   src/license
