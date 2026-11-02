PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives, for Python 3.9 and newer.
It needs no system libraries: install it with ``pip install pycryptodome``.

What do you want to do?
-----------------------

.. include:: src/guides/tasks.rst.inc

For instance, this is how to encrypt and authenticate a message
with AES in GCM mode, and then decrypt it
(see :doc:`src/guides/symmetric` for the details):

.. code-block:: python

    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(b"Attack at dawn")

    # The receiver needs the key, the nonce, the ciphertext and the tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

Where to go next
----------------

* :doc:`src/guides/index`, for the common tasks, step by step.
* :doc:`src/api`, for all the algorithms and their parameters, grouped by package.
* :doc:`src/installation`, for the details of the installation.
* :doc:`src/faq`, for the most frequent questions.

.. toctree::
   :hidden:
   :caption: Getting started

   Home <self>
   Introduction <src/introduction>
   src/features
   src/installation

.. toctree::
   :hidden:
   :caption: Guides

   Overview <src/guides/index>
   src/guides/symmetric
   src/guides/passwords
   src/guides/public_key_encryption
   src/guides/signatures
   src/guides/hashing
   src/guides/keys

.. toctree::
   :hidden:
   :caption: Reference

   src/api
   src/exceptions

.. toctree::
   :hidden:
   :caption: Project

   src/faq
   src/contribute_support
   src/changelog
   src/license
