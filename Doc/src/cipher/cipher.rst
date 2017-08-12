:mod:`Crypto.Cipher` package
============================

Introduction
------------

The :mod:`Crypto.Cipher` package contains algorithms for protecting the confidentiality
of data.

There are three types of encryption algorithms:

1. **Symmetric ciphers**: all parties use the same key, for both
   decrypting and encrypting data.
   Symmetric ciphers are typically very fast and can process
   very large amount of data.

2. **Asymmetric ciphers**: senders and receivers use different keys.
   Senders encrypt with *public* keys (non-secret) whereas receivers
   decrypt with *private* keys (secret).
   Asymmetric ciphers are typically very slow and can process
   only very small payloads. Example: :doc:`oaep`.

3. **Hybrid ciphers**: the two types of ciphers above can be combined
   in a construction that inherits the benefits of both.
   An *asymmetric* cipher is used to protect a short-lived
   symmetric key,
   and a *symmetric* cipher (under that key) encrypts
   the actual message.

Symmetric ciphers
-----------------

There are two types of symmetric ciphers:

* **Stream ciphers**: the most natural kind of ciphers;
  they encrypt any piece of data by preserving its length:
  see :doc:`chacha20`, :doc:`salsa20`.

* **Block ciphers**: ciphers that can only operate on a fixed amount
  of data. The most important block cipher is :doc:`aes`, which has
  a block size of 16 bytes.
  
  A block ciphers is in general useful only in combination with
  a *mode of operation* . There are
  :doc:`classic modes <classic>` like CTR or
  :doc:`authenticated modes <modern>` like GCM.

.. figure:: simple_mode.png
    :align: center
    :figwidth: 50%

    Generic state diagram for a cipher object

In either case, the base API of a cipher is fairly simple:

*   You instantiate a symmetric cipher object by calling the :func:`new`
    function from the relevant cipher module (e.g. :func:`Crypto.Cipher.AES.new`).
    The first parameter is always the *cryptographic key*;
    its length depends on the particular cipher.
    You can (and sometimes must) pass additional cipher- or mode-specific parameters
    to :func:`new` (such as a *nonce* or a *mode of operation*).

*   For encrypting, you call the :func:`encrypt` method of the cipher
    object, once for each piece of plaintext you want to encrypt.
    The method returns the piece of ciphertext.
    You can call :func:`encrypt` multiple times.

*   For decrypting, you call the :func:`decrypt` method of the cipher
    object, once for each piece of ciphertext you want to decrypt.
    The method returns the piece of plaintext.
    You can call :func:`decrypt` multiple times.

.. note::

    The cryptographic key, the plaintext and the ciphertext are
    all encoded as *byte strings*. An error will occur with
    Python 3 strings, Python 2 Unicode strings, or byte arrays.

In all cases (with the exception of the ECB mode), the sender
will deliver to the receiver an 
**initialization vector** (or **nonce**) in addition to
the **ciphertext**.

This is a basic example::

    >>> from Crypto.Cipher import Salsa20
    >>>
    >>> key = b'0123456789012345'
    >>> cipher = Salsa20.new(key)
    >>> ciphertext =  cipher.encrypt(b'The secret I want to send.')
    >>> ciphertext += cipher.encrypt(b'The second part of the secret.')

.. toctree::
    :hidden:

    Classic modes of operation <classic>    
    Modern modes of operation <modern>

Historic ciphers
----------------

A number of ciphers are implemented purely for backward compatibility purposes,
they are deprecated or even fully broken and should not be used in new designs.

* :doc:`des` and :doc:`des3` (block ciphers)
* :doc:`arc2` (block cipher)
* :doc:`arc4` (stream cipher)
* :doc:`blowfish` (block cipher)
* :doc:`cast` (block cipher)
* :doc:`pkcs1_v1_5` (asymmetric cipher)
