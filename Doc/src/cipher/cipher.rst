``Crypto.Cipher`` package
=========================

.. toctree::
    aes.rst
    chacha20.rst
    salsa20.rst
    oaep.rst

Introduction
------------

This package contains algorithms for protecting the confidentiality
of data.

There are three types of encryption algorithms:

1. **Symmetric**: all parties that want to decrypt or encrypt
   the data share the same secret key.
   Symmetric ciphers are typically very fast and can process
   very large amount of data.

2. **Asymmetric**: senders and receivers have different keys.
   Senders use *public* keys (non-secret) to encrypt whereas receivers
   use *private* keys (secret) to decrypt.
   Asymmetric ciphers are typically very slow and can process
   only very small payloads. Example: :doc:`oaep`.

3. **Hybrid**: the two types of ciphers above can be combined
   in a construction that inherits the benefits of both.
   An *asymmetric* cipher is used to protect a short-lived
   and message-specific symmetric key,
   and a *symmetric* cipher (under that key) encrypts
   the actual data.

Symmetric ciphers
-----------------

There are two types of symmetric ciphers:

* **Stream ciphers**: the most natural kind of ciphers;
  any piece of data is converted into an encrypted form
  and its length is preserved
  (example: :doc:`chacha20`, :doc:`salsa20`).

* **Block ciphers**: ciphers that can only operate on a fixed amount
  of data (example: :doc:`aes` can only encrypt or decrypt
  exactly 16 bytes).
  
  Block ciphers are in general useful only in combination with
  :ref:`cipher modes <cipher_modes>`.
  For instance, AES in CTR mode is equivalent to a stream cipher
  and can process messages of any length;
  AES in GCM mode can do that **plus** generate a
  *Message Authentication Code* (MAC).

In either case, the basic API of a cipher is fairly simple:

1. You instantiate a symmetric cipher object by calling the :func:`new`
   function from the relevant module.
   The first parameter is always the *cryptographic key* as a *byte string*;
   its length depends on the particular cipher.
   You can (or sometime must) pass additional cipher- or mode-specific parameters.

2. You call either :func:`encrypt` or :func:`decrypt` methods of the cipher
   object, for each piece of data you want to process.
   You can call the method multiple times, but you cannot mix the two methods.
   Data passed for encryption or decryption (and data returned) is always
   of type *byte string*.

This is an abstract example:

    >>> from Crypto.Cipher import <algo>
    >>>
    >>> key = b'My very secret key'
    >>> cipher = <algo>.new(key, <other options>)
    >>> ciphertext =  cipher.encrypt(b'The secret I want to send.')
    >>> ciphertext += cipher.encrypt(b'The second part of the secret.')

The state machine for a generic symmetric cipher looks like this:

.. figure:: simple_mode.png
    :align: center
    :figwidth: 50%

.. _cipher_modes:

Modes of operation for symmetric block ciphers
----------------------------------------------

Block ciphers are only used together with a *mode of operation*.

When you create a cipher object with the :func:`new` function,
the second argument (after the cryptographic key) is a constant
that defines the specific mode. For instance:

    >>> from Crypto.Cipher import AES
    >>>
    >>> cipher = AES.new(key, AES.MODE_CBC)

Constants are defined at the module level for each cipher algorithm,
and their names start with ``MODE_``
(for instance :const:`Crypto.Cipher.AES.MODE_CBC`).
Not all modes are available for all block ciphers.

MODE_ECB
    Electronic CodeBook. A weak mode of operation whereby
    the cipher is applied in isolation to each of the blocks
    that compose the overall message.

    This mode is **not secure**, in that it exposes correlation
    between blocks.

    :func:`encrypt` and :func:`decrypt` methods only accept data
    with length multiple of the block size.

MODE_CBC
    Ciphertext Block Chaining. A mode of operation where each
    plaintext block is XOR-ed with the last produced ciphertext
    block prior to encryption.

    This mode expects an unpredictable IV (*Initialization Vector*, byte string)
    at creation time. It is passed as parameter ``iv`` to
    :func:`new`, with length equal to the block size.
    If not present, a random IV will be created.

    :func:`encrypt` and :func:`decrypt` methods only accept data
    with length multiple of the block size.

    The cipher object has a read-only attribute :attr:`iv`.

MODE_CFB
    Cipher FeedBack. A mode of operation which turns the block
    cipher into a stream cipher, with the plaintext getting
    XOR-ed with a *keystream* to obtain the ciphertext.
    The *keystream* is the last produced cipertext encrypted
    with the block cipher.

    This mode expects a non-repeatable IV (*Initialization Vector*, byte string)
    at creation time. It is passed as parameter ``iv`` to
    :func:`new`, with length equal to the block size.
    If not present, a random IV will be created.

    The cipher object has a read-only attribute :attr:`iv`.

MODE_OFB
    Output FeedBack. Another mode that leads to a stream cipher.
    The *keystream* is obtained by recursively encrypting the *IV*.

    This mode expects a non-repeatable IV (*Initialization Vector*, byte string)
    at creation time. It is passed as parameter ``iv`` to
    :func:`new`, with length equal to the block size.
    If not present, a random IV will be created.

    The cipher object has a read-only attribute :attr:`iv`.

MODE_CTR
    CounTeR mode. Another mode that leads to a stream cipher.
    The *keystream* is obtained by encrypting a
    *block counter*, the concatenation of a *nonce* (fixed
    during the computation) to a *counter field* (ever increasing).

    The following paramters are expected:

    * ``nonce``: a **mandatory** non-repeatable value (byte string),
      of length between 0 and block length minus 1.

    * ``initial_value``: the initial value for the counter field
      (default if not specified: 0).

    The cipher object has a read-only attribute :attr:`nonce`.

MODE_OPENPGP
    OpenPGP (`RFC4880 <https://tools.ietf.org/html/rfc4880>`_).
    A variant of CFB, with two differences:

    1. The first invokation to the :func:`encrypt` method
       returns the encrypted IV concatenated to the first chunk
       on ciphertext (as opposed to ciphertext only).
       The encrypted IV is as long as the block size plus 2 more bytes.

    2. When the cipher object is intended for decryption,
       the parameter ``iv`` to :func:`new` is the encrypted IV
       (and not the IV, which is the case for encryption).

    Like for CTR, any cipher object has a read-only attribute :attr:`iv`.

Authenticated Encryption
------------------------

...

Historic ciphers
----------------

...
