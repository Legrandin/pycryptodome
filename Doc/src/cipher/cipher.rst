``Crypto.Cipher`` package
=========================

Introduction
------------

The :mod:`Crypto.Cipher` package contains algorithms for protecting the confidentiality
of data.

There are three types of encryption algorithms:

1. **Symmetric ciphers**: all parties that want to decrypt or encrypt
   the data share the same secret key.
   Symmetric ciphers are typically very fast and can process
   very large amount of data.

2. **Asymmetric ciphers**: senders and receivers have different keys.
   Senders use *public* keys (non-secret) to encrypt whereas receivers
   use *private* keys (secret) to decrypt.
   Asymmetric ciphers are typically very slow and can process
   only very small payloads. Example: :doc:`oaep`.

3. **Hybrid ciphers**: the two types of ciphers above can be combined
   in a construction that inherits the benefits of both.
   An *asymmetric* cipher is used to protect a short-lived
   and message-specific symmetric key,
   and a *symmetric* cipher (under that key) encrypts
   the actual data.

Symmetric ciphers
-----------------

There are two types of symmetric ciphers:

* **Stream ciphers**: the most natural kind of ciphers;
  they encrypt any piece of data by preserving its length
  (example: :doc:`chacha20`, :doc:`salsa20`).

* **Block ciphers**: ciphers that can only operate on a fixed amount
  of data. The most important block cipher is :doc:`aes`, which has
  a block size of 16 bytes.
  
  Block ciphers are in general useful only in combination with
  *modes of operation* (:ref:`classic modes <classic_cipher_modes>` like CTR or
  :ref:`authenticated modes <aead>` like GCM).

In either case, the base API of a cipher is fairly simple:

*   You instantiate a symmetric cipher object by calling the :func:`new`
    function from the relevant cipher module (e.g. :func:`Crypto.Cipher.AES.new`).
    The first parameter is always the *cryptographic key*;
    its length depends on the particular cipher.
    You can (and sometimes must) pass additional cipher- or mode-specific parameters
    to :func:`new` (such as *nonces*).

*   For encrypting, you call the :func:`encrypt` method of the cipher
    object for each piece of plaintext you want to encrypt.
    The method returns the piece of ciphertext.
    You can call :func:`encrypt` multiple times.

*   For decrypting, you call the :func:`decrypt` method of the cipher
    object for each piece of ciphertext you want to decrypt.
    The method returns the piece of plaintext.
    You can call :func:`decrypt` multiple times.

.. note::

    The cryptographic key, the plaintext and the ciphertext are
    all encoded as *byte strings*. An error will occur with
    Python 3 strings, Python 2 Unicode strings, or byte arrays.

In all cases (with the exception of the ECB mode), the sender
will deliver to the receiver the **ciphertext** and a **nonce** /
**Initialization Vector**.

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

.. _classic_cipher_modes:

Classic modes of operation for symmetric block ciphers
------------------------------------------------------

Block ciphers are only used together with a *mode of operation*.

When you create a cipher object with the :func:`new` function,
the second argument (after the cryptographic key) is a constant
that sets the desired mode of operation. For instance:

    >>> from Crypto.Cipher import AES
    >>>
    >>> cipher = AES.new(key, AES.MODE_CBC)

Constants are defined at the module level for each cipher algorithm,
and their names start with ``MODE_``
(for instance :const:`Crypto.Cipher.AES.MODE_CBC`).

This is the list of all classic modes (more modern modes are
described in the :ref:`next section <aead>`).
Mind the not all modes are available for all block ciphers.

MODE_ECB
    Electronic CodeBook. A weak mode of operation whereby
    the cipher is applied in isolation to each of the blocks
    that compose the overall message.

    **This mode should not be used** because it is not
    `semantically secure <https://en.wikipedia.org/wiki/Semantic_security>`_
    and it exposes correlation between blocks.

    :func:`encrypt` and :func:`decrypt` methods only accept data
    with length multiple of the block size.

MODE_CBC
    Ciphertext Block Chaining, defined in
    `NIST SP 800-38A, section 6.2 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
    It is a mode of operation where each
    plaintext block is XOR-ed with the last produced ciphertext
    block prior to encryption.

    The :func:`new` function expects the following extra parameters:

    * ``iv`` (*byte string*): an unpredictable *Initialization Vector*
      of length equal to the block size
      (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
      If not present, a random IV will be created.

    :func:`encrypt` and :func:`decrypt` methods only accept data
    with length multiple of the block size. You might need to
    use `Crypto.Util.Padding`.

    The cipher object has a read-only attribute :attr:`iv`.

MODE_CFB
    Cipher FeedBack, defined in
    `NIST SP 800-38A, section 6.3 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
    It is a mode of operation which turns the block
    cipher into a stream cipher, with the plaintext getting
    XOR-ed with a *keystream* to obtain the ciphertext.
    The *keystream* is the last produced cipertext encrypted
    with the block cipher.

    The :func:`new` function expects the following extra parameters:

    * ``iv`` (*byte string*): an non-repeatable *Initialization Vector*
      of length equal to the block size
      (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
      If not present, a random IV will be created.

    * ``segment_size`` (*integer*): the number of bits the plaintext and the
      ciphertext are segmented in (default if not specified: 8).

    The cipher object has a read-only attribute :attr:`iv`.

MODE_OFB
    Output FeedBack, defined in 
    `NIST SP 800-38A, section 6.4 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
    It is another mode that leads to a stream cipher.
    The *keystream* is obtained by recursively encrypting the *IV*.

    The :func:`new` function expects the following extra parameters:

    * ``iv`` (*byte string*): an non-repeatable *Initialization Vector*
      of length equal to the block size
      (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
      If not present, a random IV will be created.

    The cipher object has a read-only attribute :attr:`iv`.

MODE_CTR
    CounTeR mode, defined in
    `NIST SP 800-38A, section 6.5 and Appendix B <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
    It is another mode that leads to a stream cipher.
    The *keystream* is obtained by encrypting a
    *block counter*, which is the concatenation of a *nonce* (fixed
    during the computation) to a *counter field* (ever increasing).

    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a **mandatory** non-repeatable value,
      of length between 0 and block length minus 1.

    * ``initial_value`` (*integer*): the initial value for the counter field
      (default if not specified: 0).

    The cipher object has a read-only attribute :attr:`nonce`.

MODE_OPENPGP
    OpenPGP (defined in `RFC4880 <https://tools.ietf.org/html/rfc4880>`_).
    A variant of CFB, with two differences:

    1. The first invokation to the :func:`encrypt` method
       returns the encrypted IV concatenated to the first chunk
       on ciphertext (as opposed to the ciphertext only).
       The encrypted IV is as long as the block size plus 2 more bytes.

    2. When the cipher object is intended for decryption,
       the parameter ``iv`` to :func:`new` is the encrypted IV
       (and not the IV, which is still the case for encryption).

    Like for CTR, any cipher object has a read-only attribute :attr:`iv`.

.. _aead:

Modern modes of operation for symmetric block ciphers
-----------------------------------------------------

Classic modes of operation such as CBC only provide guarantees over
the *confidentiality* of the message but not over its *integrity*.
In other words, they don't allow the receiver to establish if the 
ciphertext was modified in transit or if it really originates
from a certain source.

For that reason, classic modes of operation have been often paired with
a MAC primitive (such as :mod:`Crypto.Hash.HMAC`), but the
combination is not always straightforward, efficient or secure.

Recently, new modes of operations (AEAD, for `Authenticated Encryption
with Associated Data <https://en.wikipedia.org/wiki/Authenticated_encryption>`_)
have been designed to combine *encryption* and *authentication* into a single,
efficient primitive. Optionally, some part of the message can also be left in the
clear (non-confidential *associated data*, such as headers),
while the whole message remains fully authenticated.

In addition to the **ciphertext** and a **nonce** / **IV**, AEAD modes
require the additional delivery of a **MAC tag**.

The API of an AEAD cipher object is richer, as it include methods normally
found in a MAC object:

* The :func:`update` method consumes data (if any) which must be
  authenticated but not encrypted. Note that any data passed
  to :func:`encrypt` or :func:`decrypt` is automatically authenticated.

* The :func:`digest` method creates an authentication tag (MAC tag) at the end
  of the encryption process (the variant :func:`hexdigest` exists to output
  the tag as a hexadecimal string).

* The :func:`verify` method checks if the provided authentication tag (MAC tag)
  is valid at the end of the decryption process (the variant :func:`hexverify`
  exists in case the MAC tag is a hexadecimal string).

* The :func:`encrypt_and_digest` method encrypts and creates a MAC tag
  in one go.

* The :func:`decrypt_and_verify` method decrypts and checks a MAC tag
  in one go.

The state machine for a cipher object becomes:

.. figure:: aead.png
    :align: center
    :figwidth: 80%

MODE_CCM
    Counter with CBC-MAC, defined in
    `RFC3610 <https://tools.ietf.org/html/rfc3610>`_ or
    `NIST SP 800-38C <http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf>`_.
    It only works with ciphers having block size 128 bits (like AES).
    
    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a non-repeatable value,
      of length between 7 and 13 bytes.
      The longer the nonce, the smaller the allowed message size
      (with a nonce of 13 bytes, the message cannot exceed 64KBi).
      If not present, a random 11 bytes long *nonce* will be created
      (the maximum message size is 8GBi).

    * ``mac_len`` (*integer*): the desired length of the 
      MAC tag (default if not present: 16 bytes).

    * ``msg_len`` (*integer*): pre-declaration of the length of the
      message to encipher. If not specified, :func:`encrypt` and :func:`decrypt`
      can only be called once.

    * ``assoc_len`` (*integer*): pre-declaration of the length of the
      associated data. If not specified, some extra buffering will take place
      internally.
      
    The cipher object has a read-only attribute :attr:`nonce`.

MODE_EAX
    An AEAD mode designed for NIST by
    `Bellare, Rogaway, and Wagner in 2003 <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf>`_.

    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
      If not present, a random *nonce* of the recommended length (16 bytes)
      will be created.
    
    * ``mac_len`` (*integer*): the desired length of the 
      MAC tag (default if not present: 16 bytes).

    The cipher object has a read-only attribute :attr:`nonce`.

MODE_GCM

    Galois/Counter Mode, defined in
    `NIST SP 800-38D <http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf>`_.
    It only works in combination with a 128 bits cipher like AES.

    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
      If not present, a random *nonce* of the recommended length (16 bytes)
      will be created.
    
    * ``mac_len`` (*integer*): the desired length of the 
      MAC tag (default if not present: 16 bytes).

    The cipher object has a read-only attribute :attr:`nonce`.

MODE_SIV
    Synthetic Initialization Vector (SIV), defined in
    `RFC5297 <https://tools.ietf.org/html/rfc5297>`_.
    It only works with ciphers having block size 128 bits (like AES).

    Although less efficient, SIV is unlike all other AEAD modes
    in that it is *nonce misuse-resistant*: the accidental reuse
    of a nonce does not have catastrophic effects as for CCM, GCM, etc.
    Instead, it will simply degrade into a **deterministic** cipher
    and therefore allow an attacker to know whether two
    ciphertexts contain the same message or not.

    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
      If not present, the encryption will be **deterministic**.

    The length of the key passed to :func:`new` must be twice
    as required by the underlying block cipher (e.g. 32 bytes for AES-128).
    
    Each call to the method :func:`update` consumes an individual piece
    of associated data. That is, the sequence::

        >>> siv_cipher.update(b"builtin")
        >>> siv_cipher.update(b"securely")

    is not equivalent to::

        >>> siv_cipher.update(b"built")
        >>> siv_cipher.update(b"insecurely")

    The methods :func:`encrypt` and :func:`decrypt` can only be called
    **once**.

    The cipher object has a read-only attribute :attr:`nonce`.

MODE_OCB
    Offset CodeBook mode, a cipher designed by Rogaway and specified in
    `RFC7253 <http://www.rfc-editor.org/info/rfc7253>`_ (more specifically,
    this module implements the last variant, OCB3).
    It only works in combination with a 128 bits cipher like AES.

    OCB is patented in USA but
    `free licenses <http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm>`_
    exist for software implementations meant for non-military purposes
    and open source.

    The :func:`new` function expects the following extra parameters:

    * ``nonce`` (*byte string*): a non-repeatable value, of length between
      1 and 15 bytes..
      If not present, a random *nonce* of the recommended length (15 bytes)
      will be created.
    
    * ``mac_len`` (*integer*): the desired length of the 
      MAC tag (default if not present: 16 bytes).

    The cipher object has a read-only attribute :attr:`nonce`.

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

