Classic modes of operation for symmetric block ciphers
======================================================

Block ciphers are often only used together with a *mode of operation*.

When you create a block cipher object with the :func:`new` function,
the second argument (after the cryptographic key) is a constant
that sets the desired mode of operation. For instance:

    >>> from Crypto.Cipher import AES
    >>>
    >>> cipher = AES.new(key, AES.MODE_CBC)

Constants are defined at the module level for each cipher algorithm,
and their names start with ``MODE_``
(for instance :const:`Crypto.Cipher.AES.MODE_CBC`).

This is the list of all classic modes (more modern modes are
described in :doc:`another section <modern>`).
Mind the not all modes are available for all block ciphers.

ECB mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_ECB``.

`Electronic CodeBook <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29>`_.
A weak mode of operation whereby
the cipher is applied in isolation to each of the blocks
that compose the overall message.

**This mode should not be used** because it is not
`semantically secure <https://en.wikipedia.org/wiki/Semantic_security>`_
and it exposes correlation between blocks.

:func:`encrypt` and :func:`decrypt` methods only accept data
having length multiple of the block size.

CBC mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_CBC``.

`Ciphertext Block Chaining <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29>`_,
defined in `NIST SP 800-38A, section 6.2 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
It is a mode of operation where each plaintext block
is XOR-ed with the last produced ciphertext block prior to encryption.

The :func:`new` function expects the following extra parameters:

* ``iv`` (*byte string*): an unpredictable *Initialization Vector*
    of length equal to the block size
    (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
    If not present, a random IV will be created.

:func:`encrypt` and :func:`decrypt` methods only accept data
with length multiple of the block size. You might need to
use :mod:`Crypto.Util.Padding`.

The cipher object has a read-only attribute :attr:`iv`.

CFB mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_CFB``.

`Cipher FeedBack <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29>`_,
defined in `NIST SP 800-38A, section 6.3 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
It is a mode of operation which turns the block cipher into a stream cipher,
with the plaintext getting XOR-ed with a *keystream* to obtain the ciphertext.
The *keystream* is the last produced cipertext encrypted with the block cipher.

The :func:`new` function expects the following extra parameters:

* ``iv`` (*byte string*): an non-repeatable *Initialization Vector*
    of length equal to the block size
    (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
    If not present, a random IV will be created.

* ``segment_size`` (*integer*): the number of bits the plaintext and the
    ciphertext are segmented in (default if not specified: 8).

    The cipher object has a read-only attribute :attr:`iv`.

OFB mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_OFB``.


`Output FeedBack <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29>`_,
defined in `NIST SP 800-38A, section 6.4 <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
It is another mode that leads to a stream cipher.
The *keystream* is obtained by recursively encrypting the *IV*.

The :func:`new` function expects the following extra parameters:

* ``iv`` (*byte string*): an non-repeatable *Initialization Vector*
    of length equal to the block size
    (e.g. 16 bytes for :mod:`Crypto.Cipher.AES`).
    If not present, a random IV will be created.

The cipher object has a read-only attribute :attr:`iv`.

CTR mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_CTR``.

`CounTeR mode <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29>`_,
defined in `NIST SP 800-38A, section 6.5 and Appendix B <http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf>`_.
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

OpenPGP mode
------------
Constant: ``Crypto.Cipher.<cipher>.MODE_OPENPGP``.

OpenPGP (defined in `RFC4880 <https://tools.ietf.org/html/rfc4880>`_).
A variant of CFB, with two differences:

1.  The first invokation to the :func:`encrypt` method
    returns the encrypted IV concatenated to the first chunk
    on ciphertext (as opposed to the ciphertext only).
    The encrypted IV is as long as the block size plus 2 more bytes.

2.  When the cipher object is intended for decryption,
    the parameter ``iv`` to :func:`new` is the encrypted IV
    (and not the IV, which is still the case for encryption).

Like for CTR, any cipher object has a read-only attribute :attr:`iv`.

