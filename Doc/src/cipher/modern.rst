Modern modes of operation for symmetric block ciphers
=====================================================

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
    
    Generic state diagram for a AEAD cipher mode

CCM mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_CCM``.

`Counter with CBC-MAC <https://en.wikipedia.org/wiki/CCM_mode>`_, defined in
`RFC3610 <https://tools.ietf.org/html/rfc3610>`_ or
`NIST SP 800-38C <http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf>`_.
It only works with ciphers having block size 128 bits (like AES).
    
The :func:`new` function expects the following extra parameters:

*   ``nonce`` (*byte string*): a non-repeatable value,
    of length between 7 and 13 bytes.
    The longer the nonce, the smaller the allowed message size
    (with a nonce of 13 bytes, the message cannot exceed 64KBi).
    If not present, a random 11 bytes long *nonce* will be created
    (the maximum message size is 8GBi).

*   ``mac_len`` (*integer*): the desired length of the 
    MAC tag (default if not present: 16 bytes).

*   ``msg_len`` (*integer*): pre-declaration of the length of the
    message to encipher. If not specified, :func:`encrypt` and :func:`decrypt`
    can only be called once.

*   ``assoc_len`` (*integer*): pre-declaration of the length of the
    associated data. If not specified, some extra buffering will take place
    internally.
      
The cipher object has a read-only attribute :attr:`nonce`.

EAX mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_EAX``.

An AEAD mode designed for NIST by
`Bellare, Rogaway, and Wagner in 2003 <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf>`_.

The :func:`new` function expects the following extra parameters:

*   ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
    If not present, a random *nonce* of the recommended length (16 bytes)
    will be created.
    
*   ``mac_len`` (*integer*): the desired length of the 
    MAC tag (default if not present: 16 bytes).

The cipher object has a read-only attribute :attr:`nonce`.

GCM mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_GCM``.

`Galois/Counter Mode <https://en.wikipedia.org/wiki/Galois/Counter_Mode>`_,
defined in `NIST SP 800-38D <http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf>`_.
It only works in combination with a 128 bits cipher like AES.

The :func:`new` function expects the following extra parameters:

*   ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
    If not present, a random *nonce* of the recommended length (16 bytes)
    will be created.
    
*   ``mac_len`` (*integer*): the desired length of the 
    MAC tag (default if not present: 16 bytes).

The cipher object has a read-only attribute :attr:`nonce`.

SIV mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_SIV``.

Synthetic Initialization Vector (SIV), defined in `RFC5297 <https://tools.ietf.org/html/rfc5297>`_.
It only works with ciphers having block size 128 bits (like AES).

Although less efficient, SIV is unlike all other AEAD modes
in that it is *nonce misuse-resistant*: the accidental reuse
of a nonce does not have catastrophic effects as for CCM, GCM, etc.
Instead, it will simply degrade into a **deterministic** cipher
and therefore allow an attacker to know whether two
ciphertexts contain the same message or not.

The :func:`new` function expects the following extra parameters:

*   ``nonce`` (*byte string*): a non-repeatable value, of arbitrary length.
    If not present, the encryption will be **deterministic**.

The length of the key passed to :func:`new` must be twice
as required by the underlying block cipher (e.g. 32 bytes for AES-128).
    
Each call to the method :func:`update` consumes an individual piece
of associated data. That is, the sequence::

    >>> siv_cipher.update(b"builtin")
    >>> siv_cipher.update(b"securely")

is **not** equivalent to::

    >>> siv_cipher.update(b"built")
    >>> siv_cipher.update(b"insecurely")

The methods :func:`encrypt` and :func:`decrypt` can only be called **once**.

The cipher object has a read-only attribute :attr:`nonce`.

OCB mode
--------
Constant: ``Crypto.Cipher.<cipher>.MODE_OCB``.

`Offset CodeBook mode <https://en.wikipedia.org/wiki/OCB_mode>`_,
a cipher designed by Rogaway and specified in `RFC7253 <http://www.rfc-editor.org/info/rfc7253>`_
(more specifically, this module implements the last variant, OCB3).
It only works in combination with a 128 bits cipher like AES.

OCB is patented in USA but `free licenses <http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm>`_
exist for software implementations meant for non-military purposes
and open source.

The :func:`new` function expects the following extra parameters:

*   ``nonce`` (*byte string*): a non-repeatable value, of length between
    1 and 15 bytes..
    If not present, a random *nonce* of the recommended length (15 bytes)
    will be created.
    
*   ``mac_len`` (*integer*): the desired length of the 
    MAC tag (default if not present: 16 bytes).

The cipher object has a read-only attribute :attr:`nonce`.
