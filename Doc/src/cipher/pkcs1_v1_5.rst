PKCS#1 v1.5 encryption (RSA)
============================

.. warning::
    Use :doc:`oaep` instead. This module is provided only for legacy purposes.

See RFC8017__ or the `original RSA Labs specification`__ .

This scheme is more properly called ``RSAES-PKCS1-v1_5``.

As an example, a sender may encrypt a secret AES key in this way::

        >>> from Crypto.Cipher import PKCS1_v1_5
        >>> from Crypto.PublicKey import RSA
        >>> from Crypto.Random import get_random_bytes
        >>>
        >>> aes_key = get_random_bytes(16)
        >>>
        >>> rsa_key = RSA.importKey(open('pubkey.der').read())
        >>> cipher = PKCS1_v1_5.new(rsa_key)
        >>> ciphertext = cipher.encrypt(aes_key)

At the receiver side, decryption can be done using the private part of
the RSA key::

        >>> rsa_key = RSA.importKey(open('privkey.der').read())
        >>>
        >>> cipher = PKCS1_v1_5.new(rsa_key)
        >>> aes_key = cipher.decrypt(ciphertext, expected_pt_len=16)

Decryption never reports an incorrect padding: in that case,
it returns a pseudo-random message instead, which depends only on the
private key and on the ciphertext (*implicit rejection*, as defined in
`draft-irtf-cfrg-rsa-guidance`__).
In the example above, ``aes_key`` is then a pseudo-random 16-byte key,
and the protocol fails later (for instance, when the AES key is used to
decrypt and authenticate some data), in the same way as with a ciphertext
that has a correct padding but that encrypts the wrong key.

.. note::
    Before version 4.3, the method :meth:`decrypt` required a ``sentinel``,
    the value to return in case of an incorrect padding.
    It is still possible to pass a ``sentinel`` (and then there is no
    implicit rejection), but it is hard to use safely:
    a caller (or the party that submitted the ciphertext) can often find out
    when it is returned, and that is the oracle exploited by
    Bleichenbacher's attack.

.. __: https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-guidance/
.. __: https://tools.ietf.org/html/rfc8017
.. __: http://www.rsa.com/rsalabs/node.asp?id=2125.

.. automodule:: Crypto.Cipher.PKCS1_v1_5
    :members:
