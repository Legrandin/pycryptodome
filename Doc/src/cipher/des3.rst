Triple DES
==========

`Triple DES`__ (or TDES or TDEA or 3DES) is a symmetric block cipher
standardized in
`NIST SP 800-67 Rev1 <http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r1.pdf>`_.
It has a fixed data block size of 8 bytes.

TDES consists of the concatenation of 3 simple `des` ciphers
(encryption - decryption - encryption), where each stage uses an
indipendent sub-key.

A TDES key is therefore 24 (8+8+8) bytes long. However, like Single DES,
only 7 out of 8 bits are actually used: the remaining ones are parity
bits (which practically all TDES implementations ignore).
Theoreticaly, Triple DES achieves up to 112 bits of effective security.

Triple DES can also operate with a 16 bytes key (Option 2, also termed 2TDES),
in which case subkey *K1* equals subkey *K2*. The effective security
is as low as `90 bits`_.

This implementation checks and enforces the condition *K1 != K2 != K3*
(Option 3), as it would degrade Triple DES to Single DES.

**Use AES, not TDES. This module is provided for legacy purposes only.**

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import DES3
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> # When generating a Triple DES key you must check that
    >>> # subkey1 != subkey2 and subkey2 != subkey3
    >>> while True:
    >>>     try:
    >>>         key = DES3.adjust_key_parity(get_random_bytes(24))
    >>>         break
    >>>     except ValueError
    >>>         pass
    >>>
    >>> cipher = DES3.new(key, DES3.MODE_CFB)
    >>> plaintext = b'We are no longer the knights who say ni!'
    >>> msg = cipher.nonce + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Triple_DES
.. _90 bits: http://people.scs.carleton.ca/~paulv/papers/Euro90.pdf

.. automodule:: Crypto.Cipher.DES3
    :members:
