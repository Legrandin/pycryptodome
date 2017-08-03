Triple DES
==========

.. warning::
    Use :doc:`aes` instead. This module is provided only for legacy purposes.

`Triple DES`__ (or TDES or TDEA or 3DES) is a symmetric block cipher
standardized by NIST in
`SP 800-67 Rev1 <http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r1.pdf>`_,
though they will `deprecate`_ it soon.

TDES has a fixed data block size of 8 bytes.
It consists of the cascade of 3 :doc:`des` ciphers
(EDE: Encryption - Decryption - Encryption), where each stage uses an
indipendent DES sub-key.

The standard defines 3 *Keying Options*:

* *Option 1*: all sub-keys take different values (parity bits ignored).
  The TDES key is therefore 24 bytes long (concatenation of *K1*, *K2*, and
  *K3*) , to achieve 112 bits of effective security.

* *Option 2*: *K1* matches *K3* but *K2* is different (parity bits ignored).
  The TDES key is 16 bytes long (concatenation of *K1* and *K2*),
  to achieve `90 bits`_ of effective security.
  In this mode, the cipher is also termed 2TDES.

* *Option 3*: *K1* *K2*, and *K3* all match (parity bits ignored).
  As result, Triple DES degrades to Single DES.

**This implementation does not support and will purposefully fail when
attempting to configure the cipher in Option 3.**

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import DES3
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> # Avoid Option 3
    >>> while True:
    >>>     try:
    >>>         key = DES3.adjust_key_parity(get_random_bytes(24))
    >>>         break
    >>>     except ValueError:
    >>>         pass
    >>>
    >>> cipher = DES3.new(key, DES3.MODE_CFB)
    >>> plaintext = b'We are no longer the knights who say ni!'
    >>> msg = cipher.nonce + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Triple_DES
.. _deprecate: https://beta.csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA
.. _90 bits: http://people.scs.carleton.ca/~paulv/papers/Euro90.pdf

.. automodule:: Crypto.Cipher.DES3
    :members:
