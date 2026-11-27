Triple DES
==========

.. warning::
    Use :doc:`aes` instead. This module is provided only for legacy purposes.

`Triple DES`__ (or TDES or TDEA or 3DES) is a symmetric block cipher
standardized by NIST in `SP 800-67 Rev. 2`_.
NIST `withdrew`_ that standard on January 1, 2024: Triple DES must no longer be used
to encrypt data (or to wrap keys or create MACs), but it can still be used to decrypt
existing data.

TDES has a fixed data block size of 8 bytes.
It consists of the cascade of 3 :doc:`des` ciphers
(EDE: Encryption - Decryption - Encryption), where each stage uses an
independent DES sub-key.

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

**This implementation purposefully fails (with** ``ValueError``\ **) when the key
degenerates to Single DES.** That is the case of Option 3, but also of a 24-byte key
where only *K1* and *K2* match (equivalent to Single DES with *K3*)
or only *K2* and *K3* match (equivalent to Single DES with *K1*).
See :ref:`des3_degenerate_keys` if you must use such a key.

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import DES3
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> # Avoid Option 3
    >>> while True:
    ...     try:
    ...         key = DES3.adjust_key_parity(get_random_bytes(24))
    ...         break
    ...     except ValueError:
    ...         pass
    >>>
    >>> cipher = DES3.new(key, DES3.MODE_CFB)
    >>> plaintext = b'We are no longer the knights who say ni!'
    >>> msg = cipher.iv + cipher.encrypt(plaintext)

.. _des3_degenerate_keys:

Keys that degenerate to Single DES
----------------------------------

If you really must use a key that degenerates to Single DES
(for instance, the default all-zero key of a smartcard or an NFC device,
used once to provision a new key), use :doc:`des` with the equivalent key:
the result is the same, in any mode.
Its security is only that of Single DES (56 bits). For instance::

    from Crypto.Cipher import DES, DES3

    def new_des3_or_des(key, *args, **kwargs):
        """Like DES3.new(), but also accept a key that degenerates to Single DES."""

        if len(key) not in (16, 24):
            raise ValueError("Not a valid TDES key")
        k1, k2 = key[:8], key[8:16]
        k3 = key[16:] if len(key) == 24 else k1

        def same(a, b):  # parity bits are ignored
            return all((x ^ y) & 0xFE == 0 for x, y in zip(a, b))

        if same(k1, k2):
            return DES.new(k3, *args, **kwargs)
        if same(k2, k3):
            return DES.new(k1, *args, **kwargs)
        return DES3.new(key, *args, **kwargs)

    cipher = new_des3_or_des(bytes(16), DES3.MODE_CBC, iv=bytes(8))

.. __: http://en.wikipedia.org/wiki/Triple_DES
.. _SP 800-67 Rev. 2: https://csrc.nist.gov/pubs/sp/800/67/r2/final
.. _withdrew: https://csrc.nist.gov/news/2023/nist-to-withdraw-sp-800-67-rev-2
.. _90 bits: http://people.scs.carleton.ca/~paulv/papers/Euro90.pdf

API
---

.. automodule:: Crypto.Cipher.DES3
    :members:
