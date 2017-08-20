Single DES
==========

.. warning::
    Use :doc:`aes` instead. This module is provided only for legacy purposes.

DES `(Data Encryption Standard)`__ is a symmetric block cipher standardized
in `FIPS 46-3 <http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf>`_
(now withdran).
It has a fixed data block size of 8 bytes.

Its keys are 64 bits long, even though 8 bits were used for integrity (now they
are ignored) and do not contribute to security. The effective key length is
therefore 56 bits only.

DES was never cryptographically broken, but its key length is too short by nowadays
standards and it could be brute forced with some effort.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import DES
    >>>
    >>> key = b'-8B key-'
    >>> cipher = DES.new(key, DES.MODE_OFB)
    >>> plaintext = b'sona si latine loqueris '
    >>> msg = cipher.iv + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Data_Encryption_Standard

.. automodule:: Crypto.Cipher.DES
    :members:
