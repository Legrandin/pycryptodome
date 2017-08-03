RC2
===

.. warning::
    Use :doc:`aes` instead. This module is provided only for legacy purposes.

RC2_ (Rivest's Cipher version 2)  is a symmetric block cipher designed
by Ron Rivest in 1987. The cipher started as a proprietary design,
that was reverse engineered and anonymously posted on Usenet in 1996.
For this reason, the algorithm was first called *Alleged* RC2 (ARC2),
since the company that owned RC2 (RSA Data Inc.) did not confirm whether
the details leaked into public domain were really correct.

The company eventually published its full specification in RFC2268_.

RC2 has a fixed data block size of 8 bytes. Length of its keys can vary from
8 to 128 bits. One particular property of RC2 is that the actual
cryptographic strength of the key (*effective key length*) can be reduced
via a parameter.

Even though RC2 is not cryptographically broken, it has not been analyzed as
thoroughly as AES, which is also faster than RC2.

As an example, encryption can be done as follows::

    >>> from Crypto.Cipher import ARC2
    >>>
    >>> key = b'Sixteen byte key'
    >>> cipher = ARC2.new(key, ARC2.MODE_CFB)
    >>> msg = cipher.iv + cipher.encrypt(b'Attack at dawn')

.. _RC2: http://en.wikipedia.org/wiki/RC2
.. _RFC2268: http://tools.ietf.org/html/rfc2268

.. automodule:: Crypto.Cipher.ARC2
    :members:
