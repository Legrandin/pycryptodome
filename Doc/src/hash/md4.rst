MD4
===

MD4 is specified in RFC1320_ and it produces the 128 bit digest of a message.
For example::

    >>> from Crypto.Hash import MD4
    >>>
    >>> h = MD4.new()
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

MD4 stand for Message Digest version 4, and it was invented by Rivest in 1990.

.. warning::
    This algorithm is not considered secure. Do not use it for new designs.

.. _RFC1320: http://tools.ietf.org/html/rfc1320

.. automodule:: Crypto.Hash.MD4
    :members:
