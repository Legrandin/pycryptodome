MD5
===

MD5 is specified in RFC1321_ and produces the 128 bit digest of a message.
For example:

    >>> from Crypto.Hash import MD5:
    >>>
    >>> h = MD5.new()
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

MD5 stand for Message Digest version 5, and it was invented by Rivest in 1991.


.. warning::
    This algorithm is not considered secure. Do not use it for new designs.

.. warning::
    MD5 is vulnerable to `length-extension attacks <https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack>`_,
    which are relevant if you are computing the hash of a secret message.
    
    For instance, let's say you were planning to build a cheap MAC by concatenating a secret *key* to
    a public message *m* (bad idea!):
   
    .. math::
        h = \text{MD5}(m || k)
    
    By only knowing the digest *h* and the length of *m* and *k*, the attacker can easily compute a second digest *h'*:
    
    .. math::
        h' = \text{MD5}(m || p || z)
    
    where *p* is a well-known bit string and the attacker can pick a bit string *z* at will.

.. _RFC1321: http://tools.ietf.org/html/rfc1321

.. py:function:: Crypto.MD5.new(msg=None)

    Create a new hash object.

    :param msg:
        Optional. The very first chunk of the message to hash.
        It is equivalent to an early call to :func:`update`.
    :type msg: byte string
   
    :returns: An :class:`MD5_Hash` hash object

.. py:class:: Crypto.MD5.MD5_Hash

    An MD5 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string

    :ivar block_size: the size in bytes of the internal message block,
                      input to the compression function
    :vartype block_size: integer

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer

    .. py:method:: update(msg)
        
        Continue hashing of a message by consuming the next chunk of data.

        :param msg: The next chunk of the message being hashed.
        :type param: byte string

    .. py:method:: digest()
        
        Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
    
    .. py:method:: hexdigest() 
        
        Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string


