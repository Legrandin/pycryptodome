SHA-1
=====

SHA-1_ produces the 160 bit digest of a message.
For example::

    >>> from Crypto.Hash import SHA1
    >>>
    >>> h = SHA1.new()
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

*SHA* stands for Secure Hash Algorithm.

.. warning::
    This algorithm is not considered secure. Do not use it for new designs.

.. warning::
    SHA-1 is vulnerable to `length-extension attacks <https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack>`_,
    which are relevant if you are computing the hash of a secret message.
    
    For instance, let's say you were planning to build a cheap MAC by concatenating a secret *key* to
    a public message *m* (bad idea!):
   
    .. math::
        h = \text{SHA-1}(m || k)
    
    By only knowing the digest *h* and the length of *m* and *k*, the attacker can easily compute a second digest *h'*:
    
    .. math::
        h' = \text{SHA-1}(m || p || z)
    
    where *p* is a well-known bit string and the attacker can pick a bit string *z* at will.

.. _SHA-1: http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

.. py:function:: Crypto.SHA1.new(msg=None)

    Create a new hash object.

    :param msg:
        Optional. The very first chunk of the message to hash.
        It is equivalent to an early call to :func:`update`.
    :type msg: byte string
   
    :returns: A :class:`SHA1_Hash` hash object

.. py:class:: Crypto.SHA1.SHA1_Hash

    A SHA-1 hash object.
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


