RIPEMD-160
==========

RIPEMD-160_ produces the 160 bit digest of a message.
For example::

    >>> from Crypto.Hash import RIPEMD160
    >>>
    >>> h = RIPEMD160.new()
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

RIPEMD-160 stands for RACE Integrity Primitives Evaluation Message Digest
with a 160 bit digest. It was invented by Dobbertin, Bosselaers, and Preneel.

.. warning::
    This algorithm is not considered secure. Do not use it for new designs.

.. warning::
    RIPEMD-160 is vulnerable to `length-extension attacks <https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack>`_,
    which are relevant if you are computing the hash of a secret message.
    
    For instance, let's say you were planning to build a cheap MAC by concatenating a secret *key* to
    a public message *m* (bad idea!):
   
    .. math::
        h = \text{RIPEMD-160}(m || k)
    
    By only knowing the digest *h* and the length of *m* and *k*, the attacker can easily compute a second digest *h'*:
    
    .. math::
        h' = \text{RIPEMD-160}(m || p || z)
    
    where *p* is a well-known bit string and the attacker can pick a bit string *z* at will.

.. _RIPEMD-160: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html

.. automodule:: Crypto.Hash.RIPEMD160
    :members:
