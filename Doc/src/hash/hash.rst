:mod:`Crypto.Hash` package
==========================

Cryptographic hash functions take arbitrary binary strings as input, and produce a random-like output
of fixed (sometimes variable) size that is dependent on the input; it should be practically infeasible
to derive the original input data given only the hash function's
output. In other words, the hash function is *one-way*.

It should also not be practically feasible to find a second piece of data
(a *second pre-image*) whose hash is the same as the original message
(*weak collision resistance*).

Finally, it should not be feasible to find two arbitrary messages with the
same hash (*strong collision resistance*).

The output of the hash function is called the *digest* of the input message.
In general, the security of a hash function is related to the length of the
digest. If the digest is *n* bits long, its security level is roughly comparable
to the the one offered by an *n/2* bit encryption algorithm.

Hash functions can be used simply as a integrity check, or, in
association with a public-key algorithm, can be used to implement
digital signatures.

API
---

Every time you want to hash a message, you have to create a new hash object
with the :func:`new` function in the relevant algorithm module (e.g.
:func:`Crypto.Hash.SHA256.new`).

A first piece of message to hash can be passed to :func:`new` with the :attr:`data` parameter::

    >> from Crypto.Hash import SHA256
    >>
    >> hash_object = SHA256.new(data=b'First')

.. note::
    You can only hash *byte strings* (no Python 2 Unicode strings, Python 3
    strings or byte arrays).

Afterwards, the method :meth:`update` can be invoked any number of times
as necessary, with other pieces of message::

    >>> hash_object.update(b'Second')
    >>> hash_object.update(b'Third')

Which is equivalent to::

    >>> hash_object.update(b'SecondThird')

A the end, the digest can be retrieved with the methods :meth:`digest` or
:meth:`hexdigest`::

    >>> print(hash_object.digest())
    b'}\x96\xfd@\xb2$?O\xca\xc1a\x10\x15\x8c\x94\xe4\xb4\x085"\xd5"\xa8\xa4C\x9e+\x00\x859\xc7A'
    >>> print(hash_object.hexdigest())
    7d96fd40b2243f4fcac16110158c94e4b4083522d522a8a4439e2b008539c741

.. figure:: hashing.png
    :align: center
    :figwidth: 50%

    Generic state diagram for a hash object

Attributes of hash objects
--------------------------

Every hash object has the following attributes:

.. csv-table:: 
    :header: Attribute, Description
    :widths: 20, 80

    digest_size, "Size of the digest in bytes, that is, the output
    of the :meth:`digest` method.
    It does not exist for hash functions with variable digest output
    (such as :mod:`Crypto.Hash.SHAKE128`).
    This is also a module attribute."
    block_size, "The size of the message block in bytes, input to the compression
    function. Only applicable for algorithms based on the Merkle-Damgard
    construction (e.g. :mod:`Crypto.Hash.SHA256`).
    This is also a module attribute."
    oid, "A string with the dotted representation of the ASN.1 OID
    assigned to the hash algorithm."

Modern hash algorithms
----------------------

- SHA-2 family

    - :doc:`sha224`
    - SHA-256
    - SHA-384
    - SHA-512

- SHA-3

    - SHA-3 224
    - SHA-3 256
    - SHA-3 384
    - SHA-3 512

- Kekkak
- SHAKE

    - SHAKE-128
    - SHAKE-256

- BLAKE2

    - BLAKE2s
    - BLAKE2b

Message Authentication Code (MAC) algorithms
--------------------------------------------

- HMAC
- CMAC

Historich hash algorithms
-------------------------

The following algorithm should not be used in new designs:

- SHA-1
- MD2
- MD4
- MD5
- RIPEMD-160
