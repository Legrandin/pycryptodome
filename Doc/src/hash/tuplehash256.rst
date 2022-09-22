TupleHash256
============

TupleHash256 is a variable-lengh hash function for tuples of byte strings,
derived from SHA-3, and standardized in `NIST SP 800-185 <https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf>`_.

TupleHash256 provides a robust way to hash a sequence of byte strings,
while maintaining the semantics of each single string, and with a security strength of 256 bits.

For example, let's assume that a banking application combines the following strings
to validate a money transfer: ``deposit``, amount (e.g., ``100``), and username (e.g., ``joe``).
The application uses SHA256 and naively concatenates the strings to obtain a credential to authorize the operation::

    SHA256("deposit100joe")

A malicious user could register a second user ``000joe``,
so that the system computes, for the same small transfer::

    SHA256("deposit100000joe")

which is also the same credential that authorizes a much larger transfer to the other user ``joe``.

TupleHash256 makes the composition of all strings into a digest more robust
by ensuring that the size of each individual byte string is considered.
Each byte string is submitted in its entirety via the ``update()`` method.

This is an example showing how to generate a TupleHash256 for the 3 bytes strings above::

    >>> from Crypto.Hash import TupleHash256
    >>>
    >>> hd = TupleHash256.new(digest_bytes=16)
    >>> hd.update(b'deposit')
    >>> hd.update(b'100')
    >>> hd.update(b'joe')
    >>> print(hd.hexdigest())
    b101225b7e5f1f086fc6d0be01abfa1e

Any or even all the byte strings in the sequence can be empty.
An empty byte string is significant: calling ``update(b'')`` will still contribute to and modify the final digest.

An application can select the length of the digest by means of the initialization parameters ``digest_bytes`` or ``digest_bits``.
For instance, while the traditional SHA256 can only produce 32-byte tags,
with TupleHash256 you can produce a 16-byte tag (see the example above) but also a 33-byte tag::

    >>> from Crypto.Hash import TupleHash256
    >>>
    >>> hd = TupleHash256.new(digest_bytes=33)
    >>> hd.update(b'deposit')
    >>> hd.update(b'100')
    >>> hd.update(b'joe')
    >>> print(hd.hexdigest())
    29cbb43b90e19bfebf7ff0acfa651a889f106486dae9f9f42c34a48e1b8a7bfa6f

Note how the 16-byte digest is NOT just the truncated version of the 33-byte digest: they are cryptographically uncorrelated.

.. automodule:: Crypto.Hash.TupleHash256
    :members:
