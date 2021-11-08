KMAC256
=======

KMAC256is a Message Authenticated Code (MAC) derived from SHA-3
and standardized in `NIST SP 800-185 <https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf>`_.

KMAC256 provides a security strength of 256 bits.
It must be keyed with a secret of 32 bytes or more.

Unlike several other MAC functions (like HMAC),
the length of the MAC tag is not fixed.
An application can choose any size, with 64 bits (8 bytes) as the minimum.

    >>> from Crypto.Hash import KMAC256
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = get_random_bytes(32)
    >>> mac = KMAC256.new(key=key, mac_len=16)
    >>> mac.update(b'Some data')
    >>> print mac.hexdigest()

.. automodule:: Crypto.Hash.KMAC256
    :members:
