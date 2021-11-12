KMAC256
=======

KMAC256 is a variable-length Message Authenticated Code (MAC) derived from SHA-3
and standardized in `NIST SP 800-185 <https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf>`_.

KMAC256 provides a security strength of 256 bits.
It must be keyed with a secret of 32 bytes or more.

This is an example showing how to generate a KMAC256 tag::

    >>> from Crypto.Hash import KMAC256
    >>>
    >>> secret = b'Protect this thirty-two byte key'
    >>> mac = KMAC256.new(key=secret, mac_len=16)
    >>> mac.update(b'Hello')
    >>> print(mac.hexdigest())
    4ba8c9808f10b3bf5621f393363f4e1a

And this is an example showing how to validate the KMAC256 tag::

    >>> from Crypto.Hash import KMAC256
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Protect this thirty-two byte key'
    >>> mac = KMAC256.new(key=secret, mac_len=16)
    >>> mac.update(msg)
    >>> try:
    >>>   mac.verify(mac)
    >>>   print("The message '%s' is authentic" % msg)
    >>> except ValueError:
    >>>   print("The message or the key is wrong")

An application can select the length of the MAC tag by means of the initialization parameter ``mac_len``.
For instance, while the traditional HMAC-SHA256 can only produce 32-byte tags,
with KMAC256 you can produce 16-byte tags (see the examples above) but also a 33-byte tag::

    >>> from Crypto.Hash import KMAC256
    >>>
    >>> secret = b'Protect this thirty-two byte key'
    >>> mac = KMAC256.new(key=secret, mac_len=33)
    >>> mac.update(b'Hello')
    >>> print(mac.hexdigest())
    518938a66f4ce8f50a35cf77d16f002d5734da495eb6dea1e41191e657890ba4ad

Note how the 16-byte tag is NOT just the truncated version of the 33-byte tag: they are cryptographically uncorrelated.

.. automodule:: Crypto.Hash.KMAC256
    :members:
