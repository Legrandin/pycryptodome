KMAC128
=======

KMAC128 is a variable-length Message Authenticated Code (MAC) derived from SHA-3
and standardized in `NIST SP 800-185 <https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf>`_.

KMAC128 provides a security strength of 128 bits.
It must be keyed with a secret of 16 bytes or more.

This is an example showing how to generate a KMAC128 tag::

    >>> from Crypto.Hash import KMAC128
    >>>
    >>> secret = b'Sixteen byte key'
    >>> mac = KMAC128.new(key=secret, mac_len=16)
    >>> mac.update(b'Hello')
    >>> print(mac.hexdigest())
    e6cb0fb015898ebd019d4eb5fad444bf

And this is an example showing how to validate the KMAC128 tag::

    >>> from Crypto.Hash import KMAC128
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Sixteen byte key'
    >>> mac = KMAC128.new(key=secret, mac_len=16)
    >>> mac.update(msg)
    >>> try:
    >>>   mac.verify(mac)
    >>>   print("The message '%s' is authentic" % msg)
    >>> except ValueError:
    >>>   print("The message or the key is wrong")

An application can select the length of the MAC tag by means of the initialization parameter ``mac_len``.
For instance, while the traditional HMAC-SHA256 can only produce 32-byte tags,
with KMAC128 you can produce 16-byte tags (see the examples above) but also a 33-byte tag::

    >>> from Crypto.Hash import KMAC128
    >>>
    >>> secret = b'Sixteen byte key'
    >>> mac = KMAC128.new(key=secret, mac_len=33)
    >>> mac.update(b'Hello')
    >>> print(mac.hexdigest())
    eed4b3157bd5d98002ad0ca990c192125416c7a72705fea22cf5d896361243bc5a

Note how the 16-byte tag is NOT just the truncated version of the 33-byte tag: they are cryptographically uncorrelated.

.. automodule:: Crypto.Hash.KMAC128
    :members:
