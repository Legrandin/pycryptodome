HMAC
====

HMAC (Hash-based Message Authentication Code) is a MAC defined
in RFC2104_ and FIPS-198_ and constructed using a cryptograpic
hash algorithm.

It is usually named *HMAC-X*, where *X* is the hash algorithm; for
instance *HMAC-SHA1* or *HMAC-SHA256*.

The strength of an HMAC depends on:

* the strength of the hash algorithm
* the entropy of the secret key

This is an example showing how to generate a MAC (with *HMAC-SHA256*)::

    >>> from Crypto.Hash import HMAC, SHA256
    >>>
    >>> secret = b'Swordfish'
    >>> h = HMAC.new(secret, digestmod=SHA256)
    >>> h.update(b'Hello')
    >>> print h.hexdigest()

This is an example showing how to validate the MAC::

    >>> from Crypto.Hash import HMAC, SHA256
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Swordfish'
    >>> h = HMAC.new(secret, digestmod=SHA256)
    >>> h.update(msg)
    >>> try:
    >>>   h.hexverify(mac)
    >>>   print("The message '%s' is authentic" % msg)
    >>> except ValueError:
    >>>   print("The message or the key is wrong")

.. _RFC2104: http://www.ietf.org/rfc/rfc2104.txt
.. _FIPS-198: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf

.. automodule:: Crypto.Hash.HMAC
    :members:
