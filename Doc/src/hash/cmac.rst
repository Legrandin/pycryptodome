CMAC
====

CMAC (Cipher-based Message Authentication Code) is a MAC defined
in `NIST SP 800-38B`_ and in RFC4493_ (for AES only) and
constructed using a block cipher. It was originally known as `OMAC1`_.

The algorithm is sometimes named *X-CMAC* where *X* is the name
of the cipher (e.g. AES-CMAC).

This is an example showing how to generate an AES-CMAC tag::

    >>> from Crypto.Hash import CMAC
    >>> from Crypto.Cipher import AES
    >>>
    >>> secret = b'Sixteen byte key'
    >>> cobj = CMAC.new(secret, ciphermod=AES)
    >>> cobj.update(b'Hello')
    >>> print cobj.hexdigest()

And this is an example showing how to validate the AES-CMAC::

    >>> from Crypto.Hash import CMAC
    >>> from Crypto.Cipher import AES
    >>>
    >>> # We have received a message 'msg' together
    >>> # with its MAC 'mac'
    >>>
    >>> secret = b'Sixteen byte key'
    >>> cobj = CMAC.new(secret, ciphermod=AES)
    >>> cobj.update(msg)
    >>> try:
    >>>   cobj.verify(mac)
    >>>   print "The message '%s' is authentic" % msg
    >>> except ValueError:
    >>>   print "The message or the key is wrong"

A cipher block size of 128 bits (like for AES) guarantees that the risk
of MAC collisions remains negligeable even when the same CMAC key is
used to authenticate a large amount of data.

This implementation allows also usage of ciphers with a 64 bits block size
(like TDES) for legacy purposes only.
However, the risk is much higher and one CMAC key should be rotated
after as little as 16 MB (in total) have been authenticated.

.. _`NIST SP 800-38B`: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
.. _RFC4493: http://www.ietf.org/rfc/rfc4493.txt
.. _OMAC1: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html

.. automodule:: Crypto.Hash.CMAC
    :members:
