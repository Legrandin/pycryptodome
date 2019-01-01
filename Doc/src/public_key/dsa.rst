DSA
===

DSA_ is a widespread public key signature algorithm. Its security is
based on the discrete logarithm problem (DLP_). Given a cyclic
group, a generator *g*, and an element *h*, it is hard
to find an integer *x* such that :math:`g^x = h`. The problem is believed
to be difficult, and it has been proved such (and therefore secure) for
more than 30 years.

The group is actually a sub-group over the integers modulo *p*, with *p* prime.
The sub-group order is *q*, which is prime too; it always holds that *(p-1)* is a multiple of *q*.
The cryptographic strength is linked to the magnitude of *p* and *q*.
The signer holds a value *x* (*0<x<q-1*) as private key, and its public
key (*y* where :math:`y=g^x \text{ mod } p`) is distributed.

In 2017, a sufficient size is deemed to be 2048 bits for *p* and 256 bits for *q*.
For more information, see the most recent ECRYPT_ report.

The algorithm can only be used for authentication (digital signature).
DSA cannot be used for confidentiality (encryption).

The values *(p,q,g)* are called *domain parameters*;
they are not sensitive but must be shared by both parties (the signer and the verifier).
Different signers can share the same domain parameters with no security
concerns.

The DSA signature is twice as big as the size of *q* (64 bytes if *q* is 256 bit
long).

This module provides facilities for generating new DSA keys and for constructing
them from known components.

As an example, this is how you generate a new DSA key pair, save the public
key in a file called ``public_key.pem``, sign a message (with
:mod:`Crypto.Signature.DSS`), and verify it::

    >>> from Crypto.PublicKey import DSA
    >>> from Crypto.Signature import DSS
    >>> from Crypto.Hash import SHA256
    >>>
    >>> # Create a new DSA key
    >>> key = DSA.generate(2048)
    >>> f = open("public_key.pem", "w")
    >>> f.write(key.publickey().export_key(key))
    >>>
    >>> # Sign a message
    >>> message = b"Hello"
    >>> hash_obj = SHA256.new(message)
    >>> signer = DSS.new(key, 'fips-186-3')
    >>> signature = signer.sign(hash_obj)
    >>> 
    >>> # Load the public key
    >>> f = open("public_key.pem", "r")
    >>> hash_obj = SHA256.new(message)
    >>> pub_key = DSA.import_key(f.read())
    >>>
    >>> # Verify the authenticity of the message
    >>> if pub_key.verify(hash_obj, signature):
    >>>     print "OK"
    >>> else:
    >>>     print "Incorrect signature"

.. _DSA: http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _DLP: http://www.cosic.esat.kuleuven.be/publications/talk-78.pdf
.. _ECRYPT: http://www.ecrypt.eu.org/documents/D.SPA.17.pdf

.. automodule:: Crypto.PublicKey.DSA
    :members:
