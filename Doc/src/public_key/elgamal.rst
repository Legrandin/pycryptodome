El Gamal
========

.. warning::
    Even though ElGamal algorithms are in theory reasonably secure,
    in practice there are no real good reasons to prefer them to :doc:`rsa`
    instead.

Signature algorithm
-------------------
The security of the ElGamal signature scheme is based (like DSA) on the discrete
logarithm problem (DLP_). Given a cyclic group, a generator *g*,
and an element *h*, it is hard to find an integer *x* such that :math:`g^x = h`.

The group is the largest multiplicative sub-group of the integers modulo *p*,
with *p* prime.
The signer holds a value *x* (*0<x<p-1*) as private key, and its public
key (*y* where :math:`y=g^x \text{ mod } p`) is distributed.

The ElGamal signature is twice as big as *p*.

Encryption algorithm
--------------------
The security of the ElGamal encryption scheme is based on the computational
Diffie-Hellman problem (CDH_). Given a cyclic group, a generator *g*,
and two integers *a* and *b*, it is difficult to find
the element :math:`g^{ab}` when only :math:`g^a` and :math:`g^b` are known, and not *a* and *b*.

As before, the group is the largest multiplicative sub-group of the integers
modulo *p*, with *p* prime.
The receiver holds a value *a* (*0<a<p-1*) as private key, and its public key
(*b* where :math:`b=g^a`) is given to the sender.

The ElGamal ciphertext is twice as big as *p*.

Domain parameters
-----------------
For both signature and encryption schemes, the values *(p,g)* are called
*domain parameters*.
They are not sensitive but must be distributed to all parties (senders and
receivers).
Different signers can share the same domain parameters, as can
different recipients of encrypted messages.

Security
--------
Both DLP and CDH problem are believed to be difficult, and they have been proved
such (and therefore secure) for more than 30 years.

The cryptographic strength is linked to the magnitude of *p*.
In 2017, a sufficient size for *p* is deemed to be 2048 bits.
For more information, see the most recent ECRYPT_ report.

The signature is four times larger than the equivalent DSA, and the ciphertext
is two times larger than the equivalent RSA.

Functionality
-------------
This module provides facilities for generating new ElGamal keys
and constructing them from known components.

.. _DLP: http://www.cosic.esat.kuleuven.be/publications/talk-78.pdf
.. _CDH: http://en.wikipedia.org/wiki/Computational_Diffie%E2%80%93Hellman_assumption
.. _ECRYPT: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf

.. automodule:: Crypto.PublicKey.ElGamal
    :members:
