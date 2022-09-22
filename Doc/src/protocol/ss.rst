Secret Sharing Schemes
======================

This module implements the Shamir's secret sharing protocol
described in the paper `"How to share a secret"`__.

The secret can be split into an arbitrary number of shares (``n``),
such that it is sufficient to collect just ``k`` of them to reconstruct it (``k < n``).
For instance, one may want to grant 16 people the ability to access a system
with a pass code, at the condition that at least 3 of them are present at
the same time. As they join their shares, the pass code is revealed.
In that case, ``n=16`` and ``k=3``.

In the Shamir's secret sharing scheme, the ``n`` shares are created by first
defining a polynomial of degree ``k-1``:

:math:`q(x) = a_0 + a_1 x + a_2 x^2 + \ldots + a_{k-1} x^{k-1}`

The coefficient :math:`a_0` is fixed with the secret value.
The coefficients :math:`a_1 \ldots a_{k-1}` are random and they are discarded as soon as the shares are created.

Each share is a pair :math:`(x_i, y_i)`, where :math:`x_i` is an arbitrary
but unique number assigned to the share's recipient and :math:`y_i=q(x_i)`.

This implementation has the following properties:

* The secret is a byte string of 16 bytes (e.g. an AES 128 key).
* Each share is a byte string of 16 bytes.
* The recipients of the shares are assigned an integer starting from 1 (share number :math:`x_i`).
* The polynomial :math:`q(x)` is defined over the field GF(:math:`2^{128}`) with
  the same irriducible polynomial as used in AES-GCM: :math:`1 + x + x^2 + x^7 + x^{128}`.
* It can be compatible with the popular `ssss`_ tool when used with the 128 bit security level
  and no dispersion: the command line arguments must include ``-s 128 -D``.
  Note that ``ssss`` uses a slightly different polynomial:

  :math:`r(x) = a_0 + a_1 x + a_2 x^2 + \ldots + a_{k-1} x^{k-1} + x^k`

  which requires you to specify ``ssss=True`` when calling ``split()`` and ``combine()``.

Each recipient needs to hold both the share number (:math:`x_i`, which is not confidential) and
the secret (which needs to be protected securely).

As an example, the following code shows how to protect a file meant
for 5 people, in such a way that any 2 of them are sufficient to
reassemble it::

    >>> from binascii import hexlify
    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>> from Crypto.Protocol.SecretSharing import Shamir
    >>>
    >>> key = get_random_bytes(16)
    >>> shares = Shamir.split(2, 5, key)
    >>> for idx, share in shares:
    >>>     print "Index #%d: %s" % (idx, hexlify(share))
    >>>
    >>> with open("clear.txt", "rb") as fi, open("enc.txt", "wb") as fo:
    >>>     cipher = AES.new(key, AES.MODE_EAX)
    >>>     ct, tag = cipher.encrypt(fi.read()), cipher.digest()
    >>>     fo.write(nonce + tag + ct)

Each person can be given one share and the encrypted file.

When 2 people gather together with their shares, they can
decrypt the file::

    >>> from binascii import unhexlify
    >>> from Crypto.Cipher import AES
    >>> from Crypto.Protocol.SecretSharing import Shamir
    >>>
    >>> shares = []
    >>> for x in range(2):
    >>>     in_str = raw_input("Enter index and share separated by comma: ")
    >>>     idx, share = [ strip(s) for s in in_str.split(",") ]
    >>>     shares.append((idx, unhexlify(share)))
    >>> key = Shamir.combine(shares)
    >>>
    >>> with open("enc.txt", "rb") as fi:
    >>>     nonce, tag = [ fi.read(16) for x in range(2) ]
    >>>     cipher = AES.new(key, AES.MODE_EAX, nonce)
    >>>     try:
    >>>         result = cipher.decrypt(fi.read())
    >>>         cipher.verify(tag)
    >>>         with open("clear2.txt", "wb") as fo:
    >>>             fo.write(result)
    >>>     except ValueError:
    >>>         print "The shares were incorrect"

.. attention::
    Reconstruction may succeed but still produce the incorrect secret
    if any of the presented shares is incorrect (due to data corruption
    or to a malicious participant).

    It is extremely important to also use an authentication mechanism
    (such as the EAX cipher mode in the example).

.. __: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.80.8910&rep=rep1&type=pdf
.. _ssss: http://point-at-infinity.org/ssss/

.. automodule:: Crypto.Protocol.SecretSharing
    :members:
