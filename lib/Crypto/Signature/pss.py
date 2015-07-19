# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

"""RSA digital signature protocol with appendix according to PKCS#1 PSS.

See RFC3447__ or the `original RSA Labs specification`__.

This scheme is more properly called ``RSASSA-PSS``.

The following example shows how the sender can create the signatue of
a message using their private key:

    >>> from Crypto.Signature import pss
    >>> from Crypto.Hash import SHA256
    >>> from Crypto.PublicKey import RSA
    >>> from Crypto import Random
    >>>
    >>> message = 'To be signed'
    >>> key = RSA.importKey(open('privkey.der').read())
    >>> h = SHA256.new(message)
    >>> signature = pss.new(key).sign(h)

At the receiver side, verification can be done using the public RSA key:

    >>> key = RSA.importKey(open('pubkey.der').read())
    >>> h = SHA256.new(message)
    >>> verifier = pss.new(key)
    >>> try:
    >>>     verifier.verify(h, signature):
    >>>     print "The signature is authentic."
    >>> except (ValueError, TypeError):
    >>>     print "The signature is not authentic."

:undocumented: __package__

.. __: http://www.ietf.org/rfc/rfc3447.txt
.. __: http://www.rsa.com/rsalabs/node.asp?id=2125
"""

from Crypto.Util.py3compat import b, bchr, bord
import Crypto.Util.number
from Crypto.Util.number import (ceil_div,
                                long_to_bytes,
                                bytes_to_long
                                )
from Crypto.Util.strxor import strxor
from Crypto import Random


class PSS_SigScheme:
    """An instance of the PKCS#1 PSS signature scheme for a specific RSA key."""

    def __init__(self, key, mgfunc, saltLen, randfunc):
        """Initialize this PKCS#1 PSS signature scheme object.

        :Parameters:
          key : an RSA key object
            If a private half is given, both signature and
            verification are possible.
            If a public half is given, only verification is possible.
          mgfunc : callable
            A mask generation function that accepts two parameters:
            a string to use as seed, and the lenth of the mask to
            generate, in bytes.
          saltLen : integer
            Length of the salt, in bytes.
          randfunc : callable
            A function that returns random bytes.
        """

        self._key = key
        self._saltLen = saltLen
        self._mgfunc = mgfunc
        self._randfunc = randfunc

    def can_sign(self):
        """Return True if this cipher object can be used
        or signing messages."""
        return self._key.has_private()

    def sign(self, msg_hash):
        """Produce the PKCS#1 PSS signature of a message.

        This function is named ``RSASSA-PSS-SIGN``, and is specified in
        section 8.1.1 of RFC3447.

        :Parameters:
          msg_hash : hash object
            The hash that was carried out over the message. This is an object
            belonging to the `Crypto.Hash` module.

        :Return: The PSS signature encoded as a byte string.
        :Raise ValueError:
            If the RSA key length is not sufficiently long to deal
            with the given hash algorithm.
        :Raise TypeError:
            If the RSA key has no private half.

        :attention: Modify the salt length and the mask generation
                    function only if you know what you are doing.
                    The receiver must use the same parameters too.
        """

        # Set defaults for salt length and mask generation function
        if self._saltLen is None:
            sLen = msg_hash.digest_size
        else:
            sLen = self._saltLen

        if self._mgfunc is None:
            mgf = lambda x, y: MGF1(x, y, msg_hash)
        else:
            mgf = self._mgfunc

        modBits = Crypto.Util.number.size(self._key.n)

        # See 8.1.1 in RFC3447
        k = ceil_div(modBits, 8)  # k is length in bytes of the modulus
        # Step 1
        em = _EMSA_PSS_ENCODE(msg_hash, modBits-1, self._randfunc, mgf, sLen)
        # Step 2a (OS2IP)
        em_int = bytes_to_long(em)
        # Step 2b (RSASP1)
        m_int = self._key._decrypt(em_int)
        # Step 2c (I2OSP)
        signature = long_to_bytes(m_int, k)
        return signature

    def verify(self, msg_hash, signature):
        """Verify that a certain PKCS#1 PSS signature is authentic.

        This function checks if the party holding the private half
        of the given RSA key has really signed the message.

        This function is called ``RSASSA-PSS-VERIFY``, and is specified
        in section 8.1.2 of RFC3447.

        :Parameters:
          msg_hash : hash object
            The cryptographic hash computed over the message.
            This is an object belonging to the `Crypto.Hash` module.
          signature : byte string
            The signature that needs to be validated.

        :Raise ValueError:
            if the signature is incorrect.
        """

        # Set defaults for salt length and mask generation function
        if self._saltLen is None:
            sLen = msg_hash.digest_size
        else:
            sLen = self._saltLen
        if self._mgfunc:
            mgf = self._mgfunc
        else:
            mgf = lambda x, y: MGF1(x, y, msg_hash)

        modBits = Crypto.Util.number.size(self._key.n)

        # See 8.1.2 in RFC3447
        k = ceil_div(modBits, 8)  # Convert from bits to bytes
        # Step 1
        if len(signature) != k:
            raise ValueError("Incorrect signature")
        # Step 2a (O2SIP)
        signature_int = bytes_to_long(signature)
        # Step 2b (RSAVP1)
        em_int = self._key._encrypt(signature_int)
        # Step 2c (I2OSP)
        emLen = ceil_div(modBits - 1, 8)
        em = long_to_bytes(em_int, emLen)
        # Step 3/4
        _EMSA_PSS_VERIFY(msg_hash, em, modBits-1, mgf, sLen)


def MGF1(mgfSeed, maskLen, hash):
    """Mask Generation Function, described in B.2.1"""
    T = b("")
    for counter in xrange(ceil_div(maskLen, hash.digest_size)):
        c = long_to_bytes(counter, 4)
        hobj = hash.new()
        hobj.update(mgfSeed + c)
        T = T + hobj.digest()
    assert(len(T) >= maskLen)
    return T[:maskLen]


def _EMSA_PSS_ENCODE(mhash, emBits, randFunc, mgf, sLen):
    """
    Implement the ``EMSA-PSS-ENCODE`` function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.1.1).

    The original ``EMSA-PSS-ENCODE`` actually accepts the message ``M``
    as input, and hash it internally. Here, we expect that the message
    has already been hashed instead.

    :Parameters:
      mhash : hash object
        The hash object that holds the digest of the message being signed.
      emBits : int
        Maximum length of the final encoding, in bits.
      randFunc : callable
        An RNG function that accepts as only parameter an int, and returns
        a string of random bytes, to be used as salt.
      mgf : callable
        A mask generation function that accepts two parameters: a string to
        use as seed, and the lenth of the mask to generate, in bytes.
      sLen : int
        Length of the salt, in bytes.

    :Return: An ``emLen`` byte long string that encodes the hash
      (with ``emLen = \ceil(emBits/8)``).

    :Raise ValueError:
        When digest or salt length are too big.
    """

    emLen = ceil_div(emBits, 8)

    # Bitmask of digits that fill up
    lmask = 0
    for i in xrange(8*emLen-emBits):
        lmask = lmask >> 1 | 0x80

    # Step 1 and 2 have been already done
    # Step 3
    if emLen < mhash.digest_size+sLen+2:
        raise ValueError("Digest or salt length are too long"
                         " for given key size.")
    # Step 4
    salt = randFunc(sLen)
    # Step 5
    m_prime = bchr(0)*8 + mhash.digest() + salt
    # Step 6
    h = mhash.new()
    h.update(m_prime)
    # Step 7
    ps = bchr(0)*(emLen-sLen-mhash.digest_size-2)
    # Step 8
    db = ps + bchr(1) + salt
    # Step 9
    dbMask = mgf(h.digest(), emLen-mhash.digest_size-1)
    # Step 10
    maskedDB = strxor(db, dbMask)
    # Step 11
    maskedDB = bchr(bord(maskedDB[0]) & ~lmask) + maskedDB[1:]
    # Step 12
    em = maskedDB + h.digest() + bchr(0xBC)
    return em


def _EMSA_PSS_VERIFY(mhash, em, emBits, mgf, sLen):
    """
    Implement the ``EMSA-PSS-VERIFY`` function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.1.2).

    ``EMSA-PSS-VERIFY`` actually accepts the message ``M`` as input,
    and hash it internally. Here, we expect that the message has already
    been hashed instead.

    :Parameters:
      mhash : hash object
        The hash object that holds the digest of the message to be verified.
      em : string
        The signature to verify, therefore proving that the sender really
        signed the message that was received.
      emBits : int
        Length of the final encoding (em), in bits.
      mgf : callable
        A mask generation function that accepts two parameters: a string to
        use as seed, and the lenth of the mask to generate, in bytes.
      sLen : int
        Length of the salt, in bytes.

    :Raise ValueError:
        When the encoding is inconsistent, or the digest or salt lengths
        are too big.
    """

    emLen = ceil_div(emBits, 8)

    # Bitmask of digits that fill up
    lmask = 0
    for i in xrange(8*emLen-emBits):
        lmask = lmask >> 1 | 0x80

    # Step 1 and 2 have been already done
    # Step 3
    if emLen < mhash.digest_size+sLen+2:
        return False
    # Step 4
    if ord(em[-1:]) != 0xBC:
        raise ValueError("Incorrect signature")
    # Step 5
    maskedDB = em[:emLen-mhash.digest_size-1]
    h = em[emLen-mhash.digest_size-1:-1]
    # Step 6
    if lmask & bord(em[0]):
        raise ValueError("Incorrect signature")
    # Step 7
    dbMask = mgf(h, emLen-mhash.digest_size-1)
    # Step 8
    db = strxor(maskedDB, dbMask)
    # Step 9
    db = bchr(bord(db[0]) & ~lmask) + db[1:]
    # Step 10
    if not db.startswith(bchr(0)*(emLen-mhash.digest_size-sLen-2) + bchr(1)):
        raise ValueError("Incorrect signature")
    # Step 11
    if sLen > 0:
        salt = db[-sLen:]
    else:
        salt = b("")
    # Step 12
    m_prime = bchr(0)*8 + mhash.digest() + salt
    # Step 13
    hobj = mhash.new()
    hobj.update(m_prime)
    hp = hobj.digest()
    # Step 14
    if h != hp:
        raise ValueError("Incorrect signature")


def new(rsa_key, **kwargs):
    """Return a signature scheme object `PSS_SigScheme` that
    can be used to perform PKCS#1 PSS signature or verification.

    :Parameters:
      rsa_key : RSA key object
        The key to use to sign or verify the message.
        This is a `Crypto.PublicKey.RSA` object.
        Signing is only possible if *key* is a private RSA key.
    :Keywords:
      mask_func : callable
        A mask generation function that accepts two parameters: a string to
        use as seed, and the length of the mask in bytes to generate.
        If not specified, the standard MGF1 is used.
      salt_bytes : int
        Length of the salt, in bytes.
        If not specified, it matches the output size of the hash function.
        If zero, the signature scheme becomes deterministic.
      rand_func : callable
        A function that returns random bytes.
        The default is `Crypto.Random.get_random_bytes`.
    """

    mask_func = kwargs.pop("mask_func", None)
    salt_len = kwargs.pop("salt_bytes", None)
    rand_func = kwargs.pop("rand_func", None)
    if rand_func is None:
        rand_func = Random.get_random_bytes
    if kwargs:
        raise ValueError("Unknown keywords: " + str(kwargs.keys()))
    return PSS_SigScheme(rsa_key, mask_func, salt_len, rand_func)
