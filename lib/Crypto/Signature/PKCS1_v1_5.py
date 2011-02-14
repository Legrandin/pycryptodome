# -*- coding: utf-8 -*-
#
#  Signature/PKCS1-v1_5.py : PKCS#1 v1.5
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""RSA digital signature protocol according to PKCS#1 v1.5

See RFC3447 or the original RSA Labs specification at
http://www.rsa.com/rsalabs/node.asp?id=2125.

This scheme is more properly called ``RSASSA-PKCS1-v1_5``.

For example, a sender may authenticate a message using SHA-1 like
this:

        >>> from Crypto.Signature import PKCS1_v1_5
        >>> from Crypto.Hash import SHA
        >>> from Crypto.PublicKey import RSA
        >>>
        >>> message = 'To be signed'
        >>> key = RSA.importKey('key.der')
        >>> h = SHA.new()
        >>> h.update(message)
        >>>> signature = PKCS1_v1_5.sign(h, key)

At the receiver side, verification can be done using the public part of
the RSA key:

        >>> key = RSA.importKey('pubkey.der')
        >>> h = SHA.new()
        >>> h.update(message)
        >>> if PKCS.verify(h, key, signature):
        >>>    print "The signature is authentic."
        >>> else:
        >>>    print "The signature is not authentic."
"""

__revision__ = "$Id$"
__all__ = [ 'sign', 'verify' ]

import Crypto.Util.number
from Crypto.Util.number import ceil_div
from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString

def sign(mhash, key):
    """Produce the PKCS#1 v1.5 signature of a message.

    This function is named ``RSASSA-PKCS1-V1_5-SIGN``, and is specified in
    section 8.2.1 of RFC3447.

    :Parameters:
     mhash : hash object
            The hash that was carried out over the message. This is an object
            belonging to the `Crypto.Hash` module.
     key : RSA key object
            The key to use to sign the message. This is a `Crypto.PublicKey.RSA`
            object and must have its private half.

    :Return: The signature encoded as a string.
    :Raise ValueError:
        If the RSA key length is not sufficiently long to deal with the given
        hash algorithm.
    :Raise TypeError:
        If the RSA key has no private half.
    """
    # TODO: Verify the key is RSA

    # See 8.2.1 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes

    # Step 1
    em = EMSA_PKCS1_V1_5_ENCODE(mhash, k)
    # Step 2a (OS2IP) and 2b (RSASP1)
    m = key.decrypt(em)
    # Step 2c (I2OSP)
    S = '\x00'*(k-len(m)) + m
    return S

def verify(mhash, key, S):
    """Verify that a certain PKCS#1 v1.5 signature is authentic.

    This function checks if the party holding the private half of the key
    really signed the message.

    This function is named ``RSASSA-PKCS1-V1_5-VERIFY``, and is specified in
    section 8.2.2 of RFC3447.

    :Parameters:
     mhash : hash object
            The hash that was carried out over the message. This is an object
            belonging to the `Crypto.Hash` module.
     key : RSA key object
            The key to use to verify the message. This is a `Crypto.PublicKey.RSA`
            object.
     S : string
            The signature that needs to be validated.

    :Return: True if verification is correct. False otherwise.
    """
    # TODO: Verify the key is RSA

    # See 8.2.2 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes

    # Step 1
    if len(S) != k:
        return 0
    # Step 2a (O2SIP) and 2b (RSAVP1)
    # Note that signature must be smaller than the module
    # but RSA.py won't complain about it.
    # TODO: Fix RSA object; don't do it here.
    m = key.encrypt(S, 0)[0]
    # Step 2c (I2OSP)
    em1 = '\x00'*(k-len(m)) + m
    # Step 3
    try:
        em2 = EMSA_PKCS1_V1_5_ENCODE(mhash, k)
    except ValueError:
        return 0
    # Step 4
    return em1==em2

def EMSA_PKCS1_V1_5_ENCODE(hash, emLen):
    """
    Implement the ``EMSA-PKCS1-V1_5-ENCODE`` function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.2).

    ``EMSA-PKCS1-V1_5-ENCODE`` actually accepts the message ``M`` as input,
    and hash it internally. Here, we expect that the message has already
    been hashed instead.

    :Parameters:
     hash : hash object
            The hash object that holds the digest of the message being signed.
     emLen : int
            The length the final encoding must have, in bytes.

    :attention: the early standard (RFC2313) stated that ``DigestInfo``
        had to be BER-encoded. This means that old signatures
        might have length tags in indefinite form, which
        is not supported in DER. Such encoding cannot be
        reproduced by this function.

    :attention: the same standard defined ``DigestAlgorithm`` to be
        of ``AlgorithmIdentifier`` type, where the PARAMETERS
        item is optional. Encodings for ``MD2/4/5`` without
        ``PARAMETERS`` cannot be reproduced by this function.

    :Return: An ``emLen`` byte long string that encodes the hash.
    """

    # First, build the ASN.1 DER object DigestInfo:
    #
    #   DigestInfo ::= SEQUENCE {
    #       digestAlgorithm AlgorithmIdentifier,
    #       digest OCTET STRING
    #   }
    #
    # where digestAlgorithm identifies the hash function and shall be an
    # algorithm ID with an OID in the set PKCS1-v1-5DigestAlgorithms.
    #
    #   PKCS1-v1-5DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
    #       { OID id-md2 PARAMETERS NULL    }|
    #       { OID id-md5 PARAMETERS NULL    }|
    #       { OID id-sha1 PARAMETERS NULL   }|
    #       { OID id-sha256 PARAMETERS NULL }|
    #       { OID id-sha384 PARAMETERS NULL }|
    #       { OID id-sha512 PARAMETERS NULL }
    #   }
    #
    digestAlgo  = DerSequence([hash.oid, DerNull().encode()])
    digest      = DerOctetString(hash.digest())
    digestInfo  = DerSequence([
                    digestAlgo.encode(),
                    digest.encode()
                    ]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding).
    if emLen<len(digestInfo)+11:
            raise ValueError("Selected hash algorith has a too long digest (%d bytes)." % len(digest))
    PS = "\xFF" * (emLen - len(digestInfo) - 3)
    return "\x00" + "\x01" + PS + "\x00" + digestInfo

