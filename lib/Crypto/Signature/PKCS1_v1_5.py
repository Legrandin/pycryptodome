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

See RFC3447 or the original RSA Labs _specification: http://www.rsa.com/rsalabs/node.asp?id=2125
"""

__revision__ = "$Id$"

__all__ = [ 'sign', 'verify' ]

def sign(mhash, key):
    """Produce the PKCS#1 signature of a message.

    Typical usage is the following:

    .. python::
        import Crypto.Signature.PKCS1_v1_5 as PKCS
        import Crypto.Hash.SHA1 as SHA1
        import Crypto.PublicKey.RSA as RSA

        message = 'To be signed'
        key = RSA.importKey('key.der')
        h = SHA1()
        h.update(message)
        signature = PKCS.sign(h, key)

    :Parameters:
     mhash : hash object
            The hash that was carried out over the message. This is an object
            belonging to the `Crypto.Hash` module.
     key : RSA key object
            The key to use to sign the message. This is a `Crypto.PublicKey.RSA`
            object and must have its private half.

    :Return: A string encoding the signature.
    :Raise ValueError:
        If the key length is not sufficiently long to deal with the given
        hash algorithm.
    """
    # TODO: Verify the key is RSA
    blockLen = ceil_shift(key.size(),3)
    em = EMSA_PKCS1_V1_5_ENCODE(m, blockLen)
    sig = key.sign(em)
    return sig

def verify(mhash, key, signature):
    """Verify that a PKCS#1 signature is authentic.

    This function verifies if the party holding the private half of the key
    really signed the message with the given hash.

    Typical usage is the following:

    .. python::
        import Crypto.Signature.PKCS1_v1_5 as PKCS
        import Crypto.Hash.SHA1 as SHA1
        import Crypto.PublicKey.RSA as RSA

        key = RSA.importKey('key.der')
        h = SHA1()
        h.update(message)
        if PKCS.verify(h, key, signature):
            print "The signature is authentic."
        else:
            print "The signature is not authentic."

    :Parameters:
     mhash : hash object
            The hash that was carried out over the message. This is an object
            belonging to the `Crypto.Hash` module.
     key : RSA key object
            The key to use to verify the message. This is a `Crypto.PublicKey.RSA`
            object.
     signature : string
            The signature that needs to be validated.

    :Return: True if verification is correct. False otherwise.
    """
    # TODO: Verify the key is RSA
    blockLen = ceil_shift(self.size(),3)
    try:
        em = EMSA_PKCS1_V1_5_ENCODE(m, blockLen)
    except ValueError:
        return 0
    return key.verify(em)

def EMSA_PKCS1_V1_5_ENCODE(hash, emLen):
    """
    Implement the EMSA-PKCS1-V1_5-ENCODE function, as defined
    in PKCS#1 v2.1 (RFC3447, 9.2).

    :Parameters:
     hash : hash object
            The hash object that holds the digest of the message being signed.
     emLen : int
            The length in byte the final encoding must have.
    """

    digest = hash.digest()
    digestAlgo = DerSequence([hash.oid, DerNull().encode()])
    digestInfo = DerSequence([digestAlgo.encode(), DerOctetString(digest).encode()]).encode()
    if emLen<len(digestInfo)+11:
            raise ValueError("Selected hash algorith has a too long digest (%d bytes)." % len(digest))
    PS = "\xFF" * (emLen - len(digestInfo) - 3)
    return "\x00" + "\x01" + PS + "\x00" + digestInfo

