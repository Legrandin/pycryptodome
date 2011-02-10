# -*- coding: utf-8 -*-
#
#  Cipher/PKCS1-v1_5.py : PKCS#1 v1.5
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

"""RSA encryption protocol according to PKCS#1 v1.5

See RFC3447 or the original RSA Labs specification at
http://www.rsa.com/rsalabs/node.asp?id=2125.

This scheme is more properly called ``RSAES-PKCS1-v1_5``.

As an example, a sender may encrypt a message in this way:

        >>> from Crypto.Cipher import PKCS1_v1_5
        >>> from Crypto.PublicKey import RSA
        >>> from Crypto import Random
        >>>
        >>> message = 'To be encrypted'
        >>> key = RSA.importKey('pubkey.der')
        >>> rng = Random.new().read
        >>> ciphertext = PKCS1_v1_5.encrypt(message, key, rng)

At the receiver side, decryption can be done using the private part of
the RSA key:

        >>> key = RSA.importKey('privkey.der')
        >>> message = PKCS1_v1_5.decrypt(ciphertext):
"""

__revision__ = "$Id$"
__all__ = [ 'encrypt', 'decrypt' ]

from Crypto.Util.number import ceil_div
import Crypto.Util.number

def encrypt(message, key, randFunc):
    """Produce the PKCS#1 v1.5 encryption of a message.

    This function is named ``RSAES-PKCS1-V1_5-ENCRYPT``, and is specified in
    section 7.2.1 of RFC3447.

    :Parameters:
     message : string
            The message to encrypt, also known as plaintext. It can be of
            variable length, but not longer than the RSA modulus (in bytes) minus 11.
     key : RSA key object
            The key to use to encrypt the message. This is a `Crypto.PublicKey.RSA`
            object.
     randFunc : callable
            An RNG function that accepts as only parameter an integer, and returns
            a string of random bytes.

    :Return: A string, the ciphertext in which the message is encrypted.
        It is as long as the RSA modulus (in bytes).
    :Raise ValueError:
        If the RSA key length is not sufficiently long to deal with the given
        message.
    """
    # TODO: Verify the key is RSA

    # See 7.2.1 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes
    mLen = len(message)

    # Step 1
    if mLen > k-11:
        raise ValueError("Plaintext is too long.")
    # Step 2a
    class nonZeroRandByte:
        def __init__(self, rf): self.rf=rf
        def __call__(self, c):
            while c=='\x00': c=self.rf(1)
            return c
    ps = "".join(map(nonZeroRandByte(randFunc), randFunc(k-mLen-3)))
    # Step 2b
    em = '\x00\x02' + ps + '\x00' + message
    # Step 3a (OS2IP), step 3b (RSAEP), part of step 3c (I2OSP)
    m = key.encrypt(em, 0)[0]
    # Complete step 3c (I2OSP)
    c = '\x00'*(k-len(m)) + m
    return c

def decrypt(ct, key):
    """Decrypt a PKCS#1 v1.5 ciphertext.

    This function is named ``RSAES-PKCS1-V1_5-DECRYPT``, and is specified in
    section 7.2.2 of RFC3447.

    :Parameters:
     ct : string
            The ciphertext that contains the message to recover.
     key : RSA key object
            The key to use to verify the message. This is a `Crypto.PublicKey.RSA`
            object. It must have its private half.

    :Return: A string, the original message.
    :Raise ValueError:
        If the ciphertext length is incorrect, or if the encryption does not
        succeed.
    :Raise TypeError:
        If the RSA key has no private half.
    """
    # TODO: Verify the key is RSA

    # See 7.2.1 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes

    # Step 1
    if len(ct) != k:
        raise ValueError("Ciphertext with incorrect length.")
    # Step 2a (O2SIP), 2b (RSADP), and part of 2c (I2OSP)
    m = key.decrypt(ct)
    # Complete step 2c (I2OSP)
    em = '\x00'*(k-len(m)) + m
    # Step 3
    sep = em.find('\x00',2)
    #print "sep=", sep
    if  not em.startswith('\x00\x02') or sep<10:
        raise ValueError("Incorrect decryption.")
    # Step 4
    return em[sep+1:]

