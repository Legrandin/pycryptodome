# -*- coding: utf-8 -*-
#
#  Cipher/PKCS1_OAEP.py : PKCS#1 OAEP
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

"""RSA encryption protocol according to PKCS#1 OAEP

See RFC3447__ or the `original RSA Labs specification`__ .

This scheme is more properly called ``RSAES-OAEP``.

As an example, a sender may encrypt a message in this way:

        >>> from Crypto.Cipher import PKCS1_OAEP
        >>> from Crypto.PublicKey import RSA
        >>>
        >>> message = 'To be encrypted'
        >>> key = RSA.importKey(open('pubkey.der').read())
        >>> ciphertext = PKCS1_OAEP.encrypt(message, key)

At the receiver side, decryption can be done using the private part of
the RSA key:

        >>> key = RSA.importKey(open('privkey.der').read())
        >>> message = PKCS1_OAEP.decrypt(ciphertext, key):

:undocumented: __revision__, __package__

.. __: http://www.ietf.org/rfc/rfc3447.txt
.. __: http://www.rsa.com/rsalabs/node.asp?id=2125.
"""

from __future__ import nested_scopes

__revision__ = "$Id$"
__all__ = [ 'encrypt', 'decrypt' ]

import Crypto.Signature.PKCS1_PSS
import Crypto.Hash.SHA

import Crypto.Util.number
from   Crypto.Util.number import ceil_div
from   Crypto.Util.strxor import strxor

def encrypt(message, key, hashAlgo=None, mgfunc=None, label=''):
    """Produce the PKCS#1 OAEP encryption of a message.

    This function is named ``RSAES-OAEP-ENCRYPT``, and is specified in
    section 7.1.1 of RFC3447.

    :Parameters:
     message : string
            The message to encrypt, also known as plaintext. It can be of
            variable length, but not longer than the RSA modulus (in bytes)
            minus 2, minus twice the hash output size.
     key : RSA key object
            The key to use to encrypt the message. This is a `Crypto.PublicKey.RSA`
            object.
     hashAlgo : hash object
            The hash function to use. This can be a module under `Crypto.Hash`
            or an existing hash object created from any of such modules. If not specified,
            `Crypto.Hash.SHA` (that is, SHA-1) is used.
     mgfunc : callable
            A mask generation function that accepts two parameters: a string to
            use as seed, and the lenth of the mask to generate, in bytes.
            If not specified, the standard MGF1 is used (a safe choice).
     label : string
            A label to apply to this particular encryption. If not specified,
            an empty string is used. Specifying a label does not improve
            security.

    :Return: A string, the ciphertext in which the message is encrypted.
        It is as long as the RSA modulus (in bytes).
    :Raise ValueError:
        If the RSA key length is not sufficiently long to deal with the given
        message.

    :attention: Modify the mask generation function only if you know what you are doing.
                The receiver must use the same one too.
    """
    # TODO: Verify the key is RSA

    randFunc = key._randfunc

    # See 7.1.1 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes
    if hashAlgo:
        hashObj = hashAlgo
    else:
        hashObj = Crypto.Hash.SHA
    hLen = hashObj.digest_size
    mLen = len(message)
    if mgfunc:
        mgf = mgfunc
    else:
        mgf = lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,hashObj)

    # Step 1b
    ps_len = k-mLen-2*hLen-2
    if ps_len<0:
        raise ValueError("Plaintext is too long.")
    # Step 2a
    lHash = hashObj.new(label).digest()
    # Step 2b
    ps = '\x00'*ps_len
    # Step 2c
    db = lHash + ps + '\x01' + message
    # Step 2d
    ros = randFunc(hLen)
    # Step 2e
    dbMask = mgf(ros, k-hLen-1)
    # Step 2f
    maskedDB = strxor(db, dbMask)
    # Step 2g
    seedMask = mgf(maskedDB, hLen)
    # Step 2h
    maskedSeed = strxor(ros, seedMask)
    # Step 2i
    em = '\x00' + maskedSeed + maskedDB
    # Step 3a (OS2IP), step 3b (RSAEP), part of step 3c (I2OSP)
    m = key.encrypt(em, 0)[0]
    # Complete step 3c (I2OSP)
    c = '\x00'*(k-len(m)) + m
    return c

def decrypt(ct, key, hashAlgo=None, mgfunc=None, label=''):
    """Decrypt a PKCS#1 OAEP ciphertext.

    This function is named ``RSAES-OAEP-DECRYPT``, and is specified in
    section 7.1.2 of RFC3447.

    :Parameters:
     ct : string
            The ciphertext that contains the message to recover.
     key : RSA key object
            The key to use to verify the message. This is a `Crypto.PublicKey.RSA`
            object. It must have its private half.
     hashAlgo : hash object
            The hash function to use. This can be a module under `Crypto.Hash`
            or an existing hash object created from any of such modules.
            If not specified, `Crypto.Hash.SHA` (that is, SHA-1) is used.
     mgfunc : callable
            A mask generation function that accepts two parameters: a string to
            use as seed, and the lenth of the mask to generate, in bytes.
            If not specified, the standard MGF1 is used. The sender must have
            used the same function.
     label : string
            A label to apply to this particular encryption. If not specified,
            an empty string is used. The sender must have used the same label.

    :Return: A string, the original message.
    :Raise ValueError:
        If the ciphertext length is incorrect, or if the decryption does not
        succeed.
    :Raise TypeError:
        If the RSA key has no private half.
    """
    # TODO: Verify the key is RSA

    # See 7.1.2 in RFC3447
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes
    if hashAlgo:
        hashObj = hashAlgo
    else:
        hashObj = Crypto.Hash.SHA
    hLen = hashObj.digest_size
    if mgfunc:
        mgf = mgfunc
    else:
        mgf = lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,hashObj)

    # Step 1b and 1c
    if len(ct) != k or k<hLen+2:
        raise ValueError("Ciphertext with incorrect length.")
    # Step 2a (O2SIP), 2b (RSADP), and part of 2c (I2OSP)
    m = key.decrypt(ct)
    # Complete step 2c (I2OSP)
    em = '\x00'*(k-len(m)) + m
    # Step 3a
    lHash = hashObj.new(label).digest()
    # Step 3b
    y = em[0]
    # y must be 0, but we MUST NOT check it here in order not to
    # allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]
    # Step 3c
    seedMask = mgf(maskedDB, hLen)
    # Step 3d
    seed = strxor(maskedSeed, seedMask)
    # Step 3e
    dbMask = mgf(seed, k-hLen-1)
    # Step 3f
    db = strxor(maskedDB, dbMask)
    # Step 3g
    valid = 1
    one = db[hLen:].find('\x01')
    lHash1 = db[:hLen]
    if lHash1!=lHash:
        valid = 0
    if one<0:
        valid = 0
    if y!='\x00':
        valid = 0
    if not valid:
        raise ValueError("Incorrect decryption.")
    # Step 4
    return db[hLen+one+1:]

