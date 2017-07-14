#
#  Util/PEM.py : Privacy Enhanced Mail utilities
#
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

"""Set of functions for encapsulating data according to the PEM format.

PEM (Privacy Enhanced Mail) was an IETF standard for securing emails via a
Public Key Infrastructure. It is specified in RFC 1421-1424.

Even though it has been abandoned, the simple message encapsulation it defined
is still widely used today for encoding *binary* cryptographic objects like
keys and certificates into text.
"""

__all__ = ['encode', 'decode']

from Crypto.Util.py3compat import b, hexlify, unhexlify, tobytes, tostr

import re
from binascii import a2b_base64, b2a_base64

from Crypto.Hash import MD5
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, DES3, AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Random import get_random_bytes


def encode(data, marker, passphrase=None, randfunc=None, algo=None):
    """Encode a piece of binary data into PEM format.

    :Parameters:
      data : byte string
        The piece of binary data to encode.
      marker : string
        The marker for the PEM block (e.g. "PUBLIC KEY").
        Note that there is no official master list for all allowed markers.
        Still, you can refer to the OpenSSL_ source code.
      passphrase : byte string
        If given, the PEM block will be encrypted. The key is derived from
        the passphrase.
      randfunc : callable
        Random number generation function; it accepts an integer N and returns
        a byte string of random data, N bytes long. If not given, a new one is
        instantiated.
      algo: string
        The encryption algorithm
    :Returns:
      The PEM block, as a string.

    .. _OpenSSL: http://cvs.openssl.org/fileview?f=openssl/crypto/pem/pem.h&v=1.66.2.1.4.2
    """

    if randfunc is None:
        randfunc = get_random_bytes

    out = "-----BEGIN %s-----\n" % marker
    if passphrase:
        if (algo is None):
            algo = "AES-256-CBC"

        salt = randfunc(16)
        if algo == "DES-CBC":
            key = PBKDF1(passphrase, salt[:8], 8, 1, MD5)
            objenc = DES.new(key, DES.MODE_CBC, salt)
        elif (algo == "DES-EDE3-CBC"):
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
            objenc = DES3.new(key, DES3.MODE_CBC, salt)
        elif (algo == "AES-128-CBC"):
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            objenc = AES.new(key, AES.MODE_CBC, salt)
        elif (algo == "AES-192-CBC"):
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt[:8], 8, 1, MD5)
            objenc = AES.new(key, AES.MODE_CBC, salt)
        elif (algo == "AES-256-CBC"):
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt[:8], 16, 1, MD5)
            objenc = AES.new(key, AES.MODE_CBC, salt)
        else:
            raise ValueError("Unsupport PEM encryption algorithm (%s)." % algo)

        out += "Proc-Type: 4,ENCRYPTED\nDEK-Info: %s,%s\n\n" %\
            (algo, tostr(hexlify(salt).upper()))

        # Encrypt with PKCS#7 padding
        data = objenc.encrypt(pad(data, objenc.block_size))
    elif passphrase is not None:
        raise ValueError("Empty password")

    # Each BASE64 line can take up to 64 characters (=48 bytes of data)
    # b2a_base64 adds a new line character!
    chunks = [tostr(b2a_base64(data[i:i + 48]))
              for i in range(0, len(data), 48)]
    out += "".join(chunks)
    out += "-----END %s-----" % marker
    return out


def decode(pem_data, passphrase=None):
    """Decode a PEM block into binary.

    :Parameters:
      pem_data : string
        The PEM block.
      passphrase : byte string
        If given and the PEM block is encrypted,
        the key will be derived from the passphrase.
    :Returns:
      A tuple with the binary data, the marker string, and a boolean to
      indicate if decryption was performed.
    :Raises ValueError:
      If decoding fails, if the PEM file is encrypted and no passphrase has
      been provided or if the passphrase is incorrect.
    """

    # Verify Pre-Encapsulation Boundary
    r = re.compile("\s*-----BEGIN (.*)-----\s+")
    m = r.match(pem_data)
    if not m:
        raise ValueError("Not a valid PEM pre boundary")
    marker = m.group(1)

    # Verify Post-Encapsulation Boundary
    r = re.compile("-----END (.*)-----\s*$")
    m = r.search(pem_data)
    if not m or m.group(1) != marker:
        raise ValueError("Not a valid PEM post boundary")

    # Removes spaces and slit on lines
    lines = pem_data.replace(" ", '').split()

    # Decrypts, if necessary
    if lines[1].startswith('Proc-Type:4,ENCRYPTED'):
        if not passphrase:
            raise ValueError("PEM is encrypted, but no passphrase available")
        DEK = lines[2].split(':')
        if len(DEK) != 2 or DEK[0] != 'DEK-Info':
            raise ValueError("PEM encryption format not supported.")
        algo, salt = DEK[1].split(',')
        salt = unhexlify(tobytes(salt))
        if algo == "DES-CBC":
            # This is EVP_BytesToKey in OpenSSL
            key = PBKDF1(passphrase, salt, 8, 1, MD5)
            objdec = DES.new(key, DES.MODE_CBC, salt)
        elif algo == "DES-EDE3-CBC":
            # Note that EVP_BytesToKey is note exactly the same as PBKDF1
            key = PBKDF1(passphrase, salt, 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
            objdec = DES3.new(key, DES3.MODE_CBC, salt)
        elif algo == "AES-128-CBC":
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            objdec = AES.new(key, AES.MODE_CBC, salt)
        elif algo == "AES-192-CBC":
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt[:8], 8, 1, MD5)
            objdec = AES.new(key, AES.MODE_CBC, salt)
        elif algo == "AES-256-CBC":
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt[:8], 16, 1, MD5)
            objdec = AES.new(key, AES.MODE_CBC, salt)
        else:
            raise ValueError("Unsupport PEM encryption algorithm (%s)." % algo)
        lines = lines[2:]
    else:
        objdec = None

    # Decode body
    data = a2b_base64(b(''.join(lines[1:-1])))
    enc_flag = False
    if objdec:
        data = unpad(objdec.decrypt(data), objdec.block_size)
        enc_flag = True

    return (data, marker, enc_flag)
