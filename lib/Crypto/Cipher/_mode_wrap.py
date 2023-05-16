# ===================================================================
#
# Copyright (c) 2023, James Edington <james.edington@uah.edu>
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

"""
NIST SP800-38F Key Wrap mode.
"""

__all__ = ['WrapMode']

from Crypto.Util.number import long_to_bytes
from Crypto.Util.py3compat import _copy_bytes
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes

class WrapMode(object):
    """Key Wrap mode.

    This mode is a historic authenticated construction
    mainly used in S/MIME and PKCS#7 applications.

    See `NIST SP800-38F`_ , Section 6 .

    .. _`NIST SP800-38F` : https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf

    :undocumented: __init__
    """

    def __init__(self, factory, key, icv, cipher_params):
        self.block_size = factory.block_size
        self.key_size = factory.block_size // 2
        self._icv = _copy_bytes(None, None, icv)

        if len(self._icv) != (self.key_size):
            raise ValueError("Length of ICV must be %d"
                             " for MODE_WRAP"
                             % (self.key_size, ))

        # Instantiate the underlying ECB cipher
        self._cipher = factory.new(
                            key,
                            factory.MODE_ECB,
                            **cipher_params)

        self._done = False  # True after the first encryption

    def encrypt(self, plaintext):
        """Encrypt (wrap) a key with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a key
        you cannot encrypt (or decrypt) another key using the same
        object.

        The data to encrypt cannot be broken up in two or
        more pieces; `encrypt` can only be called once.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The key to encrypt.

        :Return:
            the encrypted key, as a byte string.
            It is exactly 8 bytes longer than *plaintext*.
        """

        klen = self.key_size

        if len(plaintext) % klen != 0:
            raise ValueError("MODE_WRAP used with a key that needs padding (consider MODE_WRAP_PADDED)")

        if self._done:
            raise TypeError("cannot wrap multiple keys with the same cipher")

        A = self._icv
        R = bytearray(_copy_bytes(None, None, plaintext))
        n = len(plaintext) // klen
        ctr = 0
        for j in range(6):
            for i in range(n):
                ctr += 1
                B = self._cipher.encrypt(A + R[i*klen:(i+1)*klen])
                A, R[i*klen:(i+1)*klen] = strxor(B[:klen], long_to_bytes(ctr, klen)), B[klen:]

        self._done = True
        return A + R

    def decrypt(self, ciphertext):
        """Decrypt wrapped key with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a key
        you cannot decrypt (or encrypt) another key using the same
        object.

        The data to decrypt cannot be broken up in two or
        more pieces; `decrypt` can only be called once.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The piece of data to decrypt.

        :Return: the decrypted key (byte string).
        :Raises ValueError:
            if the ICV does not match. The message has been tampered with
            or the kek is incorrect.
        """

        klen = self.key_size

        if len(ciphertext) % l != 0:
            raise ValueError("bad key length for MODE_WRAP")

        if self._done:
            raise TypeError("cannot unwrap multiple keys with the same cipher")

        A = _copy_bytes(None, klen, ciphertext)
        R = bytearray(_copy_bytes(klen, None, ciphertext))
        n = len(ciphertext) // klen - 1
        ctr = 6*n
        for j in reversed(range(6)):
            for i in reversed(range(n)):
                B = self._cipher.decrypt(strxor(A, long_to_bytes(ctr, klen)) + R[i*klen:(i+1)*klen])
                A, R[i*klen:(i+1)*klen] = B[:klen], B[klen:]
                ctr -= 1

        if A != self._icv:
            raise ValueError("integrity check failed")

        self._done = True
        return _copy_bytes(None, None, R)


def _create_wrap_cipher(factory, **kwargs):
    """Create a new block cipher, configured in Key Wrap mode.

    :Parameters:
      factory : module
        The module.

    :Keywords:
      key : bytes/bytearray/memoryview
        The secret key to use in the symmetric cipher.

      icv : bytes/bytearray/memoryview
        The "Integrity Check Value" to use.
    """

    icv = kwargs.pop("icv", b'\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6')

    try:
        key = kwargs.pop("key")
    except KeyError as e:
        raise TypeError("Missing component: " + str(e))

    return WrapMode(factory, key, icv, kwargs)
