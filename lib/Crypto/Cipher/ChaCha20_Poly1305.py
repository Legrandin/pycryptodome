# ===================================================================
#
# Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
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

from binascii import unhexlify

from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305, BLAKE2s

from Crypto.Random import get_random_bytes

from Crypto.Util.number import long_to_bytes
from Crypto.Util.py3compat import _copy_bytes, bord


def _enum(**enums):
    return type('Enum', (), enums)


_CipherStatus = _enum(PROCESSING_AUTH_DATA=1,
                      PROCESSING_CIPHERTEXT=2,
                      PROCESSING_DONE=3)


class ChaCha20Poly1305Cipher(object):
    """ChaCha20-Poly1305 cipher object.
    Do not create it directly. Use :py:func:`new` instead.

    :var nonce: The nonce with length 8 or 12
    :vartype nonce: byte string
    """

    def __init__(self, key, nonce):
        """Initialize a ChaCha20-Poly1305 AEAD cipher object

        See also `new()` at the module level."""

        self.nonce = _copy_bytes(None, None, nonce)

        self._next = (self.update, self.encrypt, self.decrypt, self.digest,
                      self.verify)

        self._authenticator = Poly1305.new(key=key, nonce=nonce, cipher=ChaCha20)
        
        self._cipher = ChaCha20.new(key=key, nonce=nonce)
        self._cipher.seek(64)   # Block counter starts at 1

        self._len_aad = 0
        self._len_ct = 0
        self._mac_tag = None
        self._status = _CipherStatus.PROCESSING_AUTH_DATA

    def update(self, data):

        if self.update not in self._next:
            raise TypeError("update() method cannot be called")

        self._len_aad += len(data)
        self._authenticator.update(data)

    def _pad_aad(self):

        assert(self._status == _CipherStatus.PROCESSING_AUTH_DATA)
        if self._len_aad & 0x0F:
            self._authenticator.update(b'\x00' * (16 - (self._len_aad & 0x0F)))
        self._status = _CipherStatus.PROCESSING_CIPHERTEXT

    def encrypt(self, plaintext):
        """Encrypt a piece of data.

        :param plaintext: The data to encrypt, of any size.
        :type plaintext: bytes, bytearray, memoryview
        :returns: the encrypted byte string, of equal length as the
          plaintext.
        """

        if self.encrypt not in self._next:
            raise TypeError("encrypt() method cannot be called")

        if self._status == _CipherStatus.PROCESSING_AUTH_DATA:
            self._pad_aad()

        self._next = (self.encrypt, self.digest)

        result = self._cipher.encrypt(plaintext)
        self._len_ct += len(result)
        self._authenticator.update(result)
        return result

    def decrypt(self, ciphertext):
        """Decrypt a piece of data.

        :param ciphertext: The data to decrypt, of any size.
        :type ciphertext: bytes, bytearray, memoryview
        :returns: the decrypted byte string, of equal length as the
          ciphertext.
        """
        
        if self.decrypt not in self._next:
            raise TypeError("decrypt() method cannot be called")
        
        if self._status == _CipherStatus.PROCESSING_AUTH_DATA:
            self._pad_aad()

        self._next = (self.decrypt, self.verify)

        self._len_ct += len(ciphertext)
        self._authenticator.update(ciphertext)
        return self._cipher.decrypt(ciphertext)
    
    def _compute_mac(self):
        """Finalize the cipher (if not done already and return the MAC"""

        if self._mac_tag:
            assert(self._status == _CipherStatus.PROCESSING_DONE)
            return self._mac_tag

        assert(self._status != _CipherStatus.PROCESSING_DONE)
        
        if self._status == _CipherStatus.PROCESSING_AUTH_DATA:
            self._pad_aad()

        if self._len_ct & 0x0F:
            self._authenticator.update(b'\x00' * (16 - (self._len_ct & 0x0F)))
        
        self._status = _CipherStatus.PROCESSING_DONE
        
        self._authenticator.update(long_to_bytes(self._len_aad, 8)[::-1])
        self._authenticator.update(long_to_bytes(self._len_ct, 8)[::-1])
        self._mac_tag = self._authenticator.digest()
        return self._mac_tag
 
    def digest(self):

        if self.digest not in self._next:
            raise TypeError("digest() method cannot be called")
        self._next = (self.digest,)
        
        return self._compute_mac()
    
    def hexdigest(self):
        """Compute the *printable* MAC tag.

        This method is like `digest`.

        :Return: the MAC, as a hexadecimal string.
        """
        return "".join(["%02x" % bord(x) for x in self.digest()])

    def verify(self, received_mac_tag):
        """Validate the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method checks if the decrypted message is indeed valid
        (that is, if the key is correct) and it has not been
        tampered with while in transit.

        :Parameters:
          received_mac_tag : bytes/bytearray/memoryview
            This is the *binary* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if self.verify not in self._next:
            raise TypeError("verify() cannot be called"
                            " when encrypting a message")
        self._next = (self.verify,)

        secret = get_random_bytes(16)

        self._compute_mac()

        mac1 = BLAKE2s.new(digest_bits=160, key=secret,
                           data=self._mac_tag)
        mac2 = BLAKE2s.new(digest_bits=160, key=secret,
                           data=received_mac_tag)

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Validate the *printable* MAC tag.

        This method is like `verify`.

        :Parameters:
          hex_mac_tag : string
            This is the *printable* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    def encrypt_and_digest(self, plaintext):
        """Perform encrypt() and digest() in one step.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The piece of data to encrypt.
        :Return:
            a tuple with two byte strings:

            - the encrypted data
            - the MAC
        """

        return self.encrypt(plaintext), self.digest()

    def decrypt_and_verify(self, ciphertext, received_mac_tag):
        """Perform decrypt() and verify() in one step.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The piece of data to decrypt.
          received_mac_tag : byte string
            This is the *binary* MAC, as received from the sender.

        :Return: the decrypted data (byte string).
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        plaintext = self.decrypt(ciphertext)
        self.verify(received_mac_tag)
        return plaintext


def new(**kwargs):
    """Create a new ChaCha20-Poly1305 AEAD cipher

    :keyword key: The secret key to use. It must be 32 bytes long.
    :type key: byte string

    :keyword nonce:
        A value that must never be reused for any other encryption
        done with this key. It must be 8 or 12 bytes long.

        If not provided, a random 12-byte string will be generated
        (you can read it back via the ``nonce`` attribute of the
        returned object).
    :type nonce: bytes, bytearray, memoryview

    :Return: a :class:`Crypto.Cipher.ChaCha20.ChaCha20Poly1305Cipher` object
    """

    try:
        key = kwargs.pop("key")
    except KeyError as e:
        raise TypeError("Missing parameter %s" % e)

        self._len_ct += len(plaintext)
    
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")

    nonce = kwargs.pop("nonce", None)
    if nonce is None:
        nonce = get_random_bytes(12)

    if len(nonce) not in (8, 12):
        raise ValueError("Nonce must be 8 or 12 bytes long")

    if isinstance(nonce, unicode):
        raise TypeError("nonce must be a byte string")

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    return ChaCha20Poly1305Cipher(key, nonce)


# Size of a key (in bytes)
key_size = 32
