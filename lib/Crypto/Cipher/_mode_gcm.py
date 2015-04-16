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

"""
Galois/Counter Mode (GCM).
"""

__all__ = ['GcmMode']

from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import *

from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash.CMAC import _SmoothMAC
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer,
                                  create_string_buffer, get_raw_buffer,
                                  SmartPointer, c_size_t, expect_byte_string)

_raw_galois_lib = load_pycryptodome_raw_lib("Crypto.Util._galois",
                    """
                    int ghash(  uint8_t y_out[16],
                                const uint8_t block_data[],
                                size_t len,
                                const uint8_t y_in[16],
                                const void *exp_key);
                    int ghash_expand(const uint8_t h[16],
                                     void **ghash_tables);
                    int ghash_destroy(void *ghash_tables);
                    """)

class _GHASH(_SmoothMAC):
    """GHASH function defined in NIST SP 800-38D, Algorithm 2.

    If X_1, X_2, .. X_m are the blocks of input data, the function
    computes:

       X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H

    in the Galois field GF(2^256) using the reducing polynomial
    (x^128 + x^7 + x^2 + x + 1).
    """

    def __init__(self, hash_subkey, block_size):
        _SmoothMAC.__init__(self, block_size, None, 0)

        self._key = hash_subkey
        self._exp_key = VoidPointer()
        expect_byte_string(self._key)
        result = _raw_galois_lib.ghash_expand(self._key,
                                              self._exp_key.address_of())
        if result:
            raise ValueError("Error %d while expanding the GMAC key" % result)
        self._exp_key = SmartPointer(self._exp_key.get(),
                                     _raw_galois_lib.ghash_destroy)

        self._last_y = create_string_buffer(16)
        for i in xrange(16):
            self._last_y[i] = bchr(0)
        self._mac = _raw_galois_lib.ghash

    def copy(self):
        clone = _GHASH(self._key, self._bs)
        _SmoothMAC._deep_copy(self, clone)
        clone._last_y = self._last_y
        return clone

    def _update(self, block_data):
        expect_byte_string(block_data)
        result = _raw_galois_lib.ghash(self._last_y,
                                       block_data,
                                       c_size_t(len(block_data)),
                                       self._last_y,
                                       self._exp_key.get())
        if result:
            raise ValueError("Error %d while updating GMAC" % result)

    def _digest(self, left_data):
        return get_raw_buffer(self._last_y)


class GcmMode(object):
    """Galois Counter Mode (GCM).

    This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
    It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed, and it will
    still be subject to authentication. The decryption step tells the receiver
    if the message comes from a source that really knowns the secret key.
    Additionally, decryption detects if any part of the message - including the
    header - has been modified or corrupted.

    This mode requires a *nonce*.

    This mode is only available for ciphers that operate on 128 bits blocks
    (e.g. AES but not TDES).

    See `NIST SP800-38D`_.

    .. _`NIST SP800-38D`: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    """

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in
        Galois Counter Mode (GCM).

        :Parameters:
          factory : module
            A block cipher module, taken from `Crypto.Cipher`.
            The cipher must have block length of 16 bytes.
            GCM has been only defined for `Crypto.Cipher.AES`.

        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.
            It must be 16 (e.g. *AES-128*), 24 (e.g. *AES-192*)
            or 32 (e.g. *AES-256*) bytes long.

          nonce : byte string
            A mandatory value that must never be reused for any other encryption.

            There are no restrictions on its length,
            but it is recommended to use at least 16 bytes.

            The nonce shall never repeat for two
            different messages encrypted with the same key,
            but it does not need to be random.

          mac_len : integer
            Length of the MAC, in bytes.
            It must be no larger than 16 bytes (which is the default).
        """

        self.block_size = factory.block_size
        if self.block_size != 16:
            raise ValueError("GCM mode is only available for ciphers"
                             " that operate on 128 bits blocks")

        self._factory = factory
        try:
            self._key = key = kwargs.pop("key")
            nonce = kwargs.pop("nonce")
        except KeyError, e:
            raise TypeError("Missing parameter:" + str(e))
        self._mac_len = kwargs.pop("mac_len", 16)

        self._tag = None  ## Cache for MAC tag

        # MAC tag length
        if not (4 <= self._mac_len <= 16):
            raise ValueError("Parameter 'mac_len' must not be larger"
                             " than 16 bytes")

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        self._no_more_assoc_data = False

        # Length of the ciphertext or plaintext
        self._msg_len = 0

        # Step 1 in SP800-38D, Algorithm 4 (encryption) - Compute H
        # See also Algorithm 5 (decryption)
        hash_subkey = factory.new(key,
                                  self._factory.MODE_ECB,
                                  **kwargs
                                  ).encrypt(bchr(0) * 16)

        # Step 2 - Compute J0 (integer, not byte string!)
        if len(nonce) == 12:
            self._j0 = bytes_to_long(nonce + b("\x00\x00\x00\x01"))
        else:
            fill = (16 - (len(nonce) % 16)) % 16 + 8
            ghash_in = (nonce +
                        bchr(0) * fill +
                        long_to_bytes(8 * len(nonce), 8))
            mac = _GHASH(hash_subkey, factory.block_size)
            mac.update(ghash_in)
            self._j0 = bytes_to_long(mac.digest())
            del mac

        # Step 3 - Prepare GCTR cipher for encryption/decryption
        ctr = Counter.new(128, initial_value=self._j0 + 1)
        self._cipher = factory.new(key,
                                   self._factory.MODE_CTR,
                                   counter=ctr,
                                   **kwargs)

        # Step 5 - Bootstrat GHASH
        self._signer = _GHASH(hash_subkey, factory.block_size)

        # Step 6 - Prepare GCTR cipher for GMAC
        ctr = Counter.new(128, initial_value=self._j0)
        self._tag_cipher = factory.new(key,
                                       self._factory.MODE_CTR,
                                       counter=ctr,
                                       **kwargs)

    def update(self, assoc_data):
        """Protect associated data

        If there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.
        In GCM, the *associated data* is also called
        *additional authenticated data* (AAD).

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : byte string
            A piece of associated data. There are no restrictions on its size.
        """

        if self.update not in self._next:
            raise TypeError("update() can only be called"
                                " immediately after initialization")

        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        return self._signer.update(assoc_data)

    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        The data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
            It can be of any length.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        if self.encrypt not in self._next:
            raise TypeError("encrypt() can only be called after"
                            " initialization or an update()")
        self._next = [self.encrypt, self.digest]

        ciphertext = self._cipher.encrypt(plaintext)

        if not self._no_more_assoc_data:
            # The authenticated data A is concatenated to the minimum
            # number of zero bytes (possibly none) such that the
            # ciphertext C is aligned to the 16 byte boundary.
            # See step 5 in section 7.1
            self._signer.zero_pad()
            self._no_more_assoc_data = True

        self._signer.update(ciphertext)
        self._msg_len += len(plaintext)

        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        The data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        This function does not remove any padding from the plaintext.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
            It can be of any length.

        :Return: the decrypted data (byte string).
        """

        if self.decrypt not in self._next:
            raise TypeError("decrypt() can only be called"
                            " after initialization or an update()")
        self._next = [self.decrypt, self.verify]

        if not self._no_more_assoc_data:
            # The authenticated data A is concatenated to the minimum
            # number of zero bytes (possibly none) such that the
            # ciphertext C is aligned to the 16 byte boundary.
            # See step 6 in section 7.2
            self._signer.zero_pad()
            self._no_more_assoc_data = True

        self._signer.update(ciphertext)
        self._msg_len += len(ciphertext)

        return self._cipher.decrypt(ciphertext)

    def digest(self):
        """Compute the *binary* MAC tag in an AEAD mode.

        The caller invokes this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        :Return: the MAC, as a byte string.
        """

        if self.digest not in self._next:
            raise TypeError("digest() cannot be called when decrypting"
                                " or validating a message")
        self._next = [self.digest]

        return self._compute_mac()

    def _compute_mac(self):
        """Compute MAC without any FSM checks."""

        if self._tag:
            return self._tag

        # Step 5 in NIST SP 800-38D, Algorithm 4 - Compute S
        self._signer.zero_pad()
        auth_len = self._signer.data_signed_so_far() - self._msg_len
        self._signer.update(long_to_bytes(8 * auth_len, 8))
        self._signer.update(long_to_bytes(8 * self._msg_len, 8))
        s_tag = self._signer.digest()

        # Step 6 - Compute T
        self._tag = self._tag_cipher.encrypt(s_tag)[:self._mac_len]

        return self._tag

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
          received_mac_tag : byte string
            This is the *binary* MAC, as received from the sender.
        :Raises ValueError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if self.verify not in self._next:
            raise TypeError("verify() cannot be called"
                            " when encrypting a message")
        self._next = [self.verify]

        secret = get_random_bytes(16)

        mac1 = BLAKE2s.new(digest_bits=160, key=secret, data=self._compute_mac())
        mac2 = BLAKE2s.new(digest_bits=160, key=secret, data=received_mac_tag)

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
          plaintext : byte string
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
          ciphertext : byte string
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


def _create_gcm_cipher(factory, **kwargs):
    return GcmMode(factory, **kwargs)
