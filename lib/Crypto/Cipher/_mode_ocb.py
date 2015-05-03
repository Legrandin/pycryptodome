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
Offset Codebook (OCB) mode.
"""

import struct
from binascii import unhexlify

from Crypto.Util.py3compat import b, bord, bchr
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor

from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer,
                                  create_string_buffer, get_raw_buffer,
                                  SmartPointer, c_size_t, expect_byte_string,
                                  null_pointer)

raw_ocb_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_ocb", """
                                    int OCB_start_operation(void *cipher,
                                        const uint8_t *offset_0,
                                        size_t offset_0_len,
                                        void **pState);
                                    int OCB_encrypt(void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                                    int OCB_decrypt(void *state,
                                        const uint8_t *in,
                                        uint8_t *out,
                                        size_t data_len);
                                    int OCB_update(void *state,
                                        const uint8_t *in,
                                        size_t data_len);
                                    int OCB_digest(void *state,
                                        uint8_t *tag,
                                        size_t tag_len);
                                    int OCB_stop_operation(void *state);
                                    """)

class OcbMode(object):
    """Offset Codebook (OCB) mode."""

    def __init__(self, factory, **kwargs):
        """Create a new block cipher, configured in OCB mode.

        :Parameters:
          factory : module
            A symmetric cipher module from `Crypto.Cipher`
            (like `Crypto.Cipher.AES`).

        :Keywords:
          key : byte string
            The secret key to use in the symmetric cipher.

          nonce : byte string
            A mandatory value that must never be reused for
            any other encryption. Its length can vary from
            1 to 15 bytes.

          mac_len : integer
            Length of the MAC, in bytes.
            It must be in the range ``[8..16]``.
            The default is 16 (128 bits).
        """

        if factory.block_size != 16:
            raise ValueError("OCB mode is only available for ciphers"
                             " that operate on 128 bits blocks")
        #: The block size of the underlying cipher, in bytes.
        self.block_size = factory.block_size

        try:
            key = kwargs.get("key")
            external_nonce = kwargs.pop("nonce")  # N
            self._mac_len = kwargs.pop("mac_len", 16)
        except KeyError, e:
            raise TypeError("Keyword missing: " + str(e))

        if len(external_nonce) not in range(1,16):
            raise ValueError("Nonce must be at most 15 bytes long")

        if not 8 <= self._mac_len <= 16:
            raise ValueError("MAC tag must be between 8 and 16 bytes long")
        #: Cache for MAC tag
        self._mac_tag = None

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        # Compute Offset_0
        ecb_cipher = factory.new(key, factory.MODE_ECB)
        nonce = bchr(self._mac_len << 4 & 0xFF) + \
                bchr(0) * (14 - len(external_nonce)) + bchr(1) + \
                external_nonce
        bottom = bord(nonce[15]) & 0x3F   # 6 bits, 0..63
        ktop = ecb_cipher.encrypt(nonce[:15] + bchr(bord(nonce[15]) & 0xC0))
        stretch = ktop + strxor(ktop[:8], ktop[1:9])    # 192 bits
        offset_0 = long_to_bytes(bytes_to_long(stretch) >> (64 - bottom), 24)[8:]

        # Create low-level cipher instance
        raw_cipher = factory._create_base_cipher(kwargs)
        if kwargs:
            raise TypeError("Unknown keywords: " + str(kwargs))

        self._state = VoidPointer()
        result = raw_ocb_lib.OCB_start_operation(raw_cipher.get(),
                                                 offset_0,
                                                 c_size_t(len(offset_0)),
                                                 self._state.address_of())
        if result:
            raise ValueError("Error %d while instantiating the OCB mode"
                             % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the cipher mode
        self._state = SmartPointer(self._state.get(),
                                   raw_ocb_lib.OCB_stop_operation)

        # Memory allocated for the underlying block cipher is now owed
        # by the cipher mode
        raw_cipher.release()

    def update(self, assoc_data):
        """Protect associated data

        If there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : byte string
            A piece of associated data.
        """

        if self.update not in self._next:
            raise TypeError("update() can only be called"
                            " immediately after initialization")

        self._next = [self.encrypt, self.decrypt, self.digest,
                      self.verify, self.update]

        expect_byte_string(assoc_data)
        result = raw_ocb_lib.OCB_update(self._state.get(),
                                        assoc_data,
                                        c_size_t(len(assoc_data)))

        if result:
            raise ValueError("Error %d while encrypting in OCB mode" % result)

    def encrypt(self, plaintext=None):
        """Encrypt the next piece of clear data.

        :Parameters:
          plaintext : byte string
            The next piece of data to encrypt or ``None`` to signify
            that encryption has finished and that any remaining ciphertext
            has to be produced.
        :Return:
            the ciphertext, as a byte string.
            Its length may not match the length of the *plaintext*.
        """

        if self.encrypt not in self._next:
            raise TypeError("encrypt() can only be called after"
                            " initialization or an update()")

        if plaintext is None:
            pt_len = 0
            self._next = [self.digest]
            plaintext = null_pointer
        else:
            pt_len = len(plaintext)
            self._next = [self.digest, self.encrypt]
            expect_byte_string(plaintext)

        ciphertext = create_string_buffer(pt_len + self.block_size)
        result = raw_ocb_lib.OCB_encrypt(self._state.get(),
                                         plaintext,
                                         ciphertext,
                                         c_size_t(pt_len))

        if result:
            raise ValueError("Error %d while encrypting in OCB mode" % result)

        ct_len = pt_len + struct.unpack('b', ciphertext[0])[0]
        return get_raw_buffer(ciphertext)[1:ct_len+1]

    def decrypt(self, ciphertext=None):
        """Decrypt the next piece of encrypted data.

        :Parameters:
          ciphertext : byte string
            The next piece of data to decrypt or ``None`` to signify
            that decryption has finished and that any remaining plaintext
            has to be produced.
        :Return:
            the plaintext, as a byte string.
            Its length may not match the length of the *ciphertext*.
        """

        if self.decrypt not in self._next:
            raise TypeError("decrypt() can only be called after"
                            " initialization or an update()")

        if ciphertext is None:
            ct_len = 0
            self._next = [self.digest]
            ciphertext = null_pointer
        else:
            ct_len = len(ciphertext)
            self._next = [self.digest, self.decrypt]
            expect_byte_string(ciphertext)

        plaintext = create_string_buffer(ct_len + self.block_size)
        result = raw_ocb_lib.OCB_decrypt(self._state.get(),
                                         ciphertext,
                                         plaintext,
                                         c_size_t(ct_len))

        if result:
            raise ValueError("Error %d while decrypting in OCB mode" % result)

        pt_len = ct_len + struct.unpack('b', plaintext[0])[0]
        return get_raw_buffer(plaintext)[1:pt_len+1]

    def digest(self):
        """Compute the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        :Return: the MAC, as a byte string.
        """

        if self.digest not in self._next:
            raise TypeError("digest() cannot be called when decrypting"
                            " or validating a message")
        self._next = [self.digest]

        if self._mac_tag is None:

            mac_tag = create_string_buffer(self.block_size)
            result = raw_ocb_lib.OCB_digest(self._state.get(),
                                            mac_tag,
                                            c_size_t(len(mac_tag))
                                            )
            if result:
                raise ValueError("Error %d while computing digest in OCB mode"
                                 % result)
            self._mac_tag = get_raw_buffer(mac_tag)[:self._mac_len]

        return self._mac_tag

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

        if self._mac_tag is None:

            mac_tag = create_string_buffer(self.block_size)
            result = raw_ocb_lib.OCB_digest(self._state.get(),
                                            mac_tag)
            if result:
                raise ValueError("Error %d while computing digest in OCB mode"
                                 % result)
            self._mac_tag = get_raw_buffer(mac_tag)

        secret = get_random_bytes(16)
        mac1 = BLAKE2s.new(digest_bits=160, key=secret, data=self._mac_tag)
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


def _create_ocb_cipher(factory, **kwargs):
    return OcbMode(factory, **kwargs)
