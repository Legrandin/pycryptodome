# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
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

import unittest

from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util.py3compat import tobytes, b, unhexlify
from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHAKE128
from Crypto.Util import Counter

def get_tag_random(tag, length):
    return SHAKE128.new(data=tobytes(tag)).read(length)

class CtrTests(unittest.TestCase):

    key_128 = get_tag_random("key_128", 16)
    key_192 = get_tag_random("key_192", 24)
    ctr_64 = Counter.new(32, prefix=get_tag_random("iv_64", 4))
    ctr_128 = Counter.new(64, prefix=get_tag_random("iv_128", 8))

    def test_loopback_128(self):
        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        pt = get_tag_random("plaintext", 16 * 100)
        ct = cipher.encrypt(pt)

        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        pt2 = cipher.decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_loopback_64(self):
        cipher = DES3.new(self.key_192, DES3.MODE_CTR, counter=self.ctr_64)
        pt = get_tag_random("plaintext", 8 * 100)
        ct = cipher.encrypt(pt)

        cipher = DES3.new(self.key_192, DES3.MODE_CTR, counter=self.ctr_64)
        pt2 = cipher.decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_counter_is_required(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CFB)
        self.assertRaises(TypeError, AES.new, self.key_128, self.ctr_128)

    def test_iv_with_matching_length(self):
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_CTR,
                          counter=Counter.new(120))
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_CTR,
                          counter=Counter.new(136))

    def test_block_size_128(self):
        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        self.assertEqual(cipher.block_size, AES.block_size)

    def test_block_size_64(self):
        cipher = DES3.new(self.key_192, DES3.MODE_CTR, counter=self.ctr_64)
        self.assertEqual(cipher.block_size, DES3.block_size)

    def test_unaligned_data_128(self):
        plaintexts = [ b("7777777") ] * 100

        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

    def test_unaligned_data_64(self):
        plaintexts = [ b("7777777") ] * 100
        cipher = DES3.new(self.key_192, AES.MODE_CTR, counter=self.ctr_64)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = DES3.new(self.key_192, AES.MODE_CTR, counter=self.ctr_64)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

        cipher = DES3.new(self.key_192, AES.MODE_CTR, counter=self.ctr_64)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = DES3.new(self.key_192, AES.MODE_CTR, counter=self.ctr_64)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

    def test_unknown_parameters(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CTR,
                          7, counter=self.ctr_128)
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CTR,
                          counter=self.ctr_128, unknown=7)
        # But some are only known by the base cipher (e.g. use_aesni consumed by the AES module)
        AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128, use_aesni=False)

    def test_null_encryption_decryption(self):
        for func in "encrypt", "decrypt":
            cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
            result = getattr(cipher, func)(b(""))
            self.assertEqual(result, b(""))

    def test_either_encrypt_or_decrypt(self):
        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        cipher.encrypt(b(""))
        self.assertRaises(TypeError, cipher.decrypt, b(""))

        cipher = AES.new(self.key_128, AES.MODE_CTR, counter=self.ctr_128)
        cipher.decrypt(b(""))
        self.assertRaises(TypeError, cipher.encrypt, b(""))


class SP800TestVectors(unittest.TestCase):
    """Class exercising the CTR test vectors found in Section F.3
    of NIST SP 800-3A"""

    def test_aes_128(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '874d6191b620e3261bef6864990db6ce' +\
                        '9806f66b7970fdff8617187bb9fffdff' +\
                        '5ae4df3edbd5d35e5b4f09020db03eab' +\
                        '1e031dda2fbe03d1792170a0f3009cee'
        key =           '2b7e151628aed2a6abf7158809cf4f3c'
        counter =       Counter.new(nbits=16,
                                    prefix=unhexlify('f0f1f2f3f4f5f6f7f8f9fafbfcfd'),
                                    initial_value=0xfeff)

        key = unhexlify(key)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_192(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '1abc932417521ca24f2b0459fe7e6e0b' +\
                        '090339ec0aa6faefd5ccc2c6f4ce8e94' +\
                        '1e36b26bd1ebc670d1bd1d665620abf7' +\
                        '4f78a7f6d29809585a97daec58c6b050'
        key =           '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
        counter =       Counter.new(nbits=16,
                                    prefix=unhexlify('f0f1f2f3f4f5f6f7f8f9fafbfcfd'),
                                    initial_value=0xfeff)

        key = unhexlify(key)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_aes_256(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '601ec313775789a5b7a7f504bbf3d228' +\
                        'f443e3ca4d62b59aca84e990cacaf5c5' +\
                        '2b0930daa23de94ce87017ba2d84988d' +\
                        'dfc9c58db67aada613c2dd08457941a6'
        key =           '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
        counter =       Counter.new(nbits=16,
                                    prefix=unhexlify('f0f1f2f3f4f5f6f7f8f9fafbfcfd'),
                                    initial_value=0xfeff)
        key = unhexlify(key)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(CtrTests)
    tests += list_test_cases(SP800TestVectors)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
