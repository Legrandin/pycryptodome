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

from Crypto.SelfTest.Cipher.nist_loader import load_tests
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util.py3compat import tobytes, b, unhexlify
from Crypto.Cipher import AES, DES3, DES
from Crypto.Hash import SHAKE128

def get_tag_random(tag, length):
    return SHAKE128.new(data=tobytes(tag)).read(length)

class OfbTests(unittest.TestCase):

    key_128 = get_tag_random("key_128", 16)
    key_192 = get_tag_random("key_192", 24)
    iv_128 = get_tag_random("iv_128", 16)
    iv_64 = get_tag_random("iv_64", 8)
    data_128 = get_tag_random("data_128", 16)

    def test_loopback_128(self):
        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        pt = get_tag_random("plaintext", 16 * 100)
        ct = cipher.encrypt(pt)

        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        pt2 = cipher.decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_loopback_64(self):
        cipher = DES3.new(self.key_192, DES3.MODE_OFB, self.iv_64)
        pt = get_tag_random("plaintext", 8 * 100)
        ct = cipher.encrypt(pt)

        cipher = DES3.new(self.key_192, DES3.MODE_OFB, self.iv_64)
        pt2 = cipher.decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_iv_is_required(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_OFB)
        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        ct = cipher.encrypt(self.data_128)

        cipher = AES.new(self.key_128, AES.MODE_OFB, iv=self.iv_128)
        self.assertEquals(ct, cipher.encrypt(self.data_128))

        cipher = AES.new(self.key_128, AES.MODE_OFB, IV=self.iv_128)
        self.assertEquals(ct, cipher.encrypt(self.data_128))

    def test_iv_must_be_bytes(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_OFB,
                          iv = u'test1234567890-*')

    def test_only_one_iv(self):
        # Only one IV/iv keyword allowed
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_OFB,
                          iv=self.iv_128, IV=self.iv_128)

    def test_iv_with_matching_length(self):
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_OFB,
                          b(""))
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_OFB,
                          self.iv_128[:15])
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_OFB,
                          self.iv_128 + b("0"))

    def test_block_size_128(self):
        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        self.assertEqual(cipher.block_size, AES.block_size)

    def test_block_size_64(self):
        cipher = DES3.new(self.key_192, DES3.MODE_OFB, self.iv_64)
        self.assertEqual(cipher.block_size, DES3.block_size)

    def test_unaligned_data_128(self):
        plaintexts = [ b("7777777") ] * 100

        cipher = AES.new(self.key_128, AES.MODE_CFB, self.iv_128, segment_size=8)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = AES.new(self.key_128, AES.MODE_CFB, self.iv_128, segment_size=8)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

        cipher = AES.new(self.key_128, AES.MODE_CFB, self.iv_128, segment_size=128)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = AES.new(self.key_128, AES.MODE_CFB, self.iv_128, segment_size=128)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

    def test_unaligned_data_64(self):
        plaintexts = [ b("7777777") ] * 100
        cipher = DES3.new(self.key_192, DES3.MODE_CFB, self.iv_64, segment_size=8)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = DES3.new(self.key_192, DES3.MODE_CFB, self.iv_64, segment_size=8)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

        cipher = DES3.new(self.key_192, DES3.MODE_CFB, self.iv_64, segment_size=64)
        ciphertexts = [ cipher.encrypt(x) for x in plaintexts ]
        cipher = DES3.new(self.key_192, DES3.MODE_CFB, self.iv_64, segment_size=64)
        self.assertEqual(b("").join(ciphertexts), cipher.encrypt(b("").join(plaintexts)))

    def test_IV_iv_attributes(self):
        data = get_tag_random("data", 16 * 100)
        for func in "encrypt", "decrypt":
            cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
            getattr(cipher, func)(data)
            self.assertEqual(cipher.iv, self.iv_128)
            self.assertEqual(cipher.IV, self.iv_128)

    def test_unknown_attributes(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_OFB,
                          self.iv_128, 7)
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_OFB,
                          iv=self.iv_128, unknown=7)
        # But some are only known by the base cipher (e.g. use_aesni consumed by the AES module)
        AES.new(self.key_128, AES.MODE_OFB, iv=self.iv_128, use_aesni=False)

    def test_null_encryption_decryption(self):
        for func in "encrypt", "decrypt":
            cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
            result = getattr(cipher, func)(b(""))
            self.assertEqual(result, b(""))

    def test_either_encrypt_or_decrypt(self):
        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        cipher.encrypt(b(""))
        self.assertRaises(TypeError, cipher.decrypt, b(""))

        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        cipher.decrypt(b(""))
        self.assertRaises(TypeError, cipher.encrypt, b(""))

    def test_data_must_be_bytes(self):
        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        self.assertRaises(TypeError, cipher.encrypt, u'test1234567890-*')

        cipher = AES.new(self.key_128, AES.MODE_OFB, self.iv_128)
        self.assertRaises(TypeError, cipher.decrypt, u'test1234567890-*')


class NistOfbVectors(unittest.TestCase):

    def _do_kat_aes_test(self, file_name):
        test_vectors = load_tests("AES", file_name, "AES OFB KAT")
        assert(test_vectors)
        for tv in test_vectors:
            self.description = tv.desc
            cipher = AES.new(tv.key, AES.MODE_OFB, tv.iv)
            if tv.direction == "ENC":
                self.assertEqual(cipher.encrypt(tv.plaintext), tv.ciphertext)
            else:
                self.assertEqual(cipher.decrypt(tv.ciphertext), tv.plaintext)

    # See Section 6.4.3 in AESAVS
    def _do_mct_aes_test(self, file_name):
        test_vectors = load_tests("AES", file_name, "AES OFB Montecarlo")
        assert(test_vectors)
        for tv in test_vectors:

            self.description = tv.desc
            cipher = AES.new(tv.key, AES.MODE_OFB, tv.iv)

            if tv.direction == 'ENC':
                cts = [ tv.iv ]
                for count in xrange(1000):
                    cts.append(cipher.encrypt(tv.plaintext))
                    tv.plaintext = cts[-2]
                self.assertEqual(cts[-1], tv.ciphertext)
            else:
                pts = [ tv.iv]
                for count in xrange(1000):
                    pts.append(cipher.decrypt(tv.ciphertext))
                    tv.ciphertext = pts[-2]
                self.assertEqual(pts[-1], tv.plaintext)

    def _do_tdes_test(self, file_name):
        test_vectors = load_tests("TDES", file_name, "TDES OFB KAT")
        assert(test_vectors)
        for tv in test_vectors:
            self.description = tv.desc
            if hasattr(tv, "keys"):
                cipher = DES.new(tv.keys, DES.MODE_OFB, tv.iv)
            else:
                if tv.key1 != tv.key3:
                    key = tv.key1 + tv.key2 + tv.key3  # Option 3
                else:
                    key = tv.key1 + tv.key2            # Option 2
                cipher = DES3.new(key, DES3.MODE_OFB, tv.iv)
            if tv.direction == "ENC":
                self.assertEqual(cipher.encrypt(tv.plaintext), tv.ciphertext)
            else:
                self.assertEqual(cipher.decrypt(tv.ciphertext), tv.plaintext)


# Create one test method per file
nist_aes_kat_mmt_files = (
    # KAT
    "OFBGFSbox128.rsp",
    "OFBGFSbox192.rsp",
    "OFBGFSbox256.rsp",
    "OFBKeySbox128.rsp",
    "OFBKeySbox192.rsp",
    "OFBKeySbox256.rsp",
    "OFBVarKey128.rsp",
    "OFBVarKey192.rsp",
    "OFBVarKey256.rsp",
    "OFBVarTxt128.rsp",
    "OFBVarTxt192.rsp",
    "OFBVarTxt256.rsp",
    # MMT
    "OFBMMT128.rsp",
    "OFBMMT192.rsp",
    "OFBMMT256.rsp",
    )
nist_aes_mct_files = (
    "OFBMCT128.rsp",
    "OFBMCT192.rsp",
    "OFBMCT256.rsp",
    )

for file_name in nist_aes_kat_mmt_files:
    def new_func(self, file_name=file_name):
        self._do_kat_aes_test(file_name)
    setattr(NistOfbVectors, "test_AES_" + file_name, new_func)

for file_name in nist_aes_mct_files:
    def new_func(self, file_name=file_name):
        self._do_mct_aes_test(file_name)
    setattr(NistOfbVectors, "test_AES_" + file_name, new_func)
del file_name, new_func

nist_tdes_files = (
    "TOFBMMT2.rsp",    # 2TDES
    "TOFBMMT3.rsp",    # 3TDES
    "TOFBinvperm.rsp", # Single DES
    "TOFBpermop.rsp",
    "TOFBsubtab.rsp",
    "TOFBvarkey.rsp",
    "TOFBvartext.rsp",
    )

for file_name in nist_tdes_files:
    def new_func(self, file_name=file_name):
        self._do_tdes_test(file_name)
    setattr(NistOfbVectors, "test_TDES_" + file_name, new_func)

# END OF NIST OFB TEST VECTORS


class SP800TestVectors(unittest.TestCase):
    """Class exercising the OFB test vectors found in Section F.4
    of NIST SP 800-3A"""

    def test_aes_128(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    '3b3fd92eb72dad20333449f8e83cfb4a' +\
                        '7789508d16918f03f53c52dac54ed825' +\
                        '9740051e9c5fecf64344f7a82260edcc' +\
                        '304c6528f659c77866a510d9c1d6ae5e'
        key =           '2b7e151628aed2a6abf7158809cf4f3c'
        iv =            '000102030405060708090a0b0c0d0e0f'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])

    def test_aes_192(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'cdc80d6fddf18cab34c25909c99a4174' +\
                        'fcc28b8d4c63837c09e81700c1100401' +\
                        '8d9a9aeac0f6596f559c6d4daf59a5f2' +\
                        '6d9f200857ca6c3e9cac524bd9acc92a'
        key =           '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
        iv =            '000102030405060708090a0b0c0d0e0f'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])

    def test_aes_256(self):
        plaintext =     '6bc1bee22e409f96e93d7e117393172a' +\
                        'ae2d8a571e03ac9c9eb76fac45af8e51' +\
                        '30c81c46a35ce411e5fbc1191a0a52ef' +\
                        'f69f2445df4f9b17ad2b417be66c3710'
        ciphertext =    'dc7e84bfda79164b7ecd8486985d3860' +\
                        '4febdc6740d20b3ac88f6ad82a4fb08d' +\
                        '71ab47a086e86eedf39d1c5bba97c408' +\
                        '0126141d67f37be8538f5a8be740e484'
        key =           '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
        iv =            '000102030405060708090a0b0c0d0e0f'

        key = unhexlify(key)
        iv = unhexlify(iv)
        plaintext = unhexlify(plaintext)
        ciphertext = unhexlify(ciphertext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext), ciphertext)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext), plaintext)

        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.encrypt(plaintext[:-8]), ciphertext[:-8])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        self.assertEqual(cipher.decrypt(ciphertext[:-8]), plaintext[:-8])


def get_tests(config={}):
    tests = []
    tests += list_test_cases(OfbTests)
    tests += list_test_cases(NistOfbVectors)
    tests += list_test_cases(SP800TestVectors)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
