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

import unittest

from Crypto.SelfTest.Cipher.nist_loader import load_tests
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util.py3compat import tobytes, b
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128

def get_tag_random(tag, length):
    return SHAKE128.new(data=tobytes(tag)).read(length)

class CbcTests(unittest.TestCase):

    key_128 = get_tag_random("key_128", 16)
    iv_128 = get_tag_random("iv_128", 16)

    def test_loopback(self):
        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        pt = get_tag_random("plaintext", 16 * 100)
        ct = cipher.encrypt(pt)

        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        pt2 = cipher.decrypt(ct)
        self.assertEqual(pt, pt2)

    def test_iv_is_required(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CBC)
        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        cipher = AES.new(self.key_128, AES.MODE_CBC, iv=self.iv_128)
        cipher = AES.new(self.key_128, AES.MODE_CBC, IV=self.iv_128)

    def test_only_one_iv(self):
        # Only one IV/iv keyword allowed
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CBC,
                          iv=self.iv_128, IV=self.iv_128)

    def test_iv_with_matching_length(self):
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_CBC,
                          self.iv_128[:15])
        self.assertRaises(ValueError, AES.new, self.key_128, AES.MODE_CBC,
                          self.iv_128 + b("0"))

    def test_block_size(self):
        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        self.assertEqual(cipher.block_size, AES.block_size)

    def test_unaligned_data(self):
        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        for wrong_length in xrange(1,16):
            self.assertRaises(ValueError, cipher.encrypt, b("5") * wrong_length)

        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        for wrong_length in xrange(1,16):
            self.assertRaises(ValueError, cipher.decrypt, b("5") * wrong_length)

    def test_IV_iv_attributes(self):
        data = get_tag_random("data", 16 * 100)
        for func in "encrypt", "decrypt":
            cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
            getattr(cipher, func)(data)
            self.assertEqual(cipher.iv, self.iv_128)
            self.assertEqual(cipher.IV, self.iv_128)

    def test_unknown_attributes(self):
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CBC,
                          self.iv_128, 7)
        self.assertRaises(TypeError, AES.new, self.key_128, AES.MODE_CBC,
                          iv=self.iv_128, unknown=7)

    def test_null_encryption_decryption(self):
        for func in "encrypt", "decrypt":
            cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
            result = getattr(cipher, func)(b(""))
            self.assertEqual(result, b(""))

    def test_either_encrypt_or_decrypt(self):
        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        cipher.encrypt(b(""))
        self.assertRaises(TypeError, cipher.decrypt, b(""))

        cipher = AES.new(self.key_128, AES.MODE_CBC, self.iv_128)
        cipher.decrypt(b(""))
        self.assertRaises(TypeError, cipher.encrypt, b(""))


class NistCbcVectors(unittest.TestCase):

    def _do_kat_test(self, file_name):
        test_vectors = load_tests("AES", file_name)
        assert(test_vectors)
        for tv in test_vectors:
            self.description = tv.desc
            cipher = AES.new(tv.key, AES.MODE_CBC, tv.iv)
            if tv.direction == "ENC":
                self.assertEqual(cipher.encrypt(tv.plaintext), tv.ciphertext)
            else:
                self.assertEqual(cipher.decrypt(tv.ciphertext), tv.plaintext)

    # See Section 6.4.2 in AESAVS
    def _do_mct_test(self, file_name):
        test_vectors = load_tests("AES", file_name)
        assert(test_vectors)
        for tv in test_vectors:

            self.description = tv.desc
            cipher = AES.new(tv.key, AES.MODE_CBC, tv.iv)

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


# Create one test method per file
nist_aes_kat_mmt_files = (
    # KAT
    "CBCGFSbox128.rsp",
    "CBCGFSbox192.rsp",
    "CBCGFSbox256.rsp",
    "CBCKeySbox128.rsp",
    "CBCKeySbox192.rsp",
    "CBCKeySbox256.rsp",
    "CBCVarKey128.rsp",
    "CBCVarKey192.rsp",
    "CBCVarKey256.rsp",
    "CBCVarTxt128.rsp",
    "CBCVarTxt192.rsp",
    "CBCVarTxt256.rsp",
    # MMT
    "CBCMMT128.rsp",
    "CBCMMT192.rsp",
    "CBCMMT256.rsp",
    )
nist_aes_mct_files = (
    "CBCMCT128.rsp",
    "CBCMCT192.rsp",
    "CBCMCT256.rsp",
    )

for file_name in nist_aes_kat_mmt_files:
    def new_func(self, file_name=file_name):
        self._do_kat_test(file_name)
    setattr(NistCbcVectors, "test_AES_" + file_name, new_func)

for file_name in nist_aes_mct_files:
    def new_func(self, file_name=file_name):
        self._do_mct_test(file_name)
    setattr(NistCbcVectors, "test_AES_" + file_name, new_func)
del file_name, new_func


def get_tests(config={}):
    tests = []
    tests += list_test_cases(CbcTests)
    tests += list_test_cases(NistCbcVectors)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
