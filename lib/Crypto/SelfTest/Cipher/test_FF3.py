# ===================================================================
#
# Copyright (c) 2022, Joshua Holt <joshholt@gmail.com>
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
import json
import os
import warnings

from Crypto.Cipher.FF3 import FF3, RadixOutOfRangeError, AlphabetValueError, \
    AlphabetOutOfRangeError
from Crypto.SelfTest.st_common import list_test_cases

class NIST_ACVP_Samples(unittest.TestCase):

    def setUp(self):
        try:
            import pycryptodome_test_vectors # type: ignore
            init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
            ACVP_test_dir = os.path.join(init_dir, "Cipher/ACVP/FF3/")
            print(ACVP_test_dir)
            with open(ACVP_test_dir + 'prompt.json', 'r', encoding='utf-8') as tests_f:
                self.tests = json.load(tests_f)
            with open(ACVP_test_dir + 'expectedResults.json', 'r', encoding='utf-8') as results_f:
                self.results = json.load(results_f)
        except:
            warnings.warn("Warning: skipping NIST ACVP tests for FF3",
                           UserWarning)
            self.tests = None
            self.results = None

    def test_ff3_sample_vectors(self):
        if(self.tests):
            for testgroupID, testgroup in enumerate(self.tests['testGroups']):
                result_testgroup = self.results['testGroups'][testgroupID]
                for testID, test in enumerate(testgroup['tests']):
                    test = testgroup['tests'][testID]
                    result = result_testgroup['tests'][testID]
                    fpe = FF3(int(testgroup['radix']), testgroup['alphabet'], \
                        bytes.fromhex(test['key']))
                    if (testgroup['direction'] == "encrypt"):
                        ct = fpe.encrypt(test['pt'], bytes.fromhex(test['tweak']))
                        self.assertEqual(ct, result['ct'])
                    if (testgroup['direction'] == "decrypt"):
                        pt = fpe.decrypt(test['ct'], bytes.fromhex(test['tweak']))
                        self.assertEqual(pt, result['pt'])


class FF3BadInput(unittest.TestCase):


    def test_ff3_out_of_range_init(self):
        valid_radix = 10
        valid_key = bytearray(16)
        valid_alphabet = "0123456789"
        short_alphabet = "a"
        long_alphabet = "a" * 70
        non_unique_alphabet = "abab"
        bad_alphabet = "abcdefgh!"
        # Not passing a key should raise TypeError
        # Currently countin on AES to thorw this, we should detect and raise
        with self.assertRaises(TypeError):
            fpe = FF3(10)
        # Small AES key less than 128 bit/16 bytes should assert ValueError
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(0))
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(4))
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(8))
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(12))
        # AES key between 16 byte and 24 bytes should assert ValueError
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(20))
        # AES key between 24 bytes and 32 bytes should assert ValueError
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(28))
        # AES key greater than 32 bytes should ValueError
        with self.assertRaises(ValueError):
            fpe = FF3(10, valid_alphabet, bytearray(36))
        # Radix less than 2 should throw RadixOutofRangeError
        with self.assertRaises(RadixOutOfRangeError):
            fpe = FF3(1, valid_alphabet, valid_key)
        with self.assertRaises(RadixOutOfRangeError):
            fpe = FF3(65, valid_alphabet, valid_key)
        with self.assertRaises(AlphabetOutOfRangeError):
            fpe = FF3(valid_radix, short_alphabet, valid_key)
        with self.assertRaises(AlphabetOutOfRangeError):
            fpe = FF3(valid_radix, long_alphabet, valid_key)
        with self.assertRaises(AlphabetValueError):
            fpe = FF3(valid_radix, bad_alphabet, valid_key)

    def test_ff3_bad_encrypt_values(self):
        valid_radix = 10
        valid_key = bytearray(16)
        valid_alphabet = "0123456789"
        valid_tweak = bytes.fromhex("0123456789ABCD")
        valid_pt = "123456789"
        bad_pt1 = "1"
        bad_pt2 = "10000"
        bad_pt3 = "1" * 70
        bad_tweak_type = "string"
        bad_tweak1 = bytes.fromhex("012345")
        bad_tweak2 = bytes.fromhex("0123456789ABCDEF")

        fpe = FF3(valid_radix, valid_alphabet, valid_key)
        with self.assertRaises(ValueError):
            fpe.encrypt(bad_pt1, valid_tweak)
        with self.assertRaises(ValueError):
            fpe.encrypt(bad_pt2, valid_tweak)
        with self.assertRaises(ValueError):
            fpe.encrypt(bad_pt3, valid_tweak)
        with self.assertRaises(ValueError):
            fpe.encrypt(valid_pt, bad_tweak1)
        with self.assertRaises(ValueError):
            fpe.encrypt(valid_pt, bad_tweak2)

        with self.assertRaises(TypeError):
            fpe.encrypt(valid_pt, bad_tweak_type)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(NIST_ACVP_Samples)
    tests += list_test_cases(FF3BadInput)
    return tests

if __name__ == '__main__':
    import unittest
    def suite():
        return unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
