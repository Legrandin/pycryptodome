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
from Crypto.Cipher import AES


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
                cts = []
                for count in xrange(1000):
                    cts.append(cipher.encrypt(tv.plaintext))
                    # Set next plaintext
                    if count == 0:
                        tv.plaintext = tv.iv
                    else:
                        tv.plaintext = cts[count-1]
                self.assertEqual(cts[-1], tv.ciphertext)
            else:
                pts = []
                for count in xrange(1000):
                    pts.append(cipher.decrypt(tv.ciphertext))
                    # Set next ciphertext
                    if count == 0:
                        tv.ciphertext = tv.iv
                    else:
                        tv.ciphertext = pts[count-1]
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

for file_name_kat_mmt in nist_aes_kat_mmt_files:
    def new_func(self):
        self._do_kat_test(file_name_kat_mmt)
    setattr(NistCbcVectors, "test_AES_" + file_name_kat_mmt, new_func)

for file_name_mct in nist_aes_mct_files:
    def new_func(self):
        self._do_mct_test(file_name_mct)
    setattr(NistCbcVectors, "test_AES_" + file_name_mct, new_func)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(NistCbcVectors)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
