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

from binascii import unhexlify

from Crypto.Util.py3compat import b, bchr
from Crypto.Util.number import bytes_to_long
from Crypto.Util.strxor import strxor
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.SelfTest.Signature.nist import (load_test_vector,
                                            open_fips_test_file,
                                            load_hash_by_name)

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_v1_5


class FIPS_PKCS1_Verify_Tests(unittest.TestCase):

    def shortDescription(self):
        return "FIPS PKCS1 Tests (Verify)"

    def verify_positive(self, hashmod, message, public_key, signature):
        hashed = hashmod.new(message)
        pkcs1_15.new(public_key).verify(hashed, signature)

    def verify_negative(self, hashmod, message, public_key, signature):
        hashed = hashmod.new(message)
        verifier = pkcs1_15.new(public_key)
        self.assertRaises(ValueError, verifier.verify, hashed, signature)

    counter_positive = 1
    counter_negative = 1

    def test_can_sign(self):
        test_public_key = RSA.generate(1024).publickey()
        verifier = pkcs1_15.new(test_public_key)
        self.assertEqual(verifier.can_sign(), False)

    @classmethod
    def add_positive_test(cls, hashmod, message, public_key, signature):
        def new_method(self):
            self.verify_positive(hashmod, message, public_key, signature)
        setattr(cls, "test_verify_positive_%d" % cls.counter_positive,
                new_method)
        cls.counter_positive += 1

    @classmethod
    def add_negative_test(cls, hashmod, message, public_key, signature):
        def new_method(self):
            self.verify_negative(hashmod, message, public_key, signature)
        setattr(cls, "test_verify_negative_%d" % cls.counter_negative,
                new_method)
        cls.counter_negative += 1

    @classmethod
    def add_fips_tests(cls):
        file_tv = open_fips_test_file("PKCS1-v1.5", "SigVer15_186-3.rsp")
        sections = load_test_vector(file_tv, ('SHAAlg', 'd', 'Result'))

        modulus = None
        for mod_size, test_vectors in sections.iteritems():
            for test_vector in test_vectors:

                # The modulus for all subsequent test vectors appear
                # in a single line
                if len(test_vector) == 1:
                    modulus = bytes_to_long(test_vector['n'])
                    continue

                hashmod = load_hash_by_name(test_vector['SHAAlg'])
                pub_exp = bytes_to_long(test_vector['e'])
                public_key = RSA.construct((modulus, pub_exp))

                add_method_dict = {'P': cls.add_positive_test,
                                   'F': cls.add_negative_test}
                add_method = add_method_dict[test_vector['Result']]

                add_method(hashmod, test_vector['Msg'],
                           public_key, test_vector['S'])


class FIPS_PKCS1_Sign_Tests(unittest.TestCase):

    def shortDescription(self):
        return "FIPS PKCS1 Tests (Sign)"

    def _test_sign(self, hashmod, message, private_key, signature):
        hashed = hashmod.new(message)
        signature2 = pkcs1_15.new(private_key).sign(hashed)
        self.assertEqual(signature, signature2)

    counter = 1

    def test_can_sign(self):
        test_private_key = RSA.generate(1024)
        signer = pkcs1_15.new(test_private_key)
        self.assertEqual(signer.can_sign(), True)

    @classmethod
    def add_test(cls, hashmod, message, private_key, signature):
        def new_method(self):
            self._test_sign(hashmod, message, private_key, signature)
        setattr(cls, "test_sign_%d" % cls.counter, new_method)
        cls.counter += 1

    @classmethod
    def add_fips_tests(cls):
        files = ("SigGen15_186-2.txt", "SigGen15_186-3.txt")
        for file_name in files:
            file_tv = open_fips_test_file("PKCS1-v1.5", file_name)
            sections = load_test_vector(file_tv, ('SHAAlg', ))

            modulus = None
            private_key = None
            for mod_size, test_vectors in sections.iteritems():
                for test_vector in test_vectors:

                    # The modulus for all subsequent test vectors appears
                    # in a single line
                    if len(test_vector) == 1:
                        modulus = test_vector['n']
                        continue

                    # Exponents appear in two lines
                    if len(test_vector) == 2:
                        test_vector['n'] = modulus
                        triplet = [bytes_to_long(test_vector[x])
                                   for x in ('n', 'e', 'd')]
                        private_key = RSA.construct(triplet,
                                                    consistency_check=False)
                        continue

                    hashmod = load_hash_by_name(test_vector['SHAAlg'])
                    cls.add_test(hashmod, test_vector['Msg'],
                                 private_key, test_vector['S'])


# Complete the classes at runtime
FIPS_PKCS1_Verify_Tests.add_fips_tests()
FIPS_PKCS1_Sign_Tests.add_fips_tests()


class PKCS1_15_NoParams(unittest.TestCase):
    """Verify that PKCS#1 v1.5 signatures pass even without NULL parameters in
    the algorithm identifier (PyCrypto/LP bug #1119552)."""

    rsakey = """-----BEGIN RSA PRIVATE KEY-----
            MIIBOwIBAAJBAL8eJ5AKoIsjURpcEoGubZMxLD7+kT+TLr7UkvEtFrRhDDKMtuII
            q19FrL4pUIMymPMSLBn3hJLe30Dw48GQM4UCAwEAAQJACUSDEp8RTe32ftq8IwG8
            Wojl5mAd1wFiIOrZ/Uv8b963WJOJiuQcVN29vxU5+My9GPZ7RA3hrDBEAoHUDPrI
            OQIhAPIPLz4dphiD9imAkivY31Rc5AfHJiQRA7XixTcjEkojAiEAyh/pJHks/Mlr
            +rdPNEpotBjfV4M4BkgGAA/ipcmaAjcCIQCHvhwwKVBLzzTscT2HeUdEeBMoiXXK
            JACAr3sJQJGxIQIgarRp+m1WSKV1MciwMaTOnbU7wxFs9DP1pva76lYBzgUCIQC9
            n0CnZCJ6IZYqSt0H5N7+Q+2Ro64nuwV/OSQfM6sBwQ==
            -----END RSA PRIVATE KEY-----"""

    msg = b("This is a test\x0a")

    # PKCS1 v1.5 signature of the message computed using SHA-1.
    # The digestAlgorithm SEQUENCE does NOT contain the NULL parameter.
    signature = "a287a13517f716e72fb14eea8e33a8db4a4643314607e7ca3e3e28"\
                "1893db74013dda8b855fd99f6fecedcb25fcb7a434f35cd0a101f8"\
                "b19348e0bd7b6f152dfc"
    signature = unhexlify(b(signature))

    def runTest(self):
        verifier = pkcs1_15.new(RSA.importKey(self.rsakey))
        hashed = SHA1.new(self.msg)
        verifier.verify(hashed, self.signature)


class PKCS1_Legacy_Module_Tests(unittest.TestCase):
    """Verify that the legacy module Crypto.Signature.PKCS1_v1_5
    behaves as expected. The only difference is that the verify()
    method returns True/False and does not raise exceptions."""

    def shortDescription(self):
        return "Test legacy Crypto.Signature.PKCS1_v1_5"

    def runTest(self):
        key = RSA.importKey(PKCS1_15_NoParams.rsakey)
        hashed = SHA1.new(b("Test"))
        good_signature = PKCS1_v1_5.new(key).sign(hashed)
        verifier = PKCS1_v1_5.new(key.publickey())

        self.assertEqual(verifier.verify(hashed, good_signature), True)

        # Flip a few bits in the signature
        bad_signature = strxor(good_signature, bchr(1) * len(good_signature))
        self.assertEqual(verifier.verify(hashed, bad_signature), False)


class PKCS1_All_Hashes_Tests(unittest.TestCase):

    def shortDescription(self):
        return "Test PKCS#1v1.5 signature in combination with all hashes"

    def runTest(self):

        key = RSA.generate(1024)
        signer = pkcs1_15.new(key)
        hash_names = ("MD2", "MD4", "MD5", "RIPEMD160", "SHA1",
                      "SHA224", "SHA256", "SHA384", "SHA512",
                      "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512")

        for name in hash_names:
            hashed = load_hash_by_name(name).new(b("Test"))
            signer.sign(hashed)

        from Crypto.Hash import BLAKE2b, BLAKE2s
        for hash_size in (20, 32, 48, 64):
            hashed_b = BLAKE2b.new(digest_bytes=hash_size, data=b("Test"))
            signer.sign(hashed_b)
        for hash_size in (16, 20, 28, 32):
            hashed_s = BLAKE2s.new(digest_bytes=hash_size, data=b("Test"))
            signer.sign(hashed_s)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(FIPS_PKCS1_Verify_Tests)
    tests += list_test_cases(FIPS_PKCS1_Sign_Tests)
    tests += list_test_cases(PKCS1_15_NoParams)
    tests += list_test_cases(PKCS1_Legacy_Module_Tests)
    tests += list_test_cases(PKCS1_All_Hashes_Tests)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
