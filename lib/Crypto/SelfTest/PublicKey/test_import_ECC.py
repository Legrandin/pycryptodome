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
from Crypto.Util._file_system import pycryptodome_filename
from Crypto.Util.py3compat import b, unhexlify, bord
from Crypto.Util.number import bytes_to_long

from Crypto.PublicKey import ECC


def load_file(filename):
    fd = open(pycryptodome_filename([
                                    "Crypto",
                                    "SelfTest",
                                    "PublicKey",
                                    "test_vectors",
                                    "ECC",
                                    ], filename))
    return fd.read()


def compact(lines):
    return unhexlify(b("").join(lines).replace(" ", "").replace(":", ""))


def create_ref_keys():
    key_lines = load_file("ecc_p256.txt").splitlines()
    private_key_d = bytes_to_long(compact(key_lines[2:5]))
    public_key_xy = compact(key_lines[6:11])
    assert bord(public_key_xy[0]) == 4  # Uncompressed
    public_key_x = bytes_to_long(public_key_xy[1:33])
    public_key_y = bytes_to_long(public_key_xy[33:])

    return (ECC.construct(curve="P-256", d=private_key_d),
            ECC.construct(curve="P-256", point_x=public_key_x, point_y=public_key_y))


# Create reference key pair
ref_private, ref_public = create_ref_keys()


class TestImport(unittest.TestCase):

    def test_import_public_der(self):
        key_file = load_file("ecc_p256_public.der")

        key = ECC._import_subjectPublicKeyInfo(key_file)
        self.assertEqual(ref_public, key)

        key = ECC._import_der(key_file, None)
        self.assertEqual(ref_public, key)

    def test_import_private_der(self):
        key_file = load_file("ecc_p256_private.der")

        key = ECC._import_private_der(key_file, None)
        self.assertEqual(ref_private, key)

        key = ECC._import_der(key_file, None)
        self.assertEqual(ref_private, key)

    def test_import_private_pkcs8_clear(self):
        key_file = load_file("ecc_p256_private_p8_clear.der")

        key = ECC._import_der(key_file, None)
        self.assertEqual(ref_private, key)

    def test_import_private_pkcs8_encrypted(self):
        key_file = load_file("ecc_p256_private_p8.der")

        key = ECC._import_der(key_file, "secret")
        self.assertEqual(ref_private, key)

    def test_import_x509_der(self):
        key_file = load_file("ecc_p256_x509.der")

        key = ECC._import_der(key_file, None)
        self.assertEqual(ref_public, key)



def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestImport)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
