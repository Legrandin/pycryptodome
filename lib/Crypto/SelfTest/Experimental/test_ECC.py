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

import sys
import unittest
from binascii import unhexlify

from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util._file_system import pycryptodome_filename
from Crypto.Util.py3compat import bord, tostr
from Crypto.Util.number import bytes_to_long

from Crypto.Experimental import ECC

def load_file(filename, mode="rb"):
    comps = [ "Crypto", "SelfTest", "PublicKey", "test_vectors", "ECC" ]
    with open(pycryptodome_filename(comps, filename), mode) as fd:
        return fd.read()


def compact(lines):
    ext = b"".join(lines)
    return unhexlify(tostr(ext).replace(" ", "").replace(":", ""))

class TestExportExplicit_P256(unittest.TestCase):

    def test_export_private_explicit_params_der(self):
        key_file = load_file("ecc_p256_private_explicit_params.der")
        key = ECC.construct(curve='P-256', d=0x5c4e4320ef260f91ed9fc597aee98c8236b60e0ced692cc7a057d5e45798a052)

        encoded = key._export_private_der()
        self.assertEqual(key_file, encoded)

def get_tests(config={}):
    tests = []
    tests += list_test_cases(TestExportExplicit_P256)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')