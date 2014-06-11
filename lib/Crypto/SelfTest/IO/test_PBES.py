# -*- coding: utf-8 -*-
#
#  SelfTest/IO/test_PBES.py: Self-test for the _PBES module
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Self-tests for Crypto.IO._PBES module"""

import unittest
from Crypto.Util.py3compat import *

from Crypto.IO._PBES import PBES2


class TestPBES2(unittest.TestCase):

    def setUp(self):
        self.ref = b("Test data")
        self.passphrase = b("Passphrase")

    def test1(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test2(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndAES128-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test3(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'PBKDF2WithHMAC-SHA1AndAES192-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test4(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES128-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test5(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES192-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)

    def test6(self):
        ct = PBES2.encrypt(self.ref, self.passphrase,
                           'scryptAndAES256-CBC')
        pt = PBES2.decrypt(ct, self.passphrase)
        self.assertEqual(self.ref, pt)


def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    listTests = []
    listTests += list_test_cases(TestPBES2)
    return listTests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
