# -*- coding: utf-8 -*-
#
#  SelfTest/Util/test_Padding.py: Self-test for padding functions
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

import unittest
from binascii import unhexlify as uh

from Crypto.Util.py3compat import *
from Crypto.SelfTest.st_common import list_test_cases
from Crypto.Util.Padding import pad, unpad

class PKCS7_Tests(unittest.TestCase):

    def test1(self):
        padded = pad(b(""), 4)
        self.failUnless(padded == uh(b("04040404")))
        padded = pad(b(""), 4, 'pkcs7')
        self.failUnless(padded == uh(b("04040404")))
        back = unpad(padded, 4)
        self.failUnless(back == b(""))

    def test2(self):
        padded = pad(uh(b("12345678")), 4)
        self.failUnless(padded == uh(b("1234567804040404")))
        back = unpad(padded, 4)
        self.failUnless(back == uh(b("12345678")))

    def test3(self):
        padded = pad(uh(b("123456")), 4)
        self.failUnless(padded == uh(b("12345601")))
        back = unpad(padded, 4)
        self.failUnless(back == uh(b("123456")))

    def test4(self):
        padded = pad(uh(b("1234567890")), 4)
        self.failUnless(padded == uh(b("1234567890030303")))
        back = unpad(padded, 4)
        self.failUnless(back == uh(b("1234567890")))

    def testn1(self):
        self.assertRaises(ValueError, pad, uh(b("12")), 4, 'pkcs8')

    def testn2(self):
        self.assertRaises(ValueError, unpad, b("\0\0\0"), 4)

    def testn3(self):
        self.assertRaises(ValueError, unpad, b("123456\x02"), 4)
        self.assertRaises(ValueError, unpad, b("123456\x00"), 4)
        self.assertRaises(ValueError, unpad, b("123456\x05\x05\x05\x05\x05"), 4)

class X923_Tests(unittest.TestCase):

    def test1(self):
        padded = pad(b(""), 4, 'x923')
        self.failUnless(padded == uh(b("00000004")))
        back = unpad(padded, 4, 'x923')
        self.failUnless(back == b(""))

    def test2(self):
        padded = pad(uh(b("12345678")), 4, 'x923')
        self.failUnless(padded == uh(b("1234567800000004")))
        back = unpad(padded, 4, 'x923')
        self.failUnless(back == uh(b("12345678")))

    def test3(self):
        padded = pad(uh(b("123456")), 4, 'x923')
        self.failUnless(padded == uh(b("12345601")))
        back = unpad(padded, 4, 'x923')
        self.failUnless(back == uh(b("123456")))

    def test4(self):
        padded = pad(uh(b("1234567890")), 4, 'x923')
        self.failUnless(padded == uh(b("1234567890000003")))
        back = unpad(padded, 4, 'x923')
        self.failUnless(back == uh(b("1234567890")))

    def testn1(self):
        self.assertRaises(ValueError, unpad, b("123456\x02"), 4, 'x923')
        self.assertRaises(ValueError, unpad, b("123456\x00"), 4, 'x923')
        self.assertRaises(ValueError, unpad, b("123456\x00\x00\x00\x00\x05"), 4, 'x923')

class ISO7816_Tests(unittest.TestCase):

    def test1(self):
        padded = pad(b(""), 4, 'iso7816')
        self.failUnless(padded == uh(b("80000000")))
        back = unpad(padded, 4, 'iso7816')
        self.failUnless(back == b(""))

    def test2(self):
        padded = pad(uh(b("12345678")), 4, 'iso7816')
        self.failUnless(padded == uh(b("1234567880000000")))
        back = unpad(padded, 4, 'iso7816')
        self.failUnless(back == uh(b("12345678")))

    def test3(self):
        padded = pad(uh(b("123456")), 4, 'iso7816')
        self.failUnless(padded == uh(b("12345680")))
        #import pdb; pdb.set_trace()
        back = unpad(padded, 4, 'iso7816')
        self.failUnless(back == uh(b("123456")))

    def test4(self):
        padded = pad(uh(b("1234567890")), 4, 'iso7816')
        self.failUnless(padded == uh(b("1234567890800000")))
        back = unpad(padded, 4, 'iso7816')
        self.failUnless(back == uh(b("1234567890")))

    def testn1(self):
        self.assertRaises(ValueError, unpad, b("123456\x81"), 4, 'iso7816')

def get_tests(config={}):
    tests = []
    tests += list_test_cases(PKCS7_Tests)
    tests += list_test_cases(X923_Tests)
    tests += list_test_cases(ISO7816_Tests)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

