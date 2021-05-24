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

"""Self-test suite for Crypto.Hash.cSHAKE128 and cSHAKE256"""

import unittest

from Crypto.SelfTest.loader import load_test_vectors
from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Hash import cSHAKE128, cSHAKE256
from Crypto.Util.py3compat import b, bchr, tobytes


class cSHAKETest(unittest.TestCase):

    def test_new_positive(self):

        xof1 = self.cshake.new()
        xof2 = self.cshake.new(data=b("90"))
        xof3 = self.cshake.new().update(b("90"))

        self.assertNotEqual(xof1.read(10), xof2.read(10))
        xof3.read(10)
        self.assertEqual(xof2.read(10), xof3.read(10))

        xof1 = self.cshake.new()
        ref = xof1.read(10)
        xof2 = self.cshake.new(function=b(""))
        xof3 = self.cshake.new(custom=b(""))
        xof4 = self.cshake.new(custom=b(""), function=b(""))
        xof5 = self.cshake.new(custom=b("foo"))
        xof6 = self.cshake.new(function=b("foo"))

        self.assertEqual(ref, xof2.read(10))
        self.assertEqual(ref, xof3.read(10))
        self.assertEqual(ref, xof4.read(10))
        self.assertNotEqual(ref, xof5.read(10))
        self.assertNotEqual(ref, xof6.read(10))

        xof1 = self.cshake.new(custom=b("foo"))
        xof2 = self.cshake.new(function=b("foo"))

        self.assertNotEqual(xof1.read(10), xof2.read(10))

        xof1 = self.cshake.new(function=b("foo"))
        xof2 = self.cshake.new(function=b("foo"), data=b("90"))
        xof3 = self.cshake.new(function=b("foo")).update(b("90"))

        self.assertNotEqual(xof1.read(10), xof2.read(10))
        xof3.read(10)
        self.assertEqual(xof2.read(10), xof3.read(10))

        xof1 = self.cshake.new(custom=b("foo"))
        xof2 = self.cshake.new(custom=b("foo"), data=b("90"))
        xof3 = self.cshake.new(custom=b("foo")).update(b("90"))

        self.assertNotEqual(xof1.read(10), xof2.read(10))
        xof3.read(10)
        self.assertEqual(xof2.read(10), xof3.read(10))

        xof1 = self.cshake.new(function=b("foo"), custom=b("bar"))
        xof2 = self.cshake.new(function=b("foo"), custom=b("bar"), data=b("90"))
        xof3 = self.cshake.new(function=b("foo"), custom=b("bar")).update(b("90"))

        self.assertNotEqual(xof1.read(10), xof2.read(10))
        xof3.read(10)
        self.assertEqual(xof2.read(10), xof3.read(10))

    def test_update(self):
        pieces = [bchr(10) * 200, bchr(20) * 300]
        h = self.cshake.new()
        h.update(pieces[0]).update(pieces[1])
        digest = h.read(10)
        h = self.cshake.new()
        h.update(pieces[0] + pieces[1])
        self.assertEqual(h.read(10), digest)

    def test_update_negative(self):
        h = self.cshake.new()
        self.assertRaises(TypeError, h.update, u"string")

    def test_digest(self):
        h = self.cshake.new()
        digest = h.read(90)

        # read returns a byte string of the right length
        self.failUnless(isinstance(digest, type(b("digest"))))
        self.assertEqual(len(digest), 90)

    def test_update_after_read(self):
        mac = self.cshake.new()
        mac.update(b("rrrr"))
        mac.read(90)
        self.assertRaises(TypeError, mac.update, b("ttt"))


class cSHAKE128Test(cSHAKETest):
    cshake = cSHAKE128


class cSHAKE256Test(cSHAKETest):
    cshake = cSHAKE256


class cSHAKEVectors(unittest.TestCase):
    pass


# cSHAKE defaults to SHAKE if customization strings are empty,
# hence we reuse the SHAKE testvectors here as well.
vector_files = [("ShortMsgKAT_SHAKE128.txt", "Short Messages KAT SHAKE128", "128_shake", cSHAKE128),
                ("ShortMsgKAT_SHAKE256.txt", "Short Messages KAT SHAKE256", "256_shake", cSHAKE256),
                ("ShortMsgSamples_cSHAKE128.txt", "Short Message Samples cSHAKE128", "128_cshake", cSHAKE128),
                ("ShortMsgSamples_cSHAKE256.txt", "Short Message Samples cSHAKE256", "256_cshake", cSHAKE256)]

for file, descr, tag, test_class in vector_files:

    test_vectors = load_test_vectors(("Hash", "SHA3"), file, descr,
                                     {"len": lambda x: int(x),
                                      "nlen": lambda x: int(x),
                                      "slen": lambda x: int(x)}) or []

    for idx, tv in enumerate(test_vectors):
        if getattr(tv, "len", 0) == 0:
            data = b("")
        else:
            data = tobytes(tv.msg)
            assert(tv.len == len(tv.msg)*8)
        if getattr(tv, "nlen", 0) == 0:
            function = b("")
        else:
            function = tobytes(tv.n)
            assert(tv.nlen == len(tv.n)*8)
        if getattr(tv, "slen", 0) == 0:
            custom = b("")
        else:
            custom = tobytes(tv.s)
            assert(tv.slen == len(tv.s)*8)

        def new_test(self, data=data, result=tv.md, function=function, custom=custom, test_class=test_class):
            hobj = test_class.new(data=data, function=function, custom=custom)
            digest = hobj.read(len(result))
            self.assertEqual(digest, result)

        setattr(cSHAKEVectors, "test_%s_%d" % (tag, idx), new_test)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(cSHAKE128Test)
    tests += list_test_cases(cSHAKE256Test)
    tests += list_test_cases(cSHAKEVectors)
    return tests


if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
