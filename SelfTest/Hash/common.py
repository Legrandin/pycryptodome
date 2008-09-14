# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/common.py: Common code for Crypto.SelfTest.Hash
#
# =======================================================================
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================
#

"""Self-testing for PyCrypto hash modules"""

__revision__ = "$Id$"

import sys
import unittest
import binascii
import string

# For compatibility with Python 2.1 and Python 2.2
if sys.hexversion < 0x02030000:
    # Python 2.1 doesn't have a dict() function
    # Python 2.2 dict() function raises TypeError if you do dict(MD5='blah')
    def dict(**kwargs):
        return kwargs.copy()
else:
    dict = __builtins__['dict']


class HashSelfTest(unittest.TestCase):

    def __init__(self, hashmod, description, expected, input):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.expected = expected
        self.input = input
        self.description = description

    def shortDescription(self):
        return self.description

    def runTest(self):
        h = self.hashmod.new()
        h.update(self.input)

        out1 = binascii.b2a_hex(h.digest())
        out2 = h.hexdigest()

        h = self.hashmod.new(self.input)

        out3 = h.hexdigest()
        out4 = binascii.b2a_hex(h.digest())

        self.assertEqual(self.expected, out1)
        self.assertEqual(self.expected, out2)
        self.assertEqual(self.expected, out3)
        self.assertEqual(self.expected, out4)

class MACSelfTest(unittest.TestCase):

    def __init__(self, hashmod, description, expected_dict, input, key, hashmods):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.expected_dict = expected_dict
        self.input = input
        self.key = key
        self.hashmods = hashmods
        self.description = description

    def shortDescription(self):
        return self.description

    def runTest(self):
        for hashname in self.expected_dict.keys():
            hashmod = self.hashmods[hashname]
            key = binascii.a2b_hex(self.key)
            data = binascii.a2b_hex(self.input)

            # Strip whitespace from the expected string (which should be in lowercase-hex)
            expected = self.expected_dict[hashname]
            for ch in string.whitespace:
                expected = expected.replace(ch, "")

            h = self.hashmod.new(key, digestmod=hashmod)
            h.update(data)
            out1 = binascii.b2a_hex(h.digest())
            out2 = h.hexdigest()

            h = self.hashmod.new(key, data, hashmod)

            out3 = h.hexdigest()
            out4 = binascii.b2a_hex(h.digest())

            self.assertEqual(expected, out1)
            self.assertEqual(expected, out2)
            self.assertEqual(expected, out3)
            self.assertEqual(expected, out4)

def make_hash_testsuite(module, module_name, test_data):
    ts = unittest.TestSuite()
    for i in range(len(test_data)):
        row = test_data[i]
        if len(row) < 3:
            (expected, input) = row
            description = repr(input)
        else:
            (expected, input, description) = row
        name = "%s #%d: %s" % (module_name, i+1, description)
        ts.addTest(HashSelfTest(module, name, expected, input))
    return ts

def make_mac_testsuite(module, module_name, test_data, hashmods):
    ts = unittest.TestSuite()
    for i in range(len(test_data)):
        row = test_data[i]
        (key, data, results, description) = row
        name = "%s #%d: %s" % (module_name, i+1, description)
        ts.addTest(MACSelfTest(module, name, results, data, key, hashmods))
    return ts

# vim:set ts=4 sw=4 sts=4 expandtab:
