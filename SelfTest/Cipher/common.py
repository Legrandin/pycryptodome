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

import unittest
import binascii

class BlockCipherSelfTest(unittest.TestCase):

    def __init__(self, module, description, plaintext, ciphertext, key, extra_params=None):
        unittest.TestCase.__init__(self)
        self.module = module
        self.description = description
        self.key = key
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        if extra_params is None:
            self.extra_params = {}
            self.iv = None
            self.mode = 'ECB'
        elif extra_params.has_key('mode'):
            self.extra_params = extra_params.copy()
            self.mode = self.extra_params['mode']
            self.iv = self.extra_params['iv']
            del self.extra_params['iv']
            del self.extra_params['mode']
        else:
            self.extra_params = extra_params
            self.iv = None
            self.mode = 'ECB'

    def shortDescription(self):
        return self.description

    def runTest(self):
        key = binascii.a2b_hex(self.key)
        plaintext = binascii.a2b_hex(self.plaintext)
        ciphertext = binascii.a2b_hex(self.ciphertext)
        mode = getattr(self.module, "MODE_" + self.mode)
        if self.iv is None:
            c = lambda self=self, key=key, mode=mode: self.module.new(key, mode, **self.extra_params)
        else:
            c = lambda self=self, key=key, mode=mode: self.module.new(key, mode, binascii.a2b_hex(self.iv), **self.extra_params)

        ct1 = binascii.b2a_hex(c().encrypt(plaintext))
        pt1 = binascii.b2a_hex(c().decrypt(ciphertext))
        ct2 = binascii.b2a_hex(c().encrypt(plaintext))
        pt2 = binascii.b2a_hex(c().decrypt(ciphertext))

        self.assertEqual(self.ciphertext, ct1)
        self.assertEqual(self.ciphertext, ct2)
        self.assertEqual(self.plaintext, pt1)
        self.assertEqual(self.plaintext, pt2)

def make_block_testsuite(module, module_name, test_data):
    ts = unittest.TestSuite()
    for i in range(len(test_data)):
        row = test_data[i]
        if len(row) == 3:
            (plaintext, ciphertext, key) = row
            description = extra_params = None
        elif len(row) == 4:
            (plaintext, ciphertext, key, description) = row
            extra_params = None
        elif len(row) == 5:
            (plaintext, ciphertext, key, description, extra_params) = row
        else:
            raise AssertionError("Unsupported tuple size %d" % (len(row),))
        if description is None and not extra_params:
            description = "p=%s, k=%s" % (plaintext, key)
        elif description is None:
            description = "p=%s, k=%s, %r" % (plaintext, key, extra_params)
        name = "%s #%d: %s" % (module_name, i+1, description)
        ts.addTest(BlockCipherSelfTest(module, name, plaintext, ciphertext, key, extra_params))
    return ts

# vim:set ts=4 sw=4 sts=4 expandtab:
