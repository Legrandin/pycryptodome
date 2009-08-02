# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/common.py: Common code for Crypto.SelfTest.Hash
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

"""Self-testing for PyCrypto hash modules"""

__revision__ = "$Id$"

import sys
import unittest
from binascii import a2b_hex, b2a_hex

# For compatibility with Python 2.1 and Python 2.2
if sys.hexversion < 0x02030000:
    # Python 2.1 doesn't have a dict() function
    # Python 2.2 dict() function raises TypeError if you do dict(MD5='blah')
    def dict(**kwargs):
        return kwargs.copy()
else:
    dict = __builtins__['dict']

class _NoDefault: pass        # sentinel object
def _extract(d, k, default=_NoDefault):
    """Get an item from a dictionary, and remove it from the dictionary."""
    try:
        retval = d[k]
    except KeyError:
        if default is _NoDefault:
            raise
        return default
    del d[k]
    return retval

# Generic cipher test case
class CipherSelfTest(unittest.TestCase):

    def __init__(self, module, params):
        unittest.TestCase.__init__(self)
        self.module = module

        # Extract the parameters
        params = params.copy()
        self.description = _extract(params, 'description')
        self.key = _extract(params, 'key')
        self.plaintext = _extract(params, 'plaintext')
        self.ciphertext = _extract(params, 'ciphertext')

        mode = _extract(params, 'mode', None)
        if mode is not None:
            # Block cipher
            self.mode = getattr(self.module, "MODE_" + mode)
            self.iv = _extract(params, 'iv', None)
        else:
            # Stream cipher
            self.mode = None
            self.iv = None

        self.extra_params = params

    def shortDescription(self):
        return self.description

    def _new(self):
        if self.mode is None:
            # Stream cipher
            return self.module.new(a2b_hex(self.key), **self.extra_params)
        elif self.iv is None:
            # Block cipher without iv
            return self.module.new(a2b_hex(self.key), self.mode, **self.extra_params)
        else:
            # Block cipher with iv
            return self.module.new(a2b_hex(self.key), self.mode, a2b_hex(self.iv), **self.extra_params)

    def runTest(self):
        plaintext = a2b_hex(self.plaintext)
        ciphertext = a2b_hex(self.ciphertext)

        ct1 = b2a_hex(self._new().encrypt(plaintext))
        pt1 = b2a_hex(self._new().decrypt(ciphertext))
        ct2 = b2a_hex(self._new().encrypt(plaintext))
        pt2 = b2a_hex(self._new().decrypt(ciphertext))

        self.assertEqual(self.ciphertext, ct1)  # encrypt
        self.assertEqual(self.ciphertext, ct2)  # encrypt (second time)
        self.assertEqual(self.plaintext, pt1)   # decrypt
        self.assertEqual(self.plaintext, pt2)   # decrypt (second time)

class CTRSegfaultTest(unittest.TestCase):

    def __init__(self, module, params):
        unittest.TestCase.__init__(self)
        self.module = module
        self.key = params['key']

    def runTest(self):
        """Regression test: m.new(key, m.MODE_CTR) should raise TypeError, not segfault"""
        self.assertRaises(TypeError, self.module.new, a2b_hex(self.key), self.module.MODE_CTR)

def make_block_tests(module, module_name, test_data):
    tests = []
    ctrsegfault_test_added = 0
    for i in range(len(test_data)):
        row = test_data[i]

        # Build the "params" dictionary
        params = {'mode': 'ECB'}
        if len(row) == 3:
            (params['plaintext'], params['ciphertext'], params['key']) = row
        elif len(row) == 4:
            (params['plaintext'], params['ciphertext'], params['key'], params['description']) = row
        elif len(row) == 5:
            (params['plaintext'], params['ciphertext'], params['key'], params['description'], extra_params) = row
            params.update(extra_params)
        else:
            raise AssertionError("Unsupported tuple size %d" % (len(row),))

        # Build the display-name for the test
        p2 = params.copy()
        p_key = _extract(p2, 'key')
        p_plaintext = _extract(p2, 'plaintext')
        p_ciphertext = _extract(p2, 'ciphertext')
        p_description = _extract(p2, 'description', None)
        p_mode = p2.get('mode', 'ECB')
        if p_mode == 'ECB':
            _extract(p2, 'mode', 'ECB')

        if p_description is not None:
            description = p_description
        elif p_mode == 'ECB' and not p2:
            description = "p=%s, k=%s" % (p_plaintext, p_key)
        else:
            description = "p=%s, k=%s, %r" % (p_plaintext, p_key, p2)
        name = "%s #%d: %s" % (module_name, i+1, description)
        params['description'] = name

        # Add the test to the test suite
        tests.append(CipherSelfTest(module, params))
        if not ctrsegfault_test_added:
            tests.append(CTRSegfaultTest(module, params))
            ctrsegfault_test_added = 1
    return tests

def make_stream_tests(module, module_name, test_data):
    tests = []
    for i in range(len(test_data)):
        row = test_data[i]

        # Build the "params" dictionary
        params = {}
        if len(row) == 3:
            (params['plaintext'], params['ciphertext'], params['key']) = row
        elif len(row) == 4:
            (params['plaintext'], params['ciphertext'], params['key'], params['description']) = row
        elif len(row) == 5:
            (params['plaintext'], params['ciphertext'], params['key'], params['description'], extra_params) = row
            params.update(extra_params)
        else:
            raise AssertionError("Unsupported tuple size %d" % (len(row),))

        # Build the display-name for the test
        p2 = params.copy()
        p_key = _extract(p2, 'key')
        p_plaintext = _extract(p2, 'plaintext')
        p_ciphertext = _extract(p2, 'ciphertext')
        p_description = _extract(p2, 'description', None)

        if p_description is not None:
            description = p_description
        elif not p2:
            description = "p=%s, k=%s" % (p_plaintext, p_key)
        else:
            description = "p=%s, k=%s, %r" % (p_plaintext, p_key, p2)
        name = "%s #%d: %s" % (module_name, i+1, description)
        params['description'] = name

        # Add the test to the test suite
        tests.append(CipherSelfTest(module, params))
    return tests

# vim:set ts=4 sw=4 sts=4 expandtab:
