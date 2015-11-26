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

import unittest
from binascii import a2b_hex, b2a_hex, hexlify

from Crypto.Util.py3compat import *
from Crypto.Util.strxor import strxor_c

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
        self.key = b(_extract(params, 'key'))
        self.plaintext = b(_extract(params, 'plaintext'))
        self.ciphertext = b(_extract(params, 'ciphertext'))
        self.module_name = _extract(params, 'module_name', None)
        self.assoc_data = _extract(params, 'assoc_data', None)
        self.mac = _extract(params, 'mac', None)
        if self.assoc_data:
            self.mac = b(self.mac)

        mode = _extract(params, 'mode', None)
        self.mode_name = str(mode)

        if mode is not None:
            # Block cipher
            self.mode = getattr(self.module, "MODE_" + mode)

            self.iv = _extract(params, 'iv', None)
            if self.iv is None:
                self.iv = _extract(params, 'nonce', None)
            if self.iv is not None:
                self.iv = b(self.iv)

        else:
            # Stream cipher
            self.mode = None
            self.iv = _extract(params, 'iv', None)
            if self.iv is not None:
                self.iv = b(self.iv)

        self.extra_params = params

    def shortDescription(self):
        return self.description

    def _new(self, do_decryption=0):
        params = self.extra_params.copy()

        if self.mode is None:
            if self.iv is None:
                return self.module.new(a2b_hex(self.key), **params)
            else:
                return self.module.new(a2b_hex(self.key), a2b_hex(self.iv), **params)
        elif self.iv is None:
            # Block cipher without iv
            return self.module.new(a2b_hex(self.key), self.mode, **params)
        else:
            return self.module.new(a2b_hex(self.key), self.mode, a2b_hex(self.iv), **params)

    def isMode(self, name):
        if not hasattr(self.module, "MODE_"+name):
            return False
        return self.mode == getattr(self.module, "MODE_"+name)

    def runTest(self):
        plaintext = a2b_hex(self.plaintext)
        ciphertext = a2b_hex(self.ciphertext)
        assoc_data = []
        if self.assoc_data:
            assoc_data = [ a2b_hex(b(x)) for x in self.assoc_data]

        ct = None
        pt = None

        #
        # Repeat the same encryption or decryption twice and verify
        # that the result is always the same
        #
        for i in xrange(2):
            cipher = self._new()
            decipher = self._new(1)

            # Only AEAD modes
            for comp in assoc_data:
                cipher.update(comp)
                decipher.update(comp)

            ctX = b2a_hex(cipher.encrypt(plaintext))
            if self.isMode("SIV"):
                ptX = b2a_hex(decipher.decrypt_and_verify(ciphertext, a2b_hex(self.mac)))
            else:
                ptX = b2a_hex(decipher.decrypt(ciphertext))

            if ct:
                self.assertEqual(ct, ctX)
                self.assertEqual(pt, ptX)
            ct, pt = ctX, ptX

        self.assertEqual(self.ciphertext, ct)  # encrypt
        self.assertEqual(self.plaintext, pt)   # decrypt

        if self.mac:
            mac = b2a_hex(cipher.digest())
            self.assertEqual(self.mac, mac)
            decipher.verify(a2b_hex(self.mac))

class CipherStreamingSelfTest(CipherSelfTest):

    def shortDescription(self):
        desc = self.module_name
        if self.mode is not None:
            desc += " in %s mode" % (self.mode_name,)
        return "%s should behave like a stream cipher" % (desc,)

    def runTest(self):
        plaintext = a2b_hex(self.plaintext)
        ciphertext = a2b_hex(self.ciphertext)

        # The cipher should work like a stream cipher

        # Test counter mode encryption, 3 bytes at a time
        ct3 = []
        cipher = self._new()
        for i in range(0, len(plaintext), 3):
            ct3.append(cipher.encrypt(plaintext[i:i+3]))
        ct3 = b2a_hex(b("").join(ct3))
        self.assertEqual(self.ciphertext, ct3)  # encryption (3 bytes at a time)

        # Test counter mode decryption, 3 bytes at a time
        pt3 = []
        cipher = self._new()
        for i in range(0, len(ciphertext), 3):
            pt3.append(cipher.encrypt(ciphertext[i:i+3]))
        # PY3K: This is meant to be text, do not change to bytes (data)
        pt3 = b2a_hex(b("").join(pt3))
        self.assertEqual(self.plaintext, pt3)  # decryption (3 bytes at a time)


class AEADTests(unittest.TestCase):
    """Tests generic to all AEAD modes"""

    def __init__(self, module, mode_name, key_size):
        unittest.TestCase.__init__(self)
        self.module = module
        self.mode_name = mode_name
        self.mode = getattr(module, mode_name)
        if not self.isMode("SIV"):
            self.key = b('\xFF')*key_size
        else:
            self.key = b('\xFF')*key_size*2
        self.iv = b('\x00')*10
        self.description = "AEAD Test"

    def isMode(self, name):
        if not hasattr(self.module, "MODE_"+name):
            return False
        return self.mode == getattr(self.module, "MODE_"+name)

    def right_mac_test(self):
        """Positive tests for MAC"""

        self.description = "Test for right MAC in %s of %s" % \
            (self.mode_name, self.module.__name__)

        ad_ref = b("Reference AD")
        pt_ref = b("Reference plaintext")

        # Encrypt and create the reference MAC
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.update(ad_ref)
        ct_ref = cipher.encrypt(pt_ref)
        mac_ref = cipher.digest()

        # Decrypt and verify that MAC is accepted
        decipher = self.module.new(self.key, self.mode, self.iv)
        decipher.update(ad_ref)
        pt = decipher.decrypt_and_verify(ct_ref, mac_ref)
        self.assertEqual(pt, pt_ref)

        # Verify that hexverify work
        decipher.hexverify(hexlify(mac_ref))

    def wrong_mac_test(self):
        """Negative tests for MAC"""

        self.description = "Test for wrong MAC in %s of %s" % \
            (self.mode_name, self.module.__name__)

        ad_ref = b("Reference AD")
        pt_ref = b("Reference plaintext")

        # Encrypt and create the reference MAC
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.update(ad_ref)
        ct_ref = cipher.encrypt(pt_ref)
        mac_ref = cipher.digest()

        # Modify the MAC and verify it is NOT ACCEPTED
        wrong_mac = strxor_c(mac_ref, 255)
        decipher = self.module.new(self.key, self.mode, self.iv)
        decipher.update(ad_ref)
        self.assertRaises(ValueError, decipher.decrypt_and_verify,
                          ct_ref, wrong_mac)

    def zero_data(self):
        """Verify transition from INITIALIZED to FINISHED"""

        self.description = "Test for zero data in %s of %s" % \
            (self.mode_name, self.module.__name__)
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.digest()

    def multiple_updates(self):
        """Verify that update() can be called multiple times"""

        self.description = "Test for multiple updates in %s of %s" % \
            (self.mode_name, self.module.__name__)

        # In all modes other than SIV, the associated data is a single
        # component that can be arbitrarilly split and submitted to update().
        #
        # In SIV, associated data is instead organized in a vector or multiple
        # components. Each component is passed to update() as a whole.
        # This test is therefore not meaningful to SIV.
        if self.isMode("SIV"):
            return

        ad = b("").join([bchr(x) for x in xrange(0,128)])

        mac1, mac2, mac3 = (None,)*3
        for chunk_length in 1,10,40,80,128:
            chunks = [ad[i:i+chunk_length] for i in range(0, len(ad), chunk_length)]

            # No encryption/decryption
            cipher = self.module.new(self.key, self.mode, self.iv)
            for c in chunks:
                cipher.update(c)
            if mac1:
                cipher.verify(mac1)
            else:
                mac1 = cipher.digest()

            # Encryption
            cipher = self.module.new(self.key, self.mode, self.iv)
            for c in chunks:
                cipher.update(c)
            ct = cipher.encrypt(b("PT"))
            mac2 = cipher.digest()

            # Decryption
            cipher = self.module.new(self.key, self.mode, self.iv)
            for c in chunks:
                cipher.update(c)
            cipher.decrypt(ct)
            cipher.verify(mac2)

    def no_mix_encrypt_decrypt(self):
        """Verify that encrypt and decrypt cannot be mixed up"""

        self.description = "Test for mix of encrypt and decrypt in %s of %s" % \
            (self.mode_name, self.module.__name__)

        # Calling decrypt after encrypt raises an exception
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.encrypt(b("PT")*40)
        self.assertRaises(TypeError, cipher.decrypt, b("XYZ")*40)

        # Calling encrypt() after decrypt() raises an exception
        # (excluded for SIV, since decrypt() is not valid)
        if not self.isMode("SIV"):
            cipher = self.module.new(self.key, self.mode, self.iv)
            cipher.decrypt(b("CT")*40)
            self.assertRaises(TypeError, cipher.encrypt, b("XYZ")*40)

        # Calling verify after encrypt raises an exception
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.encrypt(b("PT")*40)
        self.assertRaises(TypeError, cipher.verify, b("XYZ"))
        self.assertRaises(TypeError, cipher.hexverify, "12")

        # Calling digest() after decrypt() raises an exception
        # (excluded for SIV, since decrypt() is not valid)
        if not self.isMode("SIV"):
            cipher = self.module.new(self.key, self.mode, self.iv)
            cipher.decrypt(b("CT")*40)
            self.assertRaises(TypeError, cipher.digest)
            self.assertRaises(TypeError, cipher.hexdigest)

    def no_late_update(self):
        """Verify that update cannot be called after encrypt or decrypt"""

        self.description = "Test for late update in %s of %s" % \
            (self.mode_name, self.module.__name__)

        # Calling update after encrypt raises an exception
        cipher = self.module.new(self.key, self.mode, self.iv)
        cipher.update(b("XX"))
        cipher.encrypt(b("PT")*40)
        self.assertRaises(TypeError, cipher.update, b("XYZ"))

        # Calling update() after decrypt() raises an exception
        # (excluded for SIV, since decrypt() is not valid)
        if not self.isMode("SIV"):
            cipher = self.module.new(self.key, self.mode, self.iv)
            cipher.update(b("XX"))
            cipher.decrypt(b("CT")*40)
            self.assertRaises(TypeError, cipher.update, b("XYZ"))

    def loopback(self):
        """Verify composition of encrypt_and_digest() and decrypt_and_verify()
        is the identity function."""

        self.description  = "Lookback test decrypt_and_verify(encrypt_and_digest)"\
                            "for %s in %s" % (self.mode_name,
                            self.module.__name__)

        enc_cipher = self.module.new(self.key, self.mode, self.iv)
        dec_cipher = self.module.new(self.key, self.mode, self.iv)

        enc_cipher.update(b("XXX"))
        dec_cipher.update(b("XXX"))

        plaintext = b("Reference") * 10
        ct, mac = enc_cipher.encrypt_and_digest(plaintext)
        pt = dec_cipher.decrypt_and_verify(ct, mac)

        self.assertEqual(plaintext, pt)

    def runTest(self):
        self.right_mac_test()
        self.wrong_mac_test()
        self.zero_data()
        self.multiple_updates()
        self.no_mix_encrypt_decrypt()
        self.no_late_update()
        self.loopback()

    def shortDescription(self):
        return self.description

class RoundtripTest(unittest.TestCase):
    def __init__(self, module, params):
        from Crypto import Random
        unittest.TestCase.__init__(self)
        self.module = module
        self.iv = Random.get_random_bytes(module.block_size)
        self.key = b(params['key'])
        self.plaintext = 100 * b(params['plaintext'])
        self.module_name = params.get('module_name', None)

    def shortDescription(self):
        return """%s .decrypt() output of .encrypt() should not be garbled""" % (self.module_name,)

    def runTest(self):

        ## ECB mode
        mode = self.module.MODE_ECB
        encryption_cipher = self.module.new(a2b_hex(self.key), mode)
        ciphertext = encryption_cipher.encrypt(self.plaintext)
        decryption_cipher = self.module.new(a2b_hex(self.key), mode)
        decrypted_plaintext = decryption_cipher.decrypt(ciphertext)
        self.assertEqual(self.plaintext, decrypted_plaintext)


class IVLengthTest(unittest.TestCase):
    def __init__(self, module, params):
        unittest.TestCase.__init__(self)
        self.module = module
        self.key = b(params['key'])

    def shortDescription(self):
        return "Check that all modes except MODE_ECB and MODE_CTR require an IV of the proper length"

    def runTest(self):
        self.assertRaises(TypeError, self.module.new, a2b_hex(self.key),
                self.module.MODE_ECB, b(""))

    def _dummy_counter(self):
        return "\0" * self.module.block_size

class NoDefaultECBTest(unittest.TestCase):
    def __init__(self, module, params):
        unittest.TestCase.__init__(self)
        self.module = module
        self.key = b(params['key'])

    def runTest(self):
        self.assertRaises(TypeError, self.module.new, a2b_hex(self.key))


def make_block_tests(module, module_name, test_data, additional_params=dict()):
    tests = []
    extra_tests_added = 0
    for i in range(len(test_data)):
        row = test_data[i]

        # Build the "params" dictionary with
        # - plaintext
        # - ciphertext
        # - key
        # - mode (default is ECB)
        # - (optionally) description
        # - (optionally) any other parameter that this cipher mode requires
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

        if not params.has_key("mode"):
            params["mode"] = "ECB"

        # Build the display-name for the test
        p2 = params.copy()
        p_key = _extract(p2, 'key')
        p_plaintext = _extract(p2, 'plaintext')
        p_ciphertext = _extract(p2, 'ciphertext')
        p_mode = _extract(p2, 'mode')
        p_description = _extract(p2, 'description', None)

        if p_description is not None:
            description = p_description
        elif p_mode == 'ECB' and not p2:
            description = "p=%s, k=%s" % (p_plaintext, p_key)
        else:
            description = "p=%s, k=%s, %r" % (p_plaintext, p_key, p2)
        name = "%s #%d: %s" % (module_name, i+1, description)
        params['description'] = name
        params['module_name'] = module_name
        params.update(additional_params)

        # Add extra test(s) to the test suite before the current test
        if not extra_tests_added:
            tests += [
                RoundtripTest(module, params),
                IVLengthTest(module, params),
                NoDefaultECBTest(module, params),
            ]
            extra_tests_added = 1

        # Extract associated data and MAC for AEAD modes
        if p_mode in ('EAX', 'SIV', 'GCM'):
            assoc_data, params['plaintext'] = params['plaintext'].split('|')
            assoc_data2, params['ciphertext'], params['mac'] = params['ciphertext'].split('|')
            params['assoc_data'] = assoc_data.split("-")
            if p_mode not in ('SIV', ):
                params['mac_len'] = len(params['mac'])>>1

        # Add the current test to the test suite
        tests.append(CipherSelfTest(module, params))

    # Add tests that don't use test vectors
    for aead_mode in ("MODE_EAX", "MODE_SIV", "MODE_GCM"):
        if hasattr(module, aead_mode):
            key_sizes = []
            try:
                key_sizes += module.key_size
            except TypeError:
                key_sizes = [ module.key_size ]
            for ks in key_sizes:
                tests += [
                    AEADTests(module, aead_mode, ks),
                ]

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
        params['module_name'] = module_name

        # Add the test to the test suite
        tests.append(CipherSelfTest(module, params))
        tests.append(CipherStreamingSelfTest(module, params))
    return tests

# vim:set ts=4 sw=4 sts=4 expandtab:
