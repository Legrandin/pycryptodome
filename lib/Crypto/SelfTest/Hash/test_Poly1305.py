#
#  SelfTest/Hash/test_Poly1305.py: Self-test for the Poly1305 module
#
# ===================================================================
#
# Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
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

"""Self-test suite for Crypto.Hash._Poly1305"""

import json
import unittest

from common import make_mac_tests
from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Util.py3compat import tobytes, _memoryview, unhexlify, hexlify

from Crypto.Hash import Poly1305
from Crypto.Cipher import AES

from Crypto.Util.strxor import strxor_c

# This is a list of (r+s keypair, data, result, description, keywords) tuples.
test_data_basic = [
    (
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        hexlify(b"Cryptographic Forum Research Group").decode(),
        "a8061dc1305136c6c22b8baf0c0127a9",
        "RFC7539",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "49ec78090e481ec6c26b33b91ccc0307",
        "https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7 A",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "48656c6c6f20776f726c6421",
        "a6f745008f81c916a20dcc74eef2b2f0",
        "https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7 B",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "",
        "6b657920666f7220506f6c7931333035",
        "Generated with pure Python",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "FF",
        "f7e4e0ef4c46d106219da3d1bdaeb3ff",
        "Generated with pure Python",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "FF00",
        "7471eceeb22988fc936da1d6e838b70e",
        "Generated with pure Python",
        {}
    ),
    (
        "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
        "AA" * 17,
        "32590bc07cb2afaccca3f67f122975fe",
        "Generated with pure Python",
        {}
    ),
]

# This is a list of (key(k+r), data, result, description, keywords) tuples.
test_data_aes = [
    (
        "ec074c835580741701425b623235add6851fc40c3467ac0be05cc20404f3f700",
        "f3f6",
        "f4c633c3044fc145f84f335cb81953de",
        "http://cr.yp.to/mac/poly1305-20050329.pdf",
        { 'cipher':AES, 'nonce':unhexlify("fb447350c4e868c52ac3275cf9d4327e") }
    ),
    (
        "75deaa25c09f208e1dc4ce6b5cad3fbfa0f3080000f46400d0c7e9076c834403",
        "",
        "dd3fab2251f11ac759f0887129cc2ee7",
        "http://cr.yp.to/mac/poly1305-20050329.pdf",
        { 'cipher':AES, 'nonce':unhexlify("61ee09218d29b0aaed7e154a2c5509cc") }
    ),
    (
        "6acb5f61a7176dd320c5c1eb2edcdc7448443d0bb0d21109c89a100b5ce2c208",
        "663cea190ffb83d89593f3f476b6bc24"
        "d7e679107ea26adb8caf6652d0656136",
        "0ee1c16bb73f0f4fd19881753c01cdbe",
        "http://cr.yp.to/mac/poly1305-20050329.pdf",
        { 'cipher':AES, 'nonce':unhexlify("ae212a55399729595dea458bc621ff0e") }
    ),
    (
        "e1a5668a4d5b66a5f68cc5424ed5982d12976a08c4426d0ce8a82407c4f48207",
        "ab0812724a7f1e342742cbed374d94d1"
        "36c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67"
        "fa83e158c994d961c4cb21095c1bf9",
        "5154ad0d2cb26e01274fc51148491f1b",
        "http://cr.yp.to/mac/poly1305-20050329.pdf",
        { 'cipher':AES, 'nonce':unhexlify("9ae831e743978d3a23527c7128149e3a") }
    ),
]

class Poly1305Test(unittest.TestCase):

    key = b'\x11' * 32

    def test_new_positive(self):

        data = b'r' * 100

        h1 = Poly1305.new(self.key)
        self.assertEqual(h1.digest_size, 16)
        d1 = h1.update(data).digest()
        self.assertEqual(len(d1), 16)

        h2 = Poly1305.new(self.key, data)
        d2 = h2.digest()
        self.assertEqual(d1, d2)

    def test_new_negative(self):

        self.assertRaises(ValueError, Poly1305.new, self.key[:31])
        self.assertRaises(TypeError, Poly1305.new, u"2" * 32)
        self.assertRaises(TypeError, Poly1305.new, self.key, u"2" * 100)

    def test_update(self):
        pieces = [b"\x0A" * 200, b"\x14" * 300]
        h1 = Poly1305.new(self.key)
        h1.update(pieces[0]).update(pieces[1])
        d1 = h1.digest()

        h2 = Poly1305.new(self.key)
        h2.update(pieces[0] + pieces[1])
        d2 = h2.digest()
        self.assertEqual(d1, d2)

    def test_update_negative(self):
        h = Poly1305.new(self.key)
        self.assertRaises(TypeError, h.update, u"string")

    def test_digest(self):
        h = Poly1305.new(self.key)
        digest = h.digest()

        # hexdigest does not change the state
        self.assertEqual(h.digest(), digest)
        # digest returns a byte string
        self.failUnless(isinstance(digest, type(b"digest")))

    def test_update_after_digest(self):
        msg=b"rrrrttt"

        # Normally, update() cannot be done after digest()
        h = Poly1305.new(self.key, msg[:4])
        h.digest()
        self.assertRaises(TypeError, h.update, msg[4:])

    def test_hex_digest(self):
        mac = Poly1305.new(self.key)
        digest = mac.digest()
        hexdigest = mac.hexdigest()

        # hexdigest is equivalent to digest
        self.assertEqual(hexlify(digest), tobytes(hexdigest))
        # hexdigest does not change the state
        self.assertEqual(mac.hexdigest(), hexdigest)
        # hexdigest returns a string
        self.failUnless(isinstance(hexdigest, type("digest")))

    def test_verify(self):
        h = Poly1305.new(self.key)
        mac = h.digest()
        h.verify(mac)
        wrong_mac = strxor_c(mac, 255)
        self.assertRaises(ValueError, h.verify, wrong_mac)

    def test_hexverify(self):
        h = Poly1305.new(self.key)
        mac = h.hexdigest()
        h.hexverify(mac)
        self.assertRaises(ValueError, h.hexverify, "4556")

    def test_bytearray(self):

        data = b"\x00\x01\x02"
        d_ref = Poly1305.new(self.key, data).digest()

        # Data and key can be a bytearray (during initialization)
        key_ba = bytearray(self.key)
        data_ba = bytearray(data)

        h1 = Poly1305.new(self.key, data)
        h2 = Poly1305.new(key_ba, data_ba)
        key_ba[:1] = b'\xFF'
        data_ba[:1] = b'\xEE'

        self.assertEqual(h1.digest(), d_ref)
        self.assertEqual(h2.digest(), d_ref)

        # Data can be a bytearray (during operation)
        data_ba = bytearray(data)

        h1 = Poly1305.new(self.key)
        h2 = Poly1305.new(self.key)
        h1.update(data)
        h2.update(data_ba)
        data_ba[:1] = b'\xFF'

        self.assertEqual(h1.digest(), h2.digest())

    def test_memoryview(self):

        data = b"\x00\x01\x02"

        def get_mv_ro(data):
            return memoryview(data)

        def get_mv_rw(data):
            return memoryview(bytearray(data))

        for get_mv in (get_mv_ro, get_mv_rw):

            # Data and key can be a memoryview (during initialization)
            key_mv = get_mv(self.key)
            data_mv = get_mv(data)

            h1 = Poly1305.new(self.key, data)
            h2 = Poly1305.new(key_mv, data_mv)
            if not data_mv.readonly:
                data_mv[:1] = b'\xFF'
                key_mv[:1] = b'\xFF'

            self.assertEqual(h1.digest(), h2.digest())

            # Data can be a memoryview (during operation)
            data_mv = get_mv(data)

            h1 = Poly1305.new(self.key)
            h2 = Poly1305.new(self.key)
            h1.update(data)
            h2.update(data_mv)
            if not data_mv.readonly:
                data_mv[:1] = b'\xFF'

            self.assertEqual(h1.digest(), h2.digest())

    import types
    if _memoryview == types.NoneType:
        del test_memoryview


#
# make_mac_tests() expect a new() function with signature new(key, data,
# **kwargs), and we need to adapt Poly1305's, as it only uses keywords
#
class Poly1305_New(object):

    @staticmethod
    def new(key, *data, **kwds):
        _kwds = dict(kwds)
        if len(data) == 1:
            _kwds['data'] = data[0]
        _kwds['key'] = key
        return Poly1305.new(**_kwds)


class Poly1305_Basic(object):

    @staticmethod
    def new(key, *data, **kwds):
        from Crypto.Hash.Poly1305 import Poly1305_MAC

        if len(data) == 1:
            msg = data[0]
        else:
            msg = None

        return Poly1305_MAC(key[:16], key[16:], msg)


def get_tests(config={}):
    tests = make_mac_tests(Poly1305_Basic, "Poly1305", test_data_basic)
    tests += make_mac_tests(Poly1305_New, "Poly1305", test_data_aes)
    #tests += list_test_cases(Poly1305Test)
    return tests


if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
