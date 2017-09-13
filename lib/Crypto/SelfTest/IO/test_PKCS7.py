#
#  SelfTest/IO/test_PKCS8.py: Self-test for the PKCS8 module
#
# ===================================================================
#
# Copyright (c) 2017, Christoph Egger <egger@cs.fau.de>
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

"""Self-tests for Crypto.IO.PKCS8 module"""

import unittest
from binascii import unhexlify
from base64 import b64encode

from Crypto.IO.PKCS7 import import_message, PKCS7EnvelopedData
from Crypto.PublicKey.RSA import import_key
from Crypto.Util.py3compat import *


key= """
3082025c02010002818100c50c4ffc11580e6d399fa091318b453d328e205492
00fdc8cb21f51c38f034202b6ed2e29a6e6fbca918d7f3a2446768d6e865591a
dc8a5f3c1673518da8eff56db0b4eb0882dd28c15d2196c5bd9c798b0a78c0f2
47d76f46559165d907b8faa9cf9977b0da962510f6197c5ddfb7979040a54595
7070a41bfd3f4c3d56cda7020301000102818100a6cdd36fb866e85f81e62510
83f63778a4b137a11faf832654febbf55625d09a62e9ffcf1f97d932c59a6844
afda640795d548e5f31d3a6d7ffa2948a2389e57925ec2541dc9ed626c67839a
56e38a12840990e9716137ee3b5f62bd703cf871da40907ad68fe578e63dbee1
43db933998c239e13dcebd79bd96a6920fc0e491024100dc7027fd6ac76b5c38
036b6fd72300bae129eed0d54dd4deb16a85ed545992207b8f5a299d13dc7de8
19bd5e6d36fa50c9a6de01658f623b0fe958d64a60296d024100e4d62cd79d2b
46544db9107773a8459c81c955413bd5be626298453b058f4be4a955ac6248a0
6f3588f090dfb273dcb20653b3559cd3809b383ed055f8311ae302406ef5156b
fdbf7b4ee3f2f4b54af91778f9b57dbc286210f03725835c3ec50744ca6d11d9
3873b2dcbd63976a5c56fc108630343747c3b092422416cf668898d10240457d
181edd562fc417d9f3bb223eddec99a8c69fc988ad8878c21e7bbec375db58e4
703564327bb2b903bc2a81a91742641374a8b1b7b41cee667ca32e7bd2db0240
1e935b5faba88fd610e750ad1504243995f4ae75312b6995cd6867153f69814c
c744d8d1b9d1d6503f6f3f656958c777c4446668562453a7392fdc413e035d89
"""

wrapped = []

wrapped.append((
    'stream',
    b('test!'),
    """
    308006092a864886f70d010703a08030800201003181b53081b2020100301b30
    0f310d300b0603550403130454455354020859b684160e5ffe20300d06092a86
    4886f70d0101010500048180439c4562c4abf159548bd92f848345e99b785ba0
    0a6a686b58f4a2e025a9ace679cb0acc160094ac4836cf75919ff4fe60c07767
    3119fb830edbb9ab7ad0bd46662cf3ff2aeb6e7c8f2ab327e11cb769d2520957
    75a88b951f4e8281801f3bf4a2d1098615afb9e6c22170b93bbf7a4084c89eda
    fd8f885156afc6ba2831c30b308006092a864886f70d010701301d0609608648
    0165030401020410b6649fd5cf6852e6fc1e9d398a2d9c8fa0800410722914a5
    085637a5f4f89650674cf84900000000000000000000
    """
))

wrapped.append((
    'nostream',
    b('test!'),
    """
    3082010a06092a864886f70d010703a081fc3081f90201003181b53081b20201
    00301b300f310d300b0603550403130454455354020859b684160e5ffe20300d
    06092a864886f70d01010105000481808537bfd5de14d3eff6b488a3d06a6519
    205c33d7a2c14c32b443ec15d3da59b0d2e149be53fcaedeea5094806c3e5d0e
    56d8e0d4ae86df14e87d73a639b874e1a0c158587ed78d988ab13038625f1569
    1cd3d9b03e45968bdc3518d60674bc0117857b2dedeb8385139da890268d183d
    029dbcb6d4c23a6bc1fec2a1a3c3f1c2303c06092a864886f70d010701301d06
    09608648016503040102041067c4a194ee85d8a3ed6b51ecf3088d5b80102710
    a0c33ca0323209236ba8e85a52b4
    """
))


def txt2bin(inputs):
    s = b('').join([b(x) for x in inputs if not (x in '\n\r\t ')])
    return unhexlify(s)


def myhexlify(bstring):
    return " ".join(["%02x" % b for b in bstring])


class PKCS7_EnvelopedData(unittest.TestCase):
    def setUp(self):
        self._rsakey = import_key(txt2bin(key))

    # decrypt
    def test1(self):
        ber = txt2bin(wrapped[0][2])
        pkcs7 = import_message(ber)
        pkcs7.set_key(self._rsakey)
        result = pkcs7.decrypt()
        self.assertEqual(result, wrapped[0][1])

    # encrypt
    def test2(self):
        pkcs = PKCS7EnvelopedData()
        pkcs.set_key(self._rsakey)
        ber = pkcs.encode_recipient_infos().encode()
        print(myhexlify(ber))
        print(b64encode(ber))
        print(b64encode(pkcs.encode()))


def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    listTests = []
    listTests += list_test_cases(PKCS7_EnvelopedData)
    return listTests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')


