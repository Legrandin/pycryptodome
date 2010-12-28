# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/test_Blowfish.py: Self-test for the Blowfish cipher
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

"""Self-test suite for Crypto.Cipher.Blowfish"""

__revision__ = "$Id$"

from Crypto.Util.py3compat import *

# This is a list of (plaintext, ciphertext, key) tuples.
test_data = [
    # Test vectors from http://www.schneier.com/code/vectors.txt
    (b('0000000000000000'), b('4ef997456198dd78'), b('0000000000000000')),
    (b('ffffffffffffffff'), b('51866fd5b85ecb8a'), b('ffffffffffffffff')),
    (b('1000000000000001'), b('7d856f9a613063f2'), b('3000000000000000')),
    (b('1111111111111111'), b('2466dd878b963c9d'), b('1111111111111111')),
    (b('1111111111111111'), b('61f9c3802281b096'), b('0123456789abcdef')),
    (b('0123456789abcdef'), b('7d0cc630afda1ec7'), b('1111111111111111')),
    (b('0000000000000000'), b('4ef997456198dd78'), b('0000000000000000')),
    (b('0123456789abcdef'), b('0aceab0fc6a0a28d'), b('fedcba9876543210')),
    (b('01a1d6d039776742'), b('59c68245eb05282b'), b('7ca110454a1a6e57')),
    (b('5cd54ca83def57da'), b('b1b8cc0b250f09a0'), b('0131d9619dc1376e')),
    (b('0248d43806f67172'), b('1730e5778bea1da4'), b('07a1133e4a0b2686')),
    (b('51454b582ddf440a'), b('a25e7856cf2651eb'), b('3849674c2602319e')),
    (b('42fd443059577fa2'), b('353882b109ce8f1a'), b('04b915ba43feb5b6')),
    (b('059b5e0851cf143a'), b('48f4d0884c379918'), b('0113b970fd34f2ce')),
    (b('0756d8e0774761d2'), b('432193b78951fc98'), b('0170f175468fb5e6')),
    (b('762514b829bf486a'), b('13f04154d69d1ae5'), b('43297fad38e373fe')),
    (b('3bdd119049372802'), b('2eedda93ffd39c79'), b('07a7137045da2a16')),
    (b('26955f6835af609a'), b('d887e0393c2da6e3'), b('04689104c2fd3b2f')),
    (b('164d5e404f275232'), b('5f99d04f5b163969'), b('37d06bb516cb7546')),
    (b('6b056e18759f5cca'), b('4a057a3b24d3977b'), b('1f08260d1ac2465e')),
    (b('004bd6ef09176062'), b('452031c1e4fada8e'), b('584023641aba6176')),
    (b('480d39006ee762f2'), b('7555ae39f59b87bd'), b('025816164629b007')),
    (b('437540c8698f3cfa'), b('53c55f9cb49fc019'), b('49793ebc79b3258f')),
    (b('072d43a077075292'), b('7a8e7bfa937e89a3'), b('4fb05e1515ab73a7')),
    (b('02fe55778117f12a'), b('cf9c5d7a4986adb5'), b('49e95d6d4ca229bf')),
    (b('1d9d5c5018f728c2'), b('d1abb290658bc778'), b('018310dc409b26d6')),
    (b('305532286d6f295a'), b('55cb3774d13ef201'), b('1c587f1c13924fef')),
    (b('0123456789abcdef'), b('fa34ec4847b268b2'), b('0101010101010101')),
    (b('0123456789abcdef'), b('a790795108ea3cae'), b('1f1f1f1f0e0e0e0e')),
    (b('0123456789abcdef'), b('c39e072d9fac631d'), b('e0fee0fef1fef1fe')),
    (b('ffffffffffffffff'), b('014933e0cdaff6e4'), b('0000000000000000')),
    (b('0000000000000000'), b('f21e9a77b71c49bc'), b('ffffffffffffffff')),
    (b('0000000000000000'), b('245946885754369a'), b('0123456789abcdef')),
    (b('ffffffffffffffff'), b('6b5c5a9c5d9e0a5a'), b('fedcba9876543210')),
    (b('fedcba9876543210'), b('f9ad597c49db005e'), b('f0')),
    (b('fedcba9876543210'), b('e91d21c1d961a6d6'), b('f0e1')),
    (b('fedcba9876543210'), b('e9c2b70a1bc65cf3'), b('f0e1d2')),
    (b('fedcba9876543210'), b('be1e639408640f05'), b('f0e1d2c3')),
    (b('fedcba9876543210'), b('b39e44481bdb1e6e'), b('f0e1d2c3b4')),
    (b('fedcba9876543210'), b('9457aa83b1928c0d'), b('f0e1d2c3b4a5')),
    (b('fedcba9876543210'), b('8bb77032f960629d'), b('f0e1d2c3b4a596')),
    (b('fedcba9876543210'), b('e87a244e2cc85e82'), b('f0e1d2c3b4a59687')),
    (b('fedcba9876543210'), b('15750e7a4f4ec577'), b('f0e1d2c3b4a5968778')),
    (b('fedcba9876543210'), b('122ba70b3ab64ae0'), b('f0e1d2c3b4a596877869')),
    (b('fedcba9876543210'), b('3a833c9affc537f6'), b('f0e1d2c3b4a5968778695a')),
    (b('fedcba9876543210'), b('9409da87a90f6bf2'), b('f0e1d2c3b4a5968778695a4b')),
    (b('fedcba9876543210'), b('884f80625060b8b4'), b('f0e1d2c3b4a5968778695a4b3c')),
    (b('fedcba9876543210'), b('1f85031c19e11968'), b('f0e1d2c3b4a5968778695a4b3c2d')),
    (b('fedcba9876543210'), b('79d9373a714ca34f'), b('f0e1d2c3b4a5968778695a4b3c2d1e')),
    (b('fedcba9876543210'), b('93142887ee3be15c'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f')),
    (b('fedcba9876543210'), b('03429e838ce2d14b'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f00')),
    (b('fedcba9876543210'), b('a4299e27469ff67b'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f0011')),
    (b('fedcba9876543210'), b('afd5aed1c1bc96a8'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f001122')),
    (b('fedcba9876543210'), b('10851c0e3858da9f'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f00112233')),
    (b('fedcba9876543210'), b('e6f51ed79b9db21f'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344')),
    (b('fedcba9876543210'), b('64a6e14afd36b46f'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f001122334455')),
    (b('fedcba9876543210'), b('80c7d7d45a5479ad'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566')),
    (b('fedcba9876543210'), b('05044b62fa52d080'),
        b('f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344556677')),
]

def get_tests(config={}):
    from Crypto.Cipher import Blowfish
    from common import make_block_tests
    return make_block_tests(Blowfish, "Blowfish", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
