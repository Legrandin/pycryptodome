# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/RC5.py: Self-test for the RC5 cipher
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

"""Self-test suite for Crypto.Cipher.RC5"""

__revision__ = "$Id$"

from common import dict     # For compatibility with Python 2.1 and 2.2

# This is a list of (plaintext, ciphertext, key, description or None, extra_params) tuples.
test_data = [
    # Test vectors from http://theory.lcs.mit.edu/~rivest/Rivest-rc5rev.pdf
    # Rivest, R. L. (1994). "The RC5 Encryption Algorithm" (pdf). Proceedings
    # of the Second International Workshop on Fast Software Encryption (FSE)
    # 1994e: 86–96.
    ('0000000000000000', '21a5dbee154b8f6d', '00000000000000000000000000000000',
        "Rivest94-1", dict(word_size=32, rounds=12)),
    ('21a5dbee154b8f6d', 'f7c013ac5b2b8952', '915f4619be41b2516355a50110a9ce91',
        "Rivest94-2", dict(word_size=32, rounds=12)),
    ('f7c013ac5b2b8952', '2f42b3b70369fc92', '783348e75aeb0f2fd7b169bb8dc16787',
        "Rivest94-3", dict(word_size=32, rounds=12)),
    ('2f42b3b70369fc92', '65c178b284d197cc', 'dc49db1375a5584f6485b413b5f12baf',
        "Rivest94-4", dict(word_size=32, rounds=12)),
    ('65c178b284d197cc', 'eb44e415da319824', '5269f149d41ba0152497574d7f153125',
        "Rivest94-5", dict(word_size=32, rounds=12)),

    # Test vectors from RFC 2040
    ('0000000000000000', '7a7bba4d79111d1e', '00', 'RFC2040-1', dict(rounds=0, mode='CBC', iv='0000000000000000')),
    ('ffffffffffffffff', '797bba4d78111d1e', '00', 'RFC2040-2', dict(rounds=0, mode='CBC', iv='0000000000000000')),
    ('0000000000000000', '7a7bba4d79111d1f', '00', 'RFC2040-3', dict(rounds=0, mode='CBC', iv='0000000000000001')),
    ('0000000000000001', '7a7bba4d79111d1f', '00', 'RFC2040-4', dict(rounds=0, mode='CBC', iv='0000000000000000')),
    ('1020304050607080', '8b9ded91ce7794a6', '00', 'RFC2040-5', dict(rounds=0, mode='CBC', iv='0102030405060708')),
    ('0000000000000000', '2f759fe7ad86a378', '11', 'RFC2040-6', dict(rounds=1, mode='CBC', iv='0000000000000000')),
    ('0000000000000000', 'dca2694bf40e0788', '00', 'RFC2040-7', dict(rounds=2, mode='CBC', iv='0000000000000000')),
    ('0000000000000000', 'dca2694bf40e0788', '00000000', 'RFC2040-8', dict(rounds=2, mode='CBC', iv='0000000000000000')),
    ('0000000000000000', 'dcfe098577eca5ff', '00', 'RFC2040-9', dict(rounds=8, mode='CBC', iv='0000000000000000')),
    ('1020304050607080', '9646fb77638f9ca8', '00', 'RFC2040-10', dict(rounds=8, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', 'b2b3209db6594da4', '00', 'RFC2040-11', dict(rounds=12, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', '545f7f32a5fc3836', '00', 'RFC2040-12', dict(rounds=16, mode='CBC', iv='0102030405060708')),
    ('ffffffffffffffff', '8285e7c1b5bc7402', '01020304', 'RFC2040-13', dict(rounds=8, mode='CBC', iv='0000000000000000')),
    ('ffffffffffffffff', 'fc586f92f7080934', '01020304', 'RFC2040-14', dict(rounds=12, mode='CBC', iv='0000000000000000')),
    ('ffffffffffffffff', 'cf270ef9717ff7c4', '01020304', 'RFC2040-15', dict(rounds=16, mode='CBC', iv='0000000000000000')),
    ('ffffffffffffffff', 'e493f1c1bb4d6e8c', '0102030405060708', 'RFC2040-16', dict(rounds=12, mode='CBC', iv='0000000000000000')),
    ('1020304050607080', '5c4c041e0f217ac3', '0102030405060708', 'RFC2040-17', dict(rounds=8, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', '921f12485373b4f7', '0102030405060708', 'RFC2040-18', dict(rounds=12, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', '5ba0ca6bbe7f5fad', '0102030405060708', 'RFC2040-19', dict(rounds=16, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', 'c533771cd0110e63', '01020304050607081020304050607080', 'RFC2040-20', dict(rounds=8, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', '294ddb46b3278d60', '01020304050607081020304050607080', 'RFC2040-21', dict(rounds=12, mode='CBC', iv='0102030405060708')),
    ('1020304050607080', 'dad6bda9dfe8f7e8', '01020304050607081020304050607080', 'RFC2040-22', dict(rounds=16, mode='CBC', iv='0102030405060708')),
    ('ffffffffffffffff', '97e0787837ed317f', '0102030405', 'RFC2040-23', dict(rounds=12, mode='CBC', iv='0000000000000000')),
    ('ffffffffffffffff', '7875dbf6738c6478', '0102030405', 'RFC2040-24', dict(rounds=8, mode='CBC', iv='0000000000000000')),
    ('0808080808080808', '8f34c3c681c99695', '0102030405', 'RFC2040-25', dict(rounds=8, mode='CBC', iv='7875dbf6738c6478')),
#    ('ffffffffffffffff', '7875dbf6738c64788f34c3c681c99695', '0102030405', 'RFC2040-26', dict(rounds=8, mode='CBC-Pad', iv='0000000000000000')),
    ('0000000000000000', '7cb3f1df34f94811', '0102030405', 'RFC2040-27', dict(rounds=8, mode='CBC', iv='0000000000000000')),
    ('1122334455667701', '7fd1a023a5bba217', '0102030405', 'RFC2040-28', dict(rounds=8, mode='CBC', iv='7cb3f1df34f94811')),
#    ('ffffffffffffffff7875dbf6738c647811223344556677', '7875dbf6738c64787cb3f1df34f948117fd1a023a5bba217', '0102030405', 'RFC2040-29', dict(rounds=8, mode='CBC-Pad', iv='0000000000000000')),
]

def get_tests():
    from Crypto.Cipher import RC5
    from common import make_block_tests
    return make_block_tests(RC5, "RC5", test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
