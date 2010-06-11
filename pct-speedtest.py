#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  pct-speedtest.py: Speed test for the Python Cryptography Toolkit
#
# Written in 2009 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

import time
import os
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, ARC2, ARC4, Blowfish, CAST, DES3, DES, XOR
from Crypto.Hash import MD2, MD4, MD5, SHA256, SHA
try:
    from Crypto.Hash import RIPEMD
except ImportError: # Some builds of PyCrypto don't have the RIPEMD module
    RIPEMD = None

class Benchmark:

    def __init__(self):
        self.__random_data = None

    def random_keys(self, bytes):
        """Return random keys of the specified number of bytes.

        If this function has been called before with the same number of bytes,
        cached keys are used instead of randomly generating new ones.
        """
        return self.random_blocks(bytes, 10**5)     # 100k

    def random_blocks(self, bytes_per_block, blocks):
        bytes = bytes_per_block * blocks
        data = self.random_data(bytes)
        retval = []
        for i in xrange(blocks):
            p = i * bytes_per_block
            retval.append(data[p:p+bytes_per_block])
        return retval

    def random_data(self, bytes):
        if self.__random_data is None:
            self.__random_data = self._random_bytes(bytes)
            return self.__random_data
        elif bytes == len(self.__random_data):
            return self.__random_data
        elif bytes < len(self.__random_data):
            return self.__random_data[:bytes]
        else:
            self.__random_data += self._random_bytes(bytes - len(self.__random_data))
            return self.__random_data

    def _random_bytes(self, b):
        return os.urandom(b)

    def announce_start(self, test_name):
        sys.stdout.write("%s: " % (test_name,))
        sys.stdout.flush()

    def announce_result(self, value, units):
        sys.stdout.write("%.2f %s\n" % (value, units))
        sys.stdout.flush()

    def test_pubkey_setup(self, pubkey_name, module, key_bytes):
        self.announce_start("%s pubkey setup" % (pubkey_name,))
        keys = self.random_keys(key_bytes)[:5]

        t0 = time.time()
        for k in keys:
            module.generate(key_bytes*8)
        t = time.time()
        pubkey_setups_per_second = len(keys) / (t - t0)
        self.announce_result(pubkey_setups_per_second, "Keys/sec")

    def test_key_setup(self, cipher_name, module, key_bytes, mode):
        self.announce_start("%s key setup" % (cipher_name,))

        # Generate random keys for use with the tests
        keys = self.random_keys(key_bytes)

        # Perform key setups
        if mode is None:
            t0 = time.time()
            for k in keys:
                module.new(k)
            t = time.time()
        else:
            t0 = time.time()
            for k in keys:
                module.new(k, module.MODE_ECB)
            t = time.time()

        key_setups_per_second = len(keys) / (t - t0)
        self.announce_result(key_setups_per_second/1000, "kKeys/sec")

    def test_encryption(self, cipher_name, module, key_bytes, mode):
        self.announce_start("%s encryption" % (cipher_name,))

        # Generate random keys for use with the tests
        rand = self.random_data(key_bytes + module.block_size)
        key, iv = rand[:key_bytes], rand[key_bytes:]
        blocks = self.random_blocks(16384, 1000)
        if mode is None:
            cipher = module.new(key)
        else:
            cipher = module.new(key, mode, iv)

        # Perform encryption
        t0 = time.time()
        for b in blocks:
            cipher.encrypt(b)
        t = time.time()

        encryption_speed = (len(blocks) * len(blocks[0])) / (t - t0)
        self.announce_result(encryption_speed / 10**6, "MBps")

    def test_hash_small(self, hash_name, module):
        self.announce_start("%s (%d-byte inputs)" % (hash_name, module.digest_size))

        blocks = self.random_blocks(module.digest_size, 10000)

        # Initialize hashes
        t0 = time.time()
        for b in blocks:
            module.new(b).digest()
        t = time.time()

        hashes_per_second = len(blocks) / (t - t0)
        self.announce_result(hashes_per_second / 1000, "kHashes/sec")

    def test_hash_large(self, hash_name, module):
        self.announce_start("%s (single large input)" % (hash_name,))

        blocks = self.random_blocks(16384, 10000)

        # Perform hashing
        t0 = time.time()
        h = module.new()
        for b in blocks:
            h.update(b)
        h.digest()
        t = time.time()

        hash_speed = len(blocks) * len(blocks[0]) / (t - t0)
        self.announce_result(hash_speed / 10**6, "MBps")

    def run(self):
        pubkey_specs = [
            ("RSA(1024)", RSA, 1024/8),
            ("RSA(2048)", RSA, 2048/8),
            ("RSA(4096)", RSA, 4096/8),
            ]
        block_specs = [
            ("DES", DES, 8),
            ("DES3", DES3, 24),
            ("AES128", AES, 16),
            ("AES192", AES, 24),
            ("AES256", AES, 32),
            ("Blowfish(256)", Blowfish, 32),
            ("CAST(40)", CAST, 5),
            ("CAST(80)", CAST, 10),
            ("CAST(128)", CAST, 16),
        ]
        stream_specs = [
            ("ARC2(128)", ARC2, 16),
            ("ARC4(128)", ARC4, 16),
            ("XOR(24)", XOR, 3),
            ("XOR(256)", XOR, 32),
        ]
        hash_specs = [
            ("MD2", MD2),
            ("MD4", MD4),
            ("MD5", MD5),
            ("SHA", SHA),
            ("SHA256", SHA256),
        ]
        if RIPEMD is not None:
            hash_specs += [("RIPEMD", RIPEMD)]

        for pubkey_name, module, key_bytes in pubkey_specs:
            self.test_pubkey_setup(pubkey_name, module, key_bytes)

        for cipher_name, module, key_bytes in block_specs:
            self.test_key_setup(cipher_name, module, key_bytes, module.MODE_CBC)
            self.test_encryption("%s-CBC" % (cipher_name,), module, key_bytes, module.MODE_CBC)
            self.test_encryption("%s-CFB" % (cipher_name,), module, key_bytes, module.MODE_CFB)
            self.test_encryption("%s-PGP" % (cipher_name,), module, key_bytes, module.MODE_PGP)
            self.test_encryption("%s-OFB" % (cipher_name,), module, key_bytes, module.MODE_OFB)

        for cipher_name, module, key_bytes in stream_specs:
            self.test_key_setup(cipher_name, module, key_bytes, None)
            self.test_encryption(cipher_name, module, key_bytes, None)

        for hash_name, module in hash_specs:
            self.test_hash_small(hash_name, module)
            self.test_hash_large(hash_name, module)

if __name__ == '__main__':
    Benchmark().run()

# vim:set ts=4 sw=4 sts=4 expandtab:
