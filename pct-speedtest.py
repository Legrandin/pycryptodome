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
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5 as RSAES_PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS, PKCS1_v1_5 as RSASSA_PKCS1_v1_5
from Crypto.Cipher import AES, ARC2, ARC4, Blowfish, CAST, DES3, DES, XOR
from Crypto.Hash import HMAC, MD2, MD4, MD5, SHA224, SHA256, SHA384, SHA512, CMAC
from Crypto.Random import get_random_bytes
import Crypto.Util.Counter
from Crypto.Util.number import bytes_to_long
try:
    from Crypto.Hash import SHA1
except ImportError:
    # Maybe it's called SHA
    from Crypto.Hash import SHA as SHA1
try:
    from Crypto.Hash import RIPEMD160
except ImportError:
    # Maybe it's called RIPEMD
    try:
        from Crypto.Hash import RIPEMD as RIPEMD160
    except ImportError:
        # Some builds of PyCrypto don't have the RIPEMD module
        RIPEMD160 = None

try:
    import hashlib
    import hmac
except ImportError: # Some builds/versions of Python don't have a hashlib module
    hashlib = hmac = None

# os.urandom() is less noisy when profiling, but it doesn't exist in Python < 2.4
try:
    urandom = os.urandom
except AttributeError:
    urandom = get_random_bytes

from Crypto.Random import random as pycrypto_random
import random as stdlib_random

class Benchmark:

    def __init__(self):
        self.__random_data = None

    def random_keys(self, bytes, n=10**5):
        """Return random keys of the specified number of bytes.

        If this function has been called before with the same number of bytes,
        cached keys are used instead of randomly generating new ones.
        """
        return self.random_blocks(bytes, n)

    def random_blocks(self, bytes_per_block, blocks):
        bytes = bytes_per_block * blocks
        data = self.random_data(bytes)
        retval = []
        for i in range(blocks):
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
        return urandom(b)

    def announce_start(self, test_name):
        sys.stdout.write("%s: " % (test_name,))
        sys.stdout.flush()

    def announce_result(self, value, units):
        sys.stdout.write("%.2f %s\n" % (value, units))
        sys.stdout.flush()

    def test_random_module(self, module_name, module):
        self.announce_start("%s.choice" % (module_name,))
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        t0 = time.time()
        for i in range(5000):
            module.choice(alphabet)
        t = time.time()
        invocations_per_second = 5000 / (t - t0)
        self.announce_result(invocations_per_second, "invocations/sec")

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
        keys = self.random_keys(key_bytes, n=5000)

        if hasattr(module, "MODE_CCM") and mode==module.MODE_CCM:
            iv = b"\xAA"*8
        else:
            iv = b"\xAA"*module.block_size

        # Perform key setups
        if mode is None:
            t0 = time.time()
            for k in keys:
                module.new(k)
            t = time.time()
        else:
            t0 = time.time()

            if mode==module.MODE_CTR:
                for k in keys:
                    ctr = Crypto.Util.Counter.new(module.block_size*8,
                        initial_value=bytes_to_long(iv))
                    module.new(k, module.MODE_CTR, counter=ctr)
            else:
                for k in keys:
                    module.new(k, mode, iv)
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
        elif mode == "CTR-BE":
            from Crypto.Util import Counter
            cipher = module.new(key, module.MODE_CTR, counter=Counter.new(module.block_size*8, little_endian=False))
        elif mode == "CTR-LE":
            from Crypto.Util import Counter
            cipher = module.new(key, module.MODE_CTR, counter=Counter.new(module.block_size*8, little_endian=True))
        elif hasattr(module, 'MODE_CCM') and mode==module.MODE_CCM:
            cipher = module.new(key, mode, iv[:8], msg_len=len(rand)*len(blocks))
        elif mode==module.MODE_CTR:
            ctr = Crypto.Util.Counter.new(module.block_size*8,
                    initial_value=bytes_to_long(iv),
                    allow_wraparound=True)
            cipher = module.new(key, module.MODE_CTR, counter=ctr)
        else:
            cipher = module.new(key, mode, iv)

        # Perform encryption
        t0 = time.time()
        for b in blocks:
            cipher.encrypt(b)
        t = time.time()

        encryption_speed = (len(blocks) * len(blocks[0])) / (t - t0)
        self.announce_result(encryption_speed / 10**6, "MBps")

    def test_hash_small(self, hash_name, hash_constructor, digest_size):
        self.announce_start("%s (%d-byte inputs)" % (hash_name, digest_size))

        blocks = self.random_blocks(digest_size, 10000)

        # Initialize hashes
        t0 = time.time()
        for b in blocks:
            hash_constructor(b).digest()
        t = time.time()

        hashes_per_second = len(blocks) / (t - t0)
        self.announce_result(hashes_per_second / 1000, "kHashes/sec")

    def test_hash_large(self, hash_name, hash_constructor, digest_size):
        self.announce_start("%s (single large input)" % (hash_name,))

        blocks = self.random_blocks(16384, 10000)

        # Perform hashing
        t0 = time.time()
        h = hash_constructor()
        for b in blocks:
            h.update(b)
        h.digest()
        t = time.time()

        hash_speed = len(blocks) * len(blocks[0]) / (t - t0)
        self.announce_result(hash_speed / 10**6, "MBps")

    def test_hmac_small(self, mac_name, hmac_constructor, digestmod, digest_size):
        keys = iter(self.random_keys(digest_size))
        if sys.version_info[0] == 2:
            mac_constructor = lambda data=None: hmac_constructor(keys.next(), data, digestmod)
        else:
            mac_constructor = lambda data=None: hmac_constructor(keys.__next__(), data, digestmod)
        self.test_hash_small(mac_name, mac_constructor, digest_size)

    def test_hmac_large(self, mac_name, hmac_constructor, digestmod, digest_size):
        key = self.random_keys(digest_size)[0]
        mac_constructor = lambda data=None: hmac_constructor(key, data, digestmod)
        self.test_hash_large(mac_name, mac_constructor, digest_size)

    def test_cmac_small(self, mac_name, cmac_constructor, ciphermod, key_size):
        keys = iter(self.random_keys(key_size))
        if sys.version_info[0] == 2:
            mac_constructor = lambda data=None: cmac_constructor(keys.next(), data, ciphermod)
        else:
            mac_constructor = lambda data=None: cmac_constructor(keys.__next__(), data, ciphermod)
        self.test_hash_small(mac_name, mac_constructor, ciphermod.block_size)

    def test_cmac_large(self, mac_name, cmac_constructor, ciphermod, key_size):
        key = self.random_keys(key_size)[0]
        mac_constructor = lambda data=None: cmac_constructor(key, data, ciphermod)
        self.test_hash_large(mac_name, mac_constructor, ciphermod.block_size)

    def test_pkcs1_sign(self, scheme_name, scheme_constructor, hash_name, hash_constructor, digest_size):
        self.announce_start("%s signing %s (%d-byte inputs)" % (scheme_name, hash_name, digest_size))

        # Make a key
        k = RSA.generate(2048)
        sigscheme = scheme_constructor(k)

        # Make some hashes
        blocks = self.random_blocks(digest_size, 50)
        hashes = []
        for b in blocks:
            hashes.append(hash_constructor(b))

        # Perform signing
        t0 = time.time()
        for h in hashes:
            sigscheme.sign(h)
        t = time.time()

        speed = len(hashes) / (t - t0)
        self.announce_result(speed, "sigs/sec")

    def test_pkcs1_verify(self, scheme_name, scheme_constructor, hash_name, hash_constructor, digest_size):
        self.announce_start("%s verification %s (%d-byte inputs)" % (scheme_name, hash_name, digest_size))

        # Make a key
        k = RSA.generate(2048)
        sigscheme = scheme_constructor(k)

        # Make some hashes
        blocks = self.random_blocks(digest_size, 50)
        hashes = []
        for b in blocks:
            hashes.append(hash_constructor(b))

        # Make some signatures
        signatures = []
        for h in hashes:
            signatures.append(sigscheme.sign(h))

        # Double the list, to make timing better
        hashes = hashes + hashes
        signatures = signatures + signatures

        # Perform verification
        t0 = time.time()
        for h, s in zip(hashes, signatures):
            sigscheme.verify(h, s)
        t = time.time()

        speed = len(hashes) / (t - t0)
        self.announce_result(speed, "sigs/sec")

    def run(self):
        pubkey_specs = [
            ("RSA(1024)", RSA, int(1024/8)),
            ("RSA(2048)", RSA, int(2048/8)),
            ("RSA(4096)", RSA, int(4096/8)),
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
            ("SHA1", SHA1),
            ("SHA224", SHA224),
            ("SHA256", SHA256),
            ("SHA384", SHA384),
            ("SHA512", SHA512),
        ]
        if RIPEMD160 is not None:
            hash_specs += [("RIPEMD160", RIPEMD160)]

        hashlib_specs = []
        if hashlib is not None:
            if hasattr(hashlib, 'md5'):    hashlib_specs.append(("hashlib.md5",    hashlib.md5))
            if hasattr(hashlib, 'sha1'):   hashlib_specs.append(("hashlib.sha1",   hashlib.sha1))
            if hasattr(hashlib, 'sha224'): hashlib_specs.append(("hashlib.sha224", hashlib.sha224))
            if hasattr(hashlib, 'sha256'): hashlib_specs.append(("hashlib.sha256", hashlib.sha256))
            if hasattr(hashlib, 'sha384'): hashlib_specs.append(("hashlib.sha384", hashlib.sha384))
            if hasattr(hashlib, 'sha512'): hashlib_specs.append(("hashlib.sha512", hashlib.sha512))

        # stdlib random
        self.test_random_module("stdlib random", stdlib_random)

        # Crypto.Random.random
        self.test_random_module("Crypto.Random.random", pycrypto_random)

        # Crypto.PublicKey
        for pubkey_name, module, key_bytes in pubkey_specs:
            self.test_pubkey_setup(pubkey_name, module, key_bytes)

        # Crypto.Cipher (block ciphers)
        for cipher_name, module, key_bytes in block_specs:
            self.test_key_setup("%s-CBC" % (cipher_name,), module, key_bytes, module.MODE_CBC)
            self.test_encryption("%s-CBC" % (cipher_name,), module, key_bytes, module.MODE_CBC)
            self.test_encryption("%s-CFB-8" % (cipher_name,), module, key_bytes, module.MODE_CFB)
            self.test_encryption("%s-OFB" % (cipher_name,), module, key_bytes, module.MODE_OFB)
            self.test_encryption("%s-ECB" % (cipher_name,), module, key_bytes, module.MODE_ECB)

            self.test_key_setup("%s-CTR" % (cipher_name,), module, key_bytes, module.MODE_CTR)
            self.test_encryption("%s-CTR" % (cipher_name,), module, key_bytes, module.MODE_CTR)

            self.test_encryption("%s-OPENPGP" % (cipher_name,), module, key_bytes, module.MODE_OPENPGP)
            self.test_encryption("%s-CTR-BE" % (cipher_name,), module, key_bytes, "CTR-BE")
            self.test_encryption("%s-CTR-LE" % (cipher_name,), module, key_bytes, "CTR-LE")

            if hasattr(module, "MODE_CCM"):
                self.test_key_setup("%s-CCM" % (cipher_name,), module, key_bytes, module.MODE_CCM)
                self.test_encryption("%s-CCM" % (cipher_name,), module, key_bytes, module.MODE_CCM)

            if hasattr(module, "MODE_EAX"):
                self.test_key_setup("%s-EAX" % (cipher_name,), module, key_bytes, module.MODE_EAX)
                self.test_encryption("%s-EAX" % (cipher_name,), module, key_bytes, module.MODE_EAX)

            if hasattr(module, "MODE_GCM"):
                self.test_key_setup("%s-GCM" % (cipher_name,), module, key_bytes, module.MODE_GCM)
                self.test_encryption("%s-GCM" % (cipher_name,), module, key_bytes, module.MODE_GCM)

        # Crypto.Cipher (stream ciphers)
        for cipher_name, module, key_bytes in stream_specs:
            self.test_key_setup(cipher_name, module, key_bytes, None)
            self.test_encryption(cipher_name, module, key_bytes, None)

        # Crypto.Hash
        for hash_name, module in hash_specs:
            self.test_hash_small(hash_name, module.new, module.digest_size)
            self.test_hash_large(hash_name, module.new, module.digest_size)

        # standard hashlib
        for hash_name, func in hashlib_specs:
            self.test_hash_small(hash_name, func, func().digest_size)
            self.test_hash_large(hash_name, func, func().digest_size)

        # PyCrypto HMAC
        for hash_name, module in hash_specs:
            self.test_hmac_small("HMAC-"+hash_name, HMAC.new, module, module.digest_size)
            self.test_hmac_large("HMAC-"+hash_name, HMAC.new, module, module.digest_size)

        # standard hmac + hashlib
        for hash_name, func in hashlib_specs:
            self.test_hmac_small("hmac+"+hash_name, hmac.HMAC, func, func().digest_size)
            self.test_hmac_large("hmac+"+hash_name, hmac.HMAC, func, func().digest_size)

        # CMAC
        for cipher_name, module, key_size in (("AES128", AES, 16),):
            self.test_cmac_small(cipher_name+"-CMAC", CMAC.new, module, key_size)
            self.test_cmac_large(cipher_name+"-CMAC", CMAC.new, module, key_size)

        # PKCS1_v1_5 (sign) + Crypto.Hash
        for hash_name, module in hash_specs:
            self.test_pkcs1_sign("PKCS#1-v1.5", RSASSA_PKCS1_v1_5.new, hash_name, module.new, module.digest_size)

        # PKCS1_PSS (sign) + Crypto.Hash
        for hash_name, module in hash_specs:
            self.test_pkcs1_sign("PKCS#1-PSS", PKCS1_PSS.new, hash_name, module.new, module.digest_size)

        # PKCS1_v1_5 (verify) + Crypto.Hash
        for hash_name, module in hash_specs:
            self.test_pkcs1_verify("PKCS#1-v1.5", RSASSA_PKCS1_v1_5.new, hash_name, module.new, module.digest_size)

        # PKCS1_PSS (verify) + Crypto.Hash
        for hash_name, module in hash_specs:
            self.test_pkcs1_verify("PKCS#1-PSS", PKCS1_PSS.new, hash_name, module.new, module.digest_size)

if __name__ == '__main__':
    Benchmark().run()

# vim:set ts=4 sw=4 sts=4 expandtab:
