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
from Crypto.Cipher import (AES, ARC2, ARC4, Blowfish, CAST, DES3, DES,
                           Salsa20, ChaCha20)
from Crypto.Hash import (HMAC, MD2, MD4, MD5, SHA224, SHA256, SHA384, SHA512,
                         CMAC, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
                         BLAKE2b, BLAKE2s)
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

class BLAKE2b_512(object):
    digest_size = 512
    @staticmethod
    def new(data=None):
        return BLAKE2b.new(digest_bits=512, data=data)

class BLAKE2s_256(object):
    digest_size = 256
    @staticmethod
    def new(data=None):
        return BLAKE2s.new(digest_bits=256, data=data)

class ChaCha20_old_style(object):
    @staticmethod
    def new(key, nonce):
        return ChaCha20.new(key=key, nonce=nonce)

class ModeNotAvailable(ValueError):
    pass

rng = get_random_bytes

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

    def test_key_setup(self, cipher_name, module, key_bytes, params):
        self.generate_cipher(module, key_bytes, params)
        self.announce_start("%s key setup" % (cipher_name,))

        for x in xrange(5000):
            t0 = time.time()
            self.generate_cipher(module, key_bytes, params)
            t = time.time()

        key_setups_per_second = 5000 / (t - t0)
        self.announce_result(key_setups_per_second/1000, "kKeys/sec")

    def test_encryption(self, cipher_name, module, key_bytes, params):
        self.announce_start("%s encryption" % (cipher_name,))

        pt_size = 16384000L
        pt = rng(pt_size)
        cipher = self.generate_cipher(module, key_bytes, params)

        # Perform encryption
        t0 = time.time()
        cipher.encrypt(pt)
        t = time.time()

        encryption_speed = pt_size / (t - t0)
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


    def generate_cipher(self, module, key_size, params):
        params_dict = {}
        if params:
            params_dict = dict([x.split("=") for x in params.split(" ")])

        gen_tuple = []
        gen_dict = {}

        # 1st parameter (mandatory): key
        if params_dict.get('ks') == "x2":
            key = rng(2 * key_size)
        else:
            key = rng(key_size)
        gen_tuple.append(key)

        # 2nd parameter: mode
        mode = params_dict.get("mode")
        if mode:
            mode_value = getattr(module, mode, None)
            if mode_value is None:
                # Mode not available for this cipher
                raise ModeNotAvailable()
            gen_tuple.append(getattr(module, mode))

        # 3rd parameter: IV/nonce
        iv_length = params_dict.get("iv")
        if iv_length is None:
            iv_length = params_dict.get("nonce")
        if iv_length:
            if iv_length == "bs":
                iv_length = module.block_size
            iv = rng(int(iv_length))
            gen_tuple.append(iv)

        # Specific to CTR mode
        le = params_dict.get("little_endian")
        if le:
            if le == "True":
                le = True
            else:
                le = False

            # Remove iv from parameters
            gen_tuple = gen_tuple[:-1]
            ctr = Crypto.Util.Counter.new(module.block_size*8,
                                          initial_value=bytes_to_long(iv),
                                          little_endian=le,
                                          allow_wraparound=True)
            gen_dict['counter'] = ctr

        # Generate cipher
        return module.new(*gen_tuple, **gen_dict)

    def run(self):
        pubkey_specs = [
            ("RSA(1024)", RSA, int(1024/8)),
            ("RSA(2048)", RSA, int(2048/8)),
            ("RSA(4096)", RSA, int(4096/8)),
            ]
        block_cipher_modes = [
            # Mode name, key setup, parameters
            ("CBC",     True,   "mode=MODE_CBC iv=bs"),
            ("CFB-8",   False,  "mode=MODE_CFB iv=bs"),
            ("OFB",     False,  "mode=MODE_OFB iv=bs"),
            ("ECB",     False,  "mode=MODE_ECB"),
            ("CTR-LE",  True,   "mode=MODE_CTR iv=bs little_endian=True"),
            ("CTR-BE",  False,  "mode=MODE_CTR iv=bs little_endian=False"),
            ("OPENPGP", False,  "mode=MODE_OPENPGP iv=bs"),
            ("CCM",     True,   "mode=MODE_CCM nonce=12"),
            ("GCM",     True,   "mode=MODE_GCM nonce=16"),
            ("EAX",     True,   "mode=MODE_EAX nonce=16"),
            ("SIV",     True,   "mode=MODE_SIV ks=x2 nonce=16"),
            ("OCB",     True,   "mode=MODE_OCB nonce=15"),
            ]
        block_specs = [
            # Cipher name, module, key size
            ("DES", DES, 8),
            ("DES3", DES3, 24),
            ("AES128", AES, 16),
            ("AES192", AES, 24),
            ("AES256", AES, 32),
            ("Blowfish(256)", Blowfish, 32),
            ("CAST(128)", CAST, 16),
            ("ARC2(128)", ARC2, 16),
        ]
        stream_specs = [
            # Cipher name, module, key size, nonce size
            ("ARC4(128)", ARC4, 16, 0),
            ("Salsa20(16)", Salsa20, 16, 8),
            ("Salsa20(32)", Salsa20, 32, 8),
            ("ChaCha20", ChaCha20_old_style, 32, 8),
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
            ("SHA3_224", SHA3_224),
            ("SHA3_256", SHA3_256),
            ("SHA3_384", SHA3_384),
            ("SHA3_512", SHA3_512),
            ("BLAKE2b", BLAKE2b_512),
            ("BLAKE2s", BLAKE2s_256),
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

            # Benchmark each cipher in each of the various modes (CBC, etc)
            for mode_name, test_ks, params in block_cipher_modes:

                mode_text = "%s-%s" % (cipher_name, mode_name)
                try:
                    if test_ks:
                        self.test_key_setup(mode_text, module, key_bytes, params)
                    self.test_encryption(mode_text, module, key_bytes, params)
                except ModeNotAvailable as e:
                    pass

        # Crypto.Cipher (stream ciphers)
        for cipher_name, module, key_bytes, nonce_bytes in stream_specs:
            params = ""
            if nonce_bytes:
                params = "nonce=" + str(nonce_bytes)
            self.test_key_setup(cipher_name, module, key_bytes, params)
            self.test_encryption(cipher_name, module, key_bytes, params)

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
            if not hasattr(module, "block_size"):
                continue
            self.test_hmac_small("HMAC-"+hash_name, HMAC.new, module, module.digest_size)
            self.test_hmac_large("HMAC-"+hash_name, HMAC.new, module, module.digest_size)

        # standard hmac + hashlib
        for hash_name, func in hashlib_specs:
            if not hasattr(module, "block_size"):
                continue
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
