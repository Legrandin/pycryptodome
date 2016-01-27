#
#  KDF.py : a collection of Key Derivation Functions
#
# Part of the Python Cryptography Toolkit
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

"""This file contains a collection of standard key derivation functions.

A key derivation function derives one or more secondary secret keys from
one primary secret (a master key or a pass phrase).

This is typically done to insulate the secondary keys from each other,
to avoid that leakage of a secondary key compromises the security of the
master key, or to thwart attacks on pass phrases (e.g. via rainbow tables).
"""

import struct
from struct import unpack

from Crypto.Util.py3compat import *

from Crypto.Hash import SHA1, SHA256, HMAC, CMAC
from Crypto.Util.strxor import strxor
from Crypto.Util.number import size as bit_size, long_to_bytes, bytes_to_long

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  create_string_buffer,
                                  get_raw_buffer)

_raw_salsa20_lib = load_pycryptodome_raw_lib("Crypto.Cipher._Salsa20",
                    """
                    int Salsa20_8_core(const uint8_t *x, const uint8_t *y,
                                       uint8_t *out);
                    uint32_t load_le_uint32(const uint8_t *in);
                    """)

def PBKDF1(password, salt, dkLen, count=1000, hashAlgo=None):
    """Derive one key from a password (or passphrase).

    This function performs key derivation according an old version of
    the PKCS#5 standard (v1.5).

    This algorithm is called ``PBKDF1``. Even though it is still described
    in the latest version of the PKCS#5 standard (version 2, or RFC2898),
    newer applications should use the more secure and versatile `PBKDF2` instead.

    :Parameters:
     password : string
        The secret password or pass phrase to generate the key from.
     salt : byte string
        An 8 byte string to use for better protection from dictionary attacks.
        This value does not need to be kept secret, but it should be randomly
        chosen for each derivation.
     dkLen : integer
        The length of the desired key. Default is 16 bytes, suitable for instance for `Crypto.Cipher.AES`.
     count : integer
        The number of iterations to carry out. It's recommended to use at least 1000.
     hashAlgo : module
        The hash algorithm to use, as a module or an object from the `Crypto.Hash` package.
        The digest length must be no shorter than ``dkLen``.
        The default algorithm is `SHA1`.

    :Return: A byte string of length `dkLen` that can be used as key.
    """
    if not hashAlgo:
        hashAlgo = SHA1
    password = tobytes(password)
    pHash = hashAlgo.new(password+salt)
    digest = pHash.digest_size
    if dkLen>digest:
        raise TypeError("Selected hash algorithm has a too short digest (%d bytes)." % digest)
    if len(salt) != 8:
        raise ValueError("Salt is not 8 bytes long (%d bytes instead)." % len(salt))
    for i in xrange(count-1):
        pHash = pHash.new(pHash.digest())
    return pHash.digest()[:dkLen]

def PBKDF2(password, salt, dkLen=16, count=1000, prf=None):
    """Derive one or more keys from a password (or passphrase).

    This function performs key derivation according to
    the PKCS#5 standard (v2.0), by means of the ``PBKDF2`` algorithm.

    :Parameters:
     password : string
        The secret password or pass phrase to generate the key from.
     salt : string
        A string to use for better protection from dictionary attacks.
        This value does not need to be kept secret, but it should be randomly
        chosen for each derivation. It is recommended to be at least 8 bytes long.
     dkLen : integer
        The cumulative length of the desired keys. Default is 16 bytes, suitable for instance for `Crypto.Cipher.AES`.
     count : integer
        The number of iterations to carry out. It's recommended to use at least 1000.
     prf : callable
        A pseudorandom function. It must be a function that returns a pseudorandom string
        from two parameters: a secret and a salt. If not specified, HMAC-SHA1 is used.

    :Return: A byte string of length `dkLen` that can be used as key material.
        If you wanted multiple keys, just break up this string into segments of the desired length.
"""
    password = tobytes(password)
    if prf is None:
        prf = lambda p,s: HMAC.new(p,s,SHA1).digest()

    def link(s):
        s[0], s[1] = s[1], prf(password, s[1])
        return s[0]

    key = b('')
    i = 1
    while len(key)<dkLen:
        s = [ prf(password, salt + struct.pack(">I", i)) ] * 2
        key += reduce(strxor, (link(s) for j in range(count)) )
        i += 1
    return key[:dkLen]


class _S2V(object):
    """String-to-vector PRF as defined in `RFC5297`_.

    This class implements a pseudorandom function family
    based on CMAC that takes as input a vector of strings.

    .. _RFC5297: http://tools.ietf.org/html/rfc5297
    """

    def __init__(self, key, ciphermod, cipher_params=None):
        """Initialize the S2V PRF.

        :Parameters:
          key : byte string
            A secret that can be used as key for CMACs
            based on ciphers from ``ciphermod``.
          ciphermod : module
            A block cipher module from `Crypto.Cipher`.
          cipher_params : dictionary
            A set of extra parameters to use to create a cipher instance.
        """

        self._key = key
        self._ciphermod = ciphermod
        self._last_string = self._cache = bchr(0)*ciphermod.block_size
        self._n_updates = ciphermod.block_size*8-1
        if cipher_params is None:
            self._cipher_params = {}
        else:
            self._cipher_params = dict(cipher_params)

    @staticmethod
    def new(key, ciphermod):
        """Create a new S2V PRF.

        :Parameters:
          key : byte string
            A secret that can be used as key for CMACs
            based on ciphers from ``ciphermod``.
          ciphermod : module
            A block cipher module from `Crypto.Cipher`.
        """
        return _S2V(key, ciphermod)

    def _double(self, bs):
        doubled = bytes_to_long(bs)<<1
        if bord(bs[0]) & 0x80:
            doubled ^= 0x87
        return long_to_bytes(doubled, len(bs))[-len(bs):]

    def update(self, item):
        """Pass the next component of the vector.

        The maximum number of components you can pass is equal to the block
        length of the cipher (in bits) minus 1.

        :Parameters:
          item : byte string
            The next component of the vector.
        :Raise TypeError: when the limit on the number of components has been reached.
        :Raise ValueError: when the component is empty
        """

        if not item:
            raise ValueError("A component cannot be empty")

        if self._n_updates==0:
            raise TypeError("Too many components passed to S2V")
        self._n_updates -= 1

        mac = CMAC.new(self._key,
                       msg=self._last_string,
                       ciphermod=self._ciphermod,
                       cipher_params=self._cipher_params)
        self._cache = strxor(self._double(self._cache), mac.digest())
        self._last_string = item

    def derive(self):
        """"Derive a secret from the vector of components.

        :Return: a byte string, as long as the block length of the cipher.
        """

        if len(self._last_string)>=16:
            final = self._last_string[:-16] + strxor(self._last_string[-16:], self._cache)
        else:
            padded = (self._last_string + bchr(0x80)+ bchr(0)*15)[:16]
            final = strxor(padded, self._double(self._cache))
        mac = CMAC.new(self._key,
                       msg=final,
                       ciphermod=self._ciphermod,
                       cipher_params=self._cipher_params)
        return mac.digest()


def HKDF(master, key_len, salt, hashmod, num_keys=1, context=None):
    """Derive one or more keys from a master secret using
    the HMAC-based KDF defined in RFC5869_.

    This KDF is not suitable for deriving keys from a password or for key
    stretching. Use `PBKDF2` instead.

    HKDF is a key derivation method approved by NIST in `SP 800 56C`__.

    :Parameters:
     master : byte string
        The unguessable value used by the KDF to generate the other keys.
        It must be a high-entropy secret, though not necessarily uniform.
        It must not be a password.
     salt : byte string
        A non-secret, reusable value that strengthens the randomness
        extraction step.
        Ideally, it is as long as the digest size of the chosen hash.
        If empty, a string of zeroes in used.
     key_len : integer
        The length in bytes of every derived key.
     hashmod : module
        A cryptographic hash algorithm from `Crypto.Hash`.
        `Crypto.Hash.SHA512` is a good choice.
     num_keys : integer
        The number of keys to derive. Every key is ``key_len`` bytes long.
        The maximum cumulative length of all keys is
        255 times the digest size.
     context : byte string
        Optional identifier describing what the keys are used for.

    :Return: A byte string or a tuple of byte strings.

    .. _RFC5869: http://tools.ietf.org/html/rfc5869
    .. __: http://csrc.nist.gov/publications/nistpubs/800-56C/SP-800-56C.pdf
    """

    output_len = key_len * num_keys
    if output_len > (255 * hashmod.digest_size):
        raise ValueError("Too much secret data to derive")
    if not salt:
        salt = bchr(0) * hashmod.digest_size
    if context is None:
        context = b("")

    # Step 1: extract
    hmac = HMAC.new(salt, master, digestmod=hashmod)
    prk = hmac.digest()

    # Step 2: expand
    t = [b("")]
    n = 1
    tlen = 0
    while tlen < output_len:
        hmac = HMAC.new(prk, t[-1] + context + bchr(n), digestmod=hashmod)
        t.append(hmac.digest())
        tlen += hashmod.digest_size
        n += 1
    derived_output = b("").join(t)
    if num_keys == 1:
        return derived_output[:key_len]
    kol = [derived_output[idx:idx + key_len]
           for idx in xrange(0, output_len, key_len)]
    return list(kol[:num_keys])


def _scryptBlockMix(blocks, len_blocks):
    """Hash function for ROMix."""

    x = blocks[-1]
    core = _raw_salsa20_lib.Salsa20_8_core
    result = [ create_string_buffer(64) for _ in range(len(blocks)) ]
    for i in xrange(len(blocks)):
        core(x, blocks[i], result[i])
        x = result[i]
    return [result[i + j] for j in xrange(2)
            for i in xrange(0, len_blocks, 2)]


def _scryptROMix(blocks, n):
    """Sequential memory-hard function for scrypt."""

    x = [blocks[i:i + 64] for i in xrange(0, len(blocks), 64)]
    len_x = len(x)
    v = [None]*n
    load_le_uint32 = _raw_salsa20_lib.load_le_uint32
    for i in xrange(n):
        v[i] = x
        x = _scryptBlockMix(x, len_x)
    for i in xrange(n):
        j = load_le_uint32(x[-1]) & (n - 1)
        t = [strxor(x[idx], v[j][idx]) for idx in xrange(len_x)]
        x = _scryptBlockMix(t, len_x)
    return b("").join([get_raw_buffer(y) for y in x])


def scrypt(password, salt, key_len, N, r, p, num_keys=1):
    """Derive one or more keys from a passphrase.

    This function performs key derivation according to
    the `scrypt`_ algorithm, introduced in Percival's paper
    `"Stronger key derivation via sequential memory-hard functions"`__.

    This implementation is based on the `RFC draft`__.

    :Parameters:
     password : string
        The secret pass phrase to generate the keys from.
     salt : string
        A string to use for better protection from dictionary attacks.
        This value does not need to be kept secret,
        but it should be randomly chosen for each derivation.
        It is recommended to be at least 8 bytes long.
     key_len : integer
        The length in bytes of every derived key.
     N : integer
        CPU/Memory cost parameter. It must be a power of 2 and less
        than ``2**32``.
     r : integer
        Block size parameter.
     p : integer
        Parallelization parameter.
        It must be no greater than ``(2**32-1)/(4r)``.
     num_keys : integer
        The number of keys to derive. Every key is ``key_len`` bytes long.
        By default, only 1 key is generated.
        The maximum cumulative length of all keys is ``(2**32-1)*32``
        (that is, 128TB).

    A good choice of parameters *(N, r , p)* was suggested
    by Colin Percival in his `presentation in 2009`__:

    - *(16384, 8, 1)* for interactive logins (<=100ms)
    - *(1048576, 8, 1)* for file encryption (<=5s)

    :Return: A byte string or a tuple of byte strings.

    .. _scrypt: http://www.tarsnap.com/scrypt.html
    .. __: http://www.tarsnap.com/scrypt/scrypt.pdf
    .. __: http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03
    .. __: http://www.tarsnap.com/scrypt/scrypt-slides.pdf
    """

    if 2 ** (bit_size(N) - 1) != N:
        raise ValueError("N must be a power of 2")
    if N >= 2 ** 32:
        raise ValueError("N is too big")
    if p > ((2 ** 32 - 1) * 32)  // (128 * r):
        raise ValueError("p or r are too big")

    prf_hmac_sha256 = lambda p, s: HMAC.new(p, s, SHA256).digest()

    blocks = PBKDF2(password, salt, p * 128 * r, 1, prf=prf_hmac_sha256)

    blocks = b("").join([_scryptROMix(blocks[x:x + 128 * r], N)
                         for x in xrange(0, len(blocks), 128 * r)])

    dk = PBKDF2(password, blocks, key_len * num_keys, 1,
                prf=prf_hmac_sha256)

    if num_keys == 1:
        return dk

    kol = [dk[idx:idx + key_len]
           for idx in xrange(0, key_len * num_keys, key_len)]
    return kol
