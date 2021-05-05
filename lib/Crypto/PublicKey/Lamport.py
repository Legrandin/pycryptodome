# -*- coding: utf-8 -*-
# ===================================================================
#
# Copyright (c) 2020, James Edington <james@ishygddt.xyz>
# No rights reserved.
#
# To the extent possible under law, the author has waived all
# copyright and related or neighboring rights to this work.
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

from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from Crypto.Hash import SHA1, SHA224, SHA256, SHA3_224, SHA3_256, SHA3_384, SHA3_512
from itertools import repeat


class LamportKey(object):
    r"""Class defining a Lamport key.
    Do not instantiate directly.
    Use :func:`generate`, :func:`construct` or :func:`import_key` instead.
    """

    def __init__(self, key, is_private, onewayfunc="2.16.840.1.101.3.4.2.8", used=False):
        """Build a Lamport key.
        """
        h = onewayfuncs[onewayfunc] if not callable(onewayfunc) else onewayfunc
        size = len(h(b'')) * 8
        if size != len(key) or not all(len(pair) == 2 for pair in key):
            raise ValueError("Malformed Lamport key.")
        self._key = key
        self._is_private = is_private
        self._used = used
        self._h = h
        self._size = size
        self._onewayfunc = onewayfunc


    def __repr__(self):
        return "LamportKey(key=%s, is_private=%s, onewayfunc=%s, used=%s)" % (
            repr(self._key),
            repr(self._is_private),
            repr(self._onewayfunc if self._onewayfunc not in onewayfuncs.values() else onewayfuncs[next(oid for oid, f in onewayfuncs.items() if f == self._onewayfunc)]),
            repr(self._used),
        )


    def _sign(self, message):
        if len(message) * 8 != self._size:
            raise ValueError("Message to be signed must be %i bits long." % self._size)
        if not self._is_private:
            raise ValueError("This is not a private key")
        if self._used:
            raise RuntimeError("This key has already been used!")
        signature = tuple(privpair[bit] for bit, privpair in zip(_iterbits(message), self._key))
        self._used = True
        return signature


    def sign(self, message):
        return self._sign(self._h(message))


    def _verify(self, message, signature):
        expected = tuple(pubpair[bit] for bit, pubpair in zip(_iterbits(message), self.publickey()._key))
        actual = tuple(map(self._h, signature))
        return expected == actual


    def verify(self, message, signature):
        return self._verify(self._h(message), signature)


    def has_private(self):
        return self._is_private


    def publickey(self):
        return LamportKey(key=_s2p(self._h, self._key) if self._is_private else self._key, is_private=False, onewayfunc=self._onewayfunc)


def generate(size):
    """Create a new Lamport key.

    The algorithm closely follows the `Wikipedia page`_.

    .. _The wikipedia page: https://en.wikipedia.org/wiki/Lamport_signature
    """

    try:
        onewayfunc = onewayfunc_bits[size]
    except (KeyError, ValueError) as e:
        raise ValueError("Unsupported signature size for generation. Supported sizes are %s" % repr(onewayfunc_bits.keys())) from e
    if not size % 8 == 0:
        raise ValueError("Signature size must be a multiple of 8.")
    sk = tuple(tuple(get_random_bytes(size // 8) for size in repeat(size, 2)) for size in repeat(size, size))
    return LamportKey(sk, is_private=True, onewayfunc=onewayfunc)


def _s2p(h, key):
    return tuple(map(lambda pair: tuple(map(h, pair)), key))


def _iterbits(data):
    yield from (((byte & (0b1 << k)) >> k) for k in range(8 - 1, -1, -1) for byte in data)


onewayfunc_bits = {
    224: "2.16.840.1.101.3.4.2.7",
    256: "2.16.840.1.101.3.4.2.8",
    384: "2.16.840.1.101.3.4.2.9",
    512: "2.16.840.1.101.3.4.2.10",
}


onewayfuncs = {
    "1.3.14.3.2.26": lambda m: SHA1.new(m).digest(),
    "2.16.840.1.101.3.4.2.4": lambda m: SHA224.new(m).digest(),
    "2.16.840.1.101.3.4.2.3": lambda m: SHA256.new(m).digest(),
    "2.16.840.1.101.3.4.2.2": lambda m: SHA384.new(m).digest(),
    "2.16.840.1.101.3.4.2.7": lambda m: SHA3_224.new(m).digest(),
    "2.16.840.1.101.3.4.2.8": lambda m: SHA3_256.new(m).digest(),
    "2.16.840.1.101.3.4.2.9": lambda m: SHA3_384.new(m).digest(),
    "2.16.840.1.101.3.4.2.10": lambda m: SHA3_512.new(m).digest(),
}

