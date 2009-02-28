# -*- coding: utf-8 -*-
#
#  PubKey/RSA/_slowmath.py : Pure Python implementation of the RSA portions of _fastmath
#
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# =======================================================================
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

"""Pure Python implementation of the RSA-related portions of Crypto.PublicKey._fastmath."""

__revision__ = "$Id$"

__all__ = ['rsa_construct']

from Crypto.Util.python_compat import *

from Crypto.Util.number import size, inverse

class error(Exception):
    pass

class _RSAKey(object):
    def _blind(self, m, r):
        # compute r**e * m (mod n)
        return m * pow(r, self.e, self.n)

    def _unblind(self, m, r):
        # compute m / r (mod n)
        return inverse(r, self.n) * m % self.n

    def _decrypt(self, c):
        # compute c**d (mod n)
        if not self.has_private():
            raise error("No private key")
        return pow(c, self.d, self.n) # TODO: CRT exponentiation

    def _encrypt(self, m):
        # compute m**d (mod n)
        return pow(m, self.e, self.n)

    def _sign(self, m):   # alias for _decrypt
        if not self.has_private():
            raise error("No private key")
        return self._decrypt(m)

    def _verify(self, m, sig):
        return self._encrypt(sig) == m

    def has_private(self):
        return hasattr(self, 'd')

    def size(self):
        """Return the maximum number of bits that can be encrypted"""
        return size(self.n) - 1

def rsa_construct(n, e, d=None, p=None, q=None, u=None):
    """Construct an RSAKey object"""
    assert isinstance(n, long)
    assert isinstance(e, long)
    assert isinstance(d, (long, type(None)))
    assert isinstance(p, (long, type(None)))
    assert isinstance(q, (long, type(None)))
    assert isinstance(u, (long, type(None)))
    obj = _RSAKey()
    obj.n = n
    obj.e = e
    if d is not None: obj.d = d
    if p is not None: obj.p = p
    if q is not None: obj.q = q
    if u is not None: obj.u = u
    return obj

class _DSAKey(object):
    def size(self):
        """Return the maximum number of bits that can be encrypted"""
        return size(self.p) - 1

    def has_private(self):
        return hasattr(self, 'x')

    def _sign(self, m, k):   # alias for _decrypt
        # SECURITY TODO - We _should_ be computing SHA1(m), but we don't because that's the API.
        if not self.has_private():
            raise error("No private key")
        if not (1L < k < self.q):
            raise error("k is not between 2 and q-1")
        inv_k = inverse(k, self.q)   # Compute k**-1 mod q
        r = pow(self.g, k, self.p) % self.q  # r = (g**k mod p) mod q
        s = (inv_k * (m + self.x * r)) % self.q
        return (r, s)

    def _verify(self, m, r, s):
        # SECURITY TODO - We _should_ be computing SHA1(m), but we don't because that's the API.
        if not (0 < r < self.q) or not (0 < s < self.q):
            return False
        w = inverse(s, self.q)
        u1 = (m*w) % self.q
        u2 = (r*w) % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p) % self.q
        return v == r

def dsa_construct(y, g, p, q, x=None):
    assert isinstance(y, long)
    assert isinstance(g, long)
    assert isinstance(p, long)
    assert isinstance(q, long)
    assert isinstance(x, (long, type(None)))
    obj = _DSAKey()
    obj.y = y
    obj.g = g
    obj.p = p
    obj.q = q
    if x is not None: obj.x = x
    return obj


# vim:set ts=4 sw=4 sts=4 expandtab:

