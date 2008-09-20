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

# vim:set ts=4 sw=4 sts=4 expandtab:

