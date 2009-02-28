# -*- coding: utf-8 -*-
#
#  RIPEMD160.py : RIPEMD-160 implementation
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

# This implementation was written with reference to the RIPEMD-160
# specification, which is available at:
# http://homes.esat.kuleuven.be/~cosicart/pdf/AB-9601/

# It is also documented in the _Handbook of Applied Cryptography_, as
# Algorithm 9.55.  It's on page 30 of the following PDF file:
# http://www.cacr.math.uwaterloo.ca/hac/about/chap9.pdf

# The RIPEMD-160 specification doesn't really tell us how to do padding, but
# since RIPEMD-160 is inspired by MD4, you can use the padding algorithm from
# RFC 1320.

# According to http://www.users.zetnet.co.uk/hopwood/crypto/scan/md.html:
#   RIPEMD-160 is big-bit-endian, little-byte-endian, and left-justified. (Note
#   the opposite bit and byte order.) SCAN 1.0.16 incorrectly stated
#   "little-bit-endian, little-byte-endian, and right-justified".

"""RIPEMD-160 hash module"""

__all__ = ['new', 'digest_size']

__revision__ = "$Id$"

import struct

# Rather than writing & 0xffffffffL every time (and risking typographical
# errors each time), we use this function.
# Thanks to Thomas Dixon for the idea.
def u32(n):
    return n & 0xFFFFffffL

#
# Ordering of the message words
#

# The permutation ρ
rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]

# The permutation π(i) = 9i + 5  (mod 16)
pi = [(9*i + 5) & 15 for i in range(16)]

# Round permutation r (left line)
rl = [range(16)]                    # id
rl += [[rho[j] for j in rl[-1]]]    # ρ
rl += [[rho[j] for j in rl[-1]]]    # ρ^2
rl += [[rho[j] for j in rl[-1]]]    # ρ^3
rl += [[rho[j] for j in rl[-1]]]    # ρ^4

# r' (right line)
rr = [list(pi)]                     # π
rr += [[rho[j] for j in rr[-1]]]    # ρπ
rr += [[rho[j] for j in rr[-1]]]    # ρ^2 π
rr += [[rho[j] for j in rr[-1]]]    # ρ^3 π
rr += [[rho[j] for j in rr[-1]]]    # ρ^4 π

#
# Boolean functions
#

# f₁ (x, y, z) = x ⊕ y ⊕ z
f1 = lambda x, y, z: x ^ y ^ z

# f₂ (x, y, z) = (x ∧ y) ∨ (¬x ∧ z)
f2 = lambda x, y, z: (x & y) | (~x & z)

# f₃ (x, y, z) = (x ∨ ¬y) ⊕ z
f3 = lambda x, y, z: (x | ~y) ^ z

# f₄ (x, y, z) = (x ∧ z) ∨ (y ∧ ¬z)
f4 = lambda x, y, z: (x & z) | (y & ~z)

# f₅ (x, y, z) = x ⊕ (y ∨ ¬z)
f5 = lambda x, y, z: x ^ (y | ~z)

# boolean functions (left line)
fl = [f1, f2, f3, f4, f5]

# boolean functions (right line)
fr = [f5, f4, f3, f2, f1]

#
# Shifts
#

# round   X0  X1  X2  X3 ...
_shift1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
_shift2 = [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7]
_shift3 = [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9]
_shift4 = [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6]
_shift5 = [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]

# shifts (left line)
sl = [[_shift1[rl[0][i]] for i in range(16)]]
sl.append([_shift2[rl[1][i]] for i in range(16)])
sl.append([_shift3[rl[2][i]] for i in range(16)])
sl.append([_shift4[rl[3][i]] for i in range(16)])
sl.append([_shift5[rl[4][i]] for i in range(16)])

# shifts (right line)
sr = [[_shift1[rr[0][i]] for i in range(16)]]
sr.append([_shift2[rr[1][i]] for i in range(16)])
sr.append([_shift3[rr[2][i]] for i in range(16)])
sr.append([_shift4[rr[3][i]] for i in range(16)])
sr.append([_shift5[rr[4][i]] for i in range(16)])

#
# Constants
#

_kg = lambda x, y: int(2**30 * (y ** (1.0 / x)))

# constants (left line)
KL = [
    0,          # Round 1: 0
    _kg(2, 2),  # Round 2: 2**30 * sqrt(2)
    _kg(2, 3),  # Round 3: 2**30 * sqrt(3)
    _kg(2, 5),  # Round 4: 2**30 * sqrt(5)
    _kg(2, 7),  # Round 5: 2**30 * sqrt(7)
]

# constants (right line)
KR = [
    _kg(3, 2),  # Round 1: 2**30 * cubert(2)
    _kg(3, 3),  # Round 2: 2**30 * cubert(3)
    _kg(3, 5),  # Round 3: 2**30 * cubert(5)
    _kg(3, 7),  # Round 4: 2**30 * cubert(7)
    0,          # Round 5: 0
]

# cyclic rotate
def rol(s, n):
    assert 0 <= s <= 31
    assert 0 <= n <= 0xFFFFffffL
    return u32((n << s) | (n >> (32-s)))

# Initial value
initial_h = tuple(struct.unpack("<5L", "0123456789ABCDEFFEDCBA9876543210F0E1D2C3".decode('hex')))

def box(h, f, k, x, r, s):
    assert len(s) == 16
    assert len(x) == 16
    assert len(r) == 16
    (a, b, c, d, e) = h
    for word in range(16):
        T = u32(a + f(b, c, d) + x[r[word]] + k)
        T = u32(rol(s[word], T) + e)
        (b, c, d, e, a) = (T, b, rol(10, c), d, e)
    return (a, b, c, d, e)

def _compress(h, x):    # x is a list of 16 x 32-bit words
    hl = hr = h

    # Iterate through all 5 rounds of the compression function for each parallel pipeline
    for round in range(5):
        # left line
        hl = box(hl, fl[round], KL[round], x, rl[round], sl[round])
        # right line
        hr = box(hr, fr[round], KR[round], x, rr[round], sr[round])

    # Mix the two pipelines together
    h = (u32(h[1] + hl[2] + hr[3]),
         u32(h[2] + hl[3] + hr[4]),
         u32(h[3] + hl[4] + hr[0]),
         u32(h[4] + hl[0] + hr[1]),
         u32(h[0] + hl[1] + hr[2]))

    return h

def compress(h, s):
    """The RIPEMD-160 compression function"""
    assert len(s) % 64 == 0
    p = 0
    while p < len(s):
        h = _compress(h, struct.unpack("<16L", s[p:p+64]))
        p += 64
    assert p == len(s)
    return h

class RIPEMD160(object):

    digest_size = 20

    def __init__(self, data=""):
        self.h = initial_h
        self.bytes = 0      # input size (in bytes)
        self.buf = ""
        self.update(data)

    def update(self, data):
        self.buf += data
        self.bytes += len(data)

        p = len(self.buf) & ~63     # p = floor(len(self.buf) / 64) * 64
        if p > 0:
            self.h = compress(self.h, self.buf[:p])
            self.buf = self.buf[p:]
        assert len(self.buf) < 64

    def digest(self):

        # Merkle-Damgård strengthening, per RFC 1320
        # We pad the input with a 1, followed by zeros, followed by the 64-bit
        # length of the message in bits, modulo 2**64.

        length = (self.bytes << 3) & (2**64-1) # The total length of the message in bits, modulo 2**64

        assert len(self.buf) < 64
        data = self.buf + "\x80"
        if len(data) <= 56:
            # one final block
            assert len(data) <= 56
            data = struct.pack("<56sQ", data, length)
        else:
            assert len(data) <= 120
            data = struct.pack("<120sQ", data, length)

        h = compress(self.h, data)
        return struct.pack("<5L", *h)

    def hexdigest(self):
        return self.digest().encode('hex')

    def copy(self):
        obj = self.__class__()
        obj.h = self.h
        obj.bytes = self.bytes
        obj.buf = self.buf
        return obj

def new(data=""):
    return RIPEMD160(data)

digest_size = 20

# vim:set ts=4 sw=4 sts=4 expandtab:
