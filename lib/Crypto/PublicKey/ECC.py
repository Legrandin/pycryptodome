# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
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


from Crypto.Math.Numbers import Integer

class _Curve(object):
    pass

_curve = _Curve()
_curve.p = Integer(115792089210356248762697446949407573530086143415290314195533631308867097853951)
_curve.n = Integer(115792089210356248762697446949407573529996955224135760342422259061068512044369)
_curve.Gx = Integer(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)
_curve.Gy = Integer(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


# https://www.nsa.gov/ia/_files/nist-routines.pdf
# http://point-at-infinity.org/ecc/nisttv
# http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
# https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
# https://eprint.iacr.org/2013/816.pdf

class ECPoint(object):

    def __init__(self, x, y):
        self._x = Integer(x)
        self._y = Integer(y)

    def __eq__(self, point):
        return self._x == point._x and self._y == point._y

    def __neg__(self):
        if self.is_point_at_infinity():
            return self.point_at_infinity()
        return ECPoint(self._x, _curve.p - self._y)

    def copy(self):
        return ECPoint(self._x, self._y)

    def is_point_at_infinity(self):
        return self._x == 0 and self._y == 0

    @staticmethod
    def point_at_infinity():
        return ECPoint(0, 0)

    @property
    def x(self):
        if self.is_point_at_infinity():
            raise ValueError("Point at infinity")
        return self._x

    @property
    def y(self):
        if self.is_point_at_infinity():
            raise ValueError("Point at infinity")
        return self._y

    def double(self):
        """Return a new point, doubling this one"""

        if self._y == 0:
            return self.point_at_infinity()

        common = (pow(self._x, 2, _curve.p) * 3 - 3) * (self._y << 1).inverse(_curve.p) % _curve.p
        x3 = pow(common, 2, _curve.p) - self._x - self._x
        while x3 < 0:
            x3 += _curve.p
        y3 = ((self._x - x3) * common - self._y) % _curve.p

        return ECPoint(x3, y3)

    def add(self, point):
        """Return a new point, the addition of this one and another"""

        if self.is_point_at_infinity():
            return point.copy()

        if point.is_point_at_infinity():
            return self.copy()

        if self == point:
            return self.double()

        if self._x == point._x:
            return self.point_at_infinity()

        common = (point._y - self._y) * (point._x - self._x).inverse(_curve.p) % _curve.p
        x3 = pow(common, 2, _curve.p) - self._x - point._x
        while x3 < 0:
            x3 += _curve.p
        y3 = ((self._x - x3) * common - self._y) % _curve.p

        return ECPoint(x3, y3)

    def multiply(self, scalar):
        """Return a new point, the scalar product of this one"""

        assert(scalar >= 0)

        # Trivial results
        if scalar == 0 or self.is_point_at_infinity():
            return self.point_at_infinity()
        elif scalar == 1:
            return self.copy()

        # Pre-compute the table (but only for entries as wide as the window)
        WINDOW_BITS = 3
        window_low = 1 << (WINDOW_BITS - 1)
        precomp = []
        for x in xrange(window_low, 1 << WINDOW_BITS):
            new_entry = self.point_at_infinity()
            bit_mask = window_low
            while bit_mask > 0:
                new_entry = new_entry.double()
                if (x & bit_mask):
                    new_entry = new_entry.add(self)
                bit_mask >>= 1
            precomp.append(new_entry)

        # Sliding-window multiplication
        digits = []     # pairs (size in bits, value)
        msb_pos = Integer(scalar).size_in_bits() - 1
        while msb_pos >= 0:
            if (1 << msb_pos) & scalar == 0:
                digit_size = 1
                digit_value = 0
            else:
                digit_size = min(msb_pos + 1, WINDOW_BITS)
                digit_value = (scalar >> (msb_pos + 1 - digit_size)) & ((1 << digit_size) - 1)
            digits.append((digit_size, digit_value))
            msb_pos -= digit_size

        result = self.point_at_infinity()
        for digit_size, digit_value in digits:

            if digit_size == WINDOW_BITS:
                assert(window_low <= digit_value << (1 << WINDOW_BITS))
                for _ in xrange(WINDOW_BITS):
                    result = result.double()
                result = result.add(precomp[digit_value - window_low])
            else:
                for _ in xrange(digit_size):
                    result = result.double()
                    if digit_value & 1:
                        result = self.add(result)
                    digit_value >>= 1

        return result
