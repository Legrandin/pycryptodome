# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
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

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.py3compat import maxint

class Integer(object):
    """A class to model a natural integer (including zero)"""

    def __init__(self, value):
        if isinstance(value, float):
            raise ValueError("A floating point type is not a natural number")
        try:
            self._value = value._value
        except AttributeError:
            self._value = value

    # Conversions
    def __int__(self):
        return self._value

    def __str__(self):
        return str(int(self))

    def __repr__(self):
        return "Integer(%s)" % str(self)

    def to_bytes(self, block_size=0):
        if self._value < 0:
            raise ValueError("Conversion only valid for non-negative numbers")
        result = long_to_bytes(self._value, block_size)
        if len(result) > block_size > 0:
            raise ValueError("Value too large to encode")
        return result

    @staticmethod
    def from_bytes(byte_string):
        return Integer(bytes_to_long(byte_string))

    # Relations
    def __eq__(self, term):
        try:
            result = self._value == term._value
        except AttributeError:
            result = self._value == term
        return result

    def __ne__(self, term):
        return not self.__eq__(term)

    def __lt__(self, term):
        try:
            result = self._value < term._value
        except AttributeError:
            result = self._value < term
        return result

    def __le__(self, term):
        return self.__lt__(term) or self.__eq__(term)

    def __gt__(self, term):
        return not self.__le__(term)

    def __ge__(self, term):
        return not self.__lt__(term)

    def __nonzero__(self):
        return self._value != 0

    def is_negative(self):
        return self._value < 0

    # Arithmetic operations
    def __add__(self, term):
        try:
            return Integer(self._value + term._value)
        except AttributeError:
            return Integer(self._value + term)

    def __sub__(self, term):
        try:
            diff = self._value - term._value
        except AttributeError:
            diff = self._value - term
        return Integer(diff)

    def __mul__(self, factor):
        try:
            return Integer(self._value * factor._value)
        except AttributeError:
            return Integer(self._value * factor)

    def __floordiv__(self, divisor):
        try:
            divisor_value = divisor._value
        except AttributeError:
            divisor_value = divisor
        return Integer(self._value // divisor_value)

    def __mod__(self, divisor):
        try:
            divisor_value = divisor._value
        except AttributeError:
            divisor_value = divisor
        if divisor_value < 0:
            raise ValueError("Modulus must be positive")
        return Integer(self._value % divisor_value)

    def inplace_pow(self, exponent, modulus=None):
        try:
            exp_value = exponent._value
        except AttributeError:
            exp_value = exponent
        if exp_value < 0:
            raise ValueError("Exponent must not be negative")

        try:
            mod_value = modulus._value
        except AttributeError:
            mod_value = modulus
        if mod_value is not None:
            if mod_value < 0:
                raise ValueError("Modulus must be positive")
            if mod_value == 0:
                raise ZeroDivisionError("Modulus cannot be zero")
        self._value = pow(self._value, exp_value, mod_value)
        return self

    def __pow__(self, exponent, modulus=None):
        result = Integer(self)
        return result.inplace_pow(exponent, modulus)

    def __abs__(self):
        return abs(self._value)

    def sqrt(self):
        # http://stackoverflow.com/questions/15390807/integer-square-root-in-python
        if self._value < 0:
            raise ValueError("Square root of negative value")
        x = self._value
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + self._value // x) // 2
        return Integer(x)

    def __iadd__(self, term):
        try:
            self._value += term._value
        except AttributeError:
            self._value += term
        return self

    def __isub__(self, term):
        try:
            self._value -= term._value
        except AttributeError:
            self._value -= term
        return self

    def __imul__(self, term):
        try:
            self._value *= term._value
        except AttributeError:
            self._value *= term
        return self

    def __imod__(self, term):
        try:
            modulus = term._value
        except AttributeError:
            modulus = term
        if modulus == 0:
            raise ZeroDivisionError("Division by zero")
        if modulus < 0:
            raise ValueError("Modulus must be positive")
        self._value %= modulus
        return self

    # Boolean/bit operations
    def __and__(self, term):
        try:
            return Integer(self._value & term._value)
        except AttributeError:
            return Integer(self._value & term)

    def __or__(self, term):
        try:
            return Integer(self._value | term._value)
        except AttributeError:
            return Integer(self._value | term)

    def __rshift__(self, pos):
        try:
            try:
                return Integer(self._value >> pos._value)
            except AttributeError:
                return Integer(self._value >> pos)
        except OverflowError:
            raise ValueError("Incorrect shift count")

    def __irshift__(self, pos):
        try:
            try:
                self._value >>= pos._value
            except AttributeError:
                self._value >>= pos
        except OverflowError:
            raise ValueError("Incorrect shift count")
        return self

    def __lshift__(self, pos):
        try:
            try:
                return Integer(self._value << pos._value)
            except AttributeError:
                return Integer(self._value << pos)
        except OverflowError:
            raise ValueError("Incorrect shift count")

    def __ilshift__(self, pos):
        try:
            try:
                self._value <<= pos._value
            except AttributeError:
                self._value <<= pos
        except OverflowError:
            raise ValueError("Incorrect shift count")
        return self


    def get_bit(self, n):
        try:
            try:
                return (self._value >> n._value) & 1
            except AttributeError:
                return (self._value >> n) & 1
        except OverflowError:
            raise ValueError("Incorrect bit position")

    # Extra
    def is_odd(self):
        return (self._value & 1) == 1

    def is_even(self):
        return (self._value & 1) == 0

    def size_in_bits(self):

        if self._value < 0:
            raise ValueError("Conversion only valid for non-negative numbers")

        if self._value == 0:
            return 1

        bit_size = 0
        tmp = self._value
        while tmp:
            tmp >>= 1
            bit_size += 1

        return bit_size

    def size_in_bytes(self):
        return (self.size_in_bits() - 1) // 8 + 1

    def is_perfect_square(self):
        if self._value < 0:
            return False
        if self._value in (0, 1):
            return True

        x = self._value // 2
        square_x = x ** 2

        while square_x > self._value:
            x = (square_x + self._value) // (2 * x)
            square_x = x ** 2

        return self._value == x ** 2

    def fail_if_divisible_by(self, small_prime):
        try:
            if (self._value % small_prime._value) == 0:
                raise ValueError("Value is composite")
        except AttributeError:
            if (self._value % small_prime) == 0:
                raise ValueError("Value is composite")

    def multiply_accumulate(self, a, b):
        if type(a) == Integer:
            a = a._value
        if type(b) == Integer:
            b = b._value
        self._value += a * b
        return self

    def set(self, source):
        if type(source) == Integer:
            self._value = source._value
        else:
            self._value = source

    def inplace_inverse(self, modulus):
        try:
            modulus = modulus._value
        except AttributeError:
            pass
        if modulus == 0:
            raise ZeroDivisionError("Modulus cannot be zero")
        if modulus < 0:
            raise ValueError("Modulus cannot be negative")
        r_p, r_n = self._value, modulus
        s_p, s_n = 1, 0
        while r_n > 0:
            q = r_p // r_n
            r_p, r_n = r_n, r_p - q * r_n
            s_p, s_n = s_n, s_p - q * s_n
        if r_p != 1:
            raise ValueError("No inverse value can be computed" + str(r_p))
        while s_p < 0:
            s_p += modulus
        self._value = s_p
        return self

    def inverse(self, modulus):
        result = Integer(self)
        result.inplace_inverse(modulus)
        return result

    def gcd(self, term):
        try:
            term = term._value
        except AttributeError:
            pass
        r_p, r_n = abs(self._value), abs(term)
        while r_n > 0:
            q = r_p // r_n
            r_p, r_n = r_n, r_p - q * r_n
        return Integer(r_p)

    def lcm(self, term):
        try:
            term = term._value
        except AttributeError:
            pass
        if self._value == 0 or term == 0:
            return Integer(0)
        return Integer(abs((self._value * term) // self.gcd(term)._value))

    @staticmethod
    def jacobi_symbol(a, n):
        if isinstance(a, Integer):
            a = a._value
        if isinstance(n, Integer):
            n = n._value

        if (n & 1) == 0:
            raise ValueError("n must be even for the Jacobi symbol")

        # Step 1
        a = a % n
        # Step 2
        if a == 1 or n == 1:
            return 1
        # Step 3
        if a == 0:
            return 0
        # Step 4
        e = 0
        a1 = a
        while (a1 & 1) == 0:
            a1 >>= 1
            e += 1
        # Step 5
        if (e & 1) == 0:
            s = 1
        elif n % 8 in (1, 7):
            s = 1
        else:
            s = -1
        # Step 6
        if n % 4 == 3 and a1 % 4 == 3:
            s = -s
        # Step 7
        n1 = n % a1
        # Step 8
        return s * Integer.jacobi_symbol(n1, a1)
