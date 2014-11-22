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
        self._value = value

    # Conversions
    def __int__(self):
        return self._value

    def __str__(self):
        return str(int(self))

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

    def __mod__(self, divisor):
        try:
            divisor_value = divisor._value
        except AttributeError:
            divisor_value = divisor
        if divisor_value < 0:
            raise ValueError("Modulus must be positive")
        return Integer(self._value % divisor_value)

    def __pow__(self, exponent, modulus=None):
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
        return pow(self._value, exp_value, mod_value)

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
            return Integer(self._value >> pos._value)
        except AttributeError:
            return Integer(self._value >> pos)

    def __irshift__(self, pos):
        try:
            self._value >>= pos._value
        except AttributeError:
            self._value >>= pos
        return self

    def get_bit(self, n):
        if type(n) == Integer:
            return (self._value >> n._value) & 1
        else:
            return (self._value >> n) & 1

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

    def is_divisible_by_ulong(self, divisor):
        if not (0 < divisor < maxint):
            raise ValueError("Divisor is not a C unsigned long")
        return (self._value % divisor) == 0

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
