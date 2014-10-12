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


class Natural(object):
    """A class to model a natural integer (including zero)"""

    def __init__(self, value):
        if isinstance(value, float):
            raise ValueError("A floating point type is not a natural number")
        if value < 0:
            raise ValueError("A natural number is not negative")
        self._value = value

    def to_bytes(self, block_size=0):
        result = long_to_bytes(self._value, block_size)
        if len(result) > block_size > 0:
            raise ValueError("Value too large to encode")
        return result

    def __int__(self):
        return self._value

    def __str__(self):
        return str(int(self))

    @staticmethod
    def from_bytes(byte_string):
        return Natural(bytes_to_long(byte_string))

    # Arithmetic operations
    def __add__(self, term):
        try:
            return Natural(self._value + term._value)
        except AttributeError:
            return Natural(self._value + term)

    def __sub__(self, term):
        try:
            diff = self._value - term._value
        except AttributeError:
            diff = self._value - term
        if diff < 0:
            raise ValueError("Result of subtraction is not a natural value")
        return Natural(diff)

    def __mod__(self, divisor):
        try:
            return Natural(self._value % divisor._value)
        except AttributeError:
            return Natural(self._value % divisor)

    def __pow__(self, exponent, modulus):
        try:
            exp_value = exponent._value
        except AttributeError:
            exp_value = exponent
        try:
            mod_value = modulus._value
        except AttributeError:
            mod_value = modulus
        if exp_value < 0:
            raise ValueError("Exponent must not be negative")
        if mod_value < 0:
            raise ValueError("Modulus must be positive")
        return pow(self._value, exp_value, mod_value)

    # Boolean
    def __and__(self, term):
        try:
            return Natural(self._value & term._value)
        except AttributeError:
            return Natural(self._value % term)

    def __irshift__(self, pos):
        try:
            self._value >>= pos._value
        except AttributeError:
            self._value >>= pos
        return self

    def size_in_bits(self):

        if self._value == 0:
            return 1

        bit_size = 0
        tmp = self._value
        while tmp:
            tmp >>= 1
            bit_size += 1

        return bit_size

    def is_odd(self):
        return (self._value & 1) == 1

    def is_even(self):
        return (self._value & 1) == 0

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

    # Extra
    def is_perfect_square(self):
        if self._value in (0, 1):
            return True

        x = self._value // 2
        square_x = x**2

        while square_x > self._value:
            x = (square_x + self._value) // (2 * x)
            square_x = x**2

        return self._value == x**2
