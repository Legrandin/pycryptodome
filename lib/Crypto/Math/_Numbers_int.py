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
        return long_to_bytes(self._value, block_size)

    def __int__(self):
        return self._value

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
