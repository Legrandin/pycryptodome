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

from ctypes import (CDLL, Structure, c_int, c_void_p, c_long, byref,
                    c_size_t, create_string_buffer)
from ctypes.util import find_library

from Crypto.Util.py3compat import *


class _GMP(object):

    gmp_lib_path = find_library("gmp")
    if gmp_lib_path is None:
        raise ImportError("Cannot find GMP library")
    try:
        lib = CDLL(gmp_lib_path)
    except OSError, desc:
        raise ImportError("Cannot load GMP library (%s)" % desc)

# Unfortunately, all symbols exported by the GMP library start with "__"
# and have no trailing underscore.
# You cannot directly refer to them as members of the ctypes' library
# object from within any class because Python will replace the double
# underscore with "_classname_".
_gmp = _GMP()
_gmp.mpz_init_set_si = _gmp.lib.__gmpz_init_set_si
_gmp.mpz_init_set_str = _gmp.lib.__gmpz_init_set_str
_gmp.mpz_set = _gmp.lib.__gmpz_set
_gmp.mpz_set_str = _gmp.lib.__gmpz_set_str
_gmp.gmp_snprintf = _gmp.lib.__gmp_snprintf
_gmp.mpz_add = _gmp.lib.__gmpz_add
_gmp.mpz_import = _gmp.lib.__gmpz_import
_gmp.mpz_export = _gmp.lib.__gmpz_export
_gmp.mpz_sizeinbase = _gmp.lib.__gmpz_sizeinbase
_gmp.mpz_sub = _gmp.lib.__gmpz_sub
_gmp.mpz_mul = _gmp.lib.__gmpz_mul
_gmp.mpz_cmp = _gmp.lib.__gmpz_cmp
_gmp.mpz_powm = _gmp.lib.__gmpz_powm
_gmp.mpz_pow_ui = _gmp.lib.__gmpz_pow_ui
_gmp.mpz_mod = _gmp.lib.__gmpz_mod
_gmp.mpz_neg = _gmp.lib.__gmpz_neg
_gmp.mpz_and = _gmp.lib.__gmpz_and
_gmp.mpz_ior = _gmp.lib.__gmpz_ior
_gmp.mpz_clear = _gmp.lib.__gmpz_clear
_gmp.mpz_tdiv_q_2exp = _gmp.lib.__gmpz_tdiv_q_2exp
_gmp.mpz_tstbit = _gmp.lib.__gmpz_tstbit
_gmp.mpz_perfect_square_p = _gmp.lib.__gmpz_perfect_square_p
_gmp.mpz_jacobi = _gmp.lib.__gmpz_jacobi


class _MPZ(Structure):
    _fields_ = [('_mp_alloc', c_int),
                ('_mp_size', c_int),
                ('_mp_d', c_void_p)]


class Integer(object):

    _zero_mpz = _MPZ()
    _zero_mpz_p = byref(_zero_mpz)
    _gmp.mpz_init_set_si(_zero_mpz_p, c_long(0))

    def __init__(self, value):

        self._mpz = _MPZ()
        self._mpz_p = byref(self._mpz)

        if isinstance(value, float):
            raise ValueError("A floating point type is not a natural number")

        # Special attribute that ctypes checks
        self._as_parameter_ = self._mpz_p

        if hasattr(value, "_mpz_p"):
            _gmp.mpz_set(self, value)
        else:
            abs_value = abs(value)
            if abs_value < 256:
                _gmp.mpz_init_set_si(self, c_long(value))
            else:
                if _gmp.mpz_init_set_str(self, tobytes(str(abs_value)),
                                         c_int(10)) != 0:
                    _gmp.mpz_clear(self)
                    raise ValueError("Error converting '%d'" % value)
                if value < 0:
                    _gmp.mpz_neg(self, self)

    # Conversions
    def __int__(self):

        # buf will contain the integer encoded in decimal plus the trailing
        # zero, and possibly the negative sign.
        # dig10(x) < log10(x) + 1 = log2(x)/log2(10) + 1 < log2(x)/3 + 1
        buf_len = _gmp.mpz_sizeinbase(self, c_int(2)) // 3 + 3
        buf = create_string_buffer(buf_len)

        _gmp.gmp_snprintf(buf, c_size_t(buf_len), b("%Zd"), self)
        return int(buf.value)

    def __str__(self):
        return str(int(self))

    def to_bytes(self, block_size=0):

        if self < 0:
            raise ValueError("Conversion only valid for non-negative numbers")

        buf_len = (_gmp.mpz_sizeinbase(self, c_int(2)) + 7) // 8
        if buf_len > block_size > 0:
            raise ValueError("Too big to convert")
        buf = create_string_buffer(buf_len)

        _gmp.mpz_export(
                byref(buf),
                None,         # Ignore countp
                c_int(1),     # Big endian
                c_size_t(1),  # Each word is 1 byte long
                c_int(0),     # Endianess within a word - not relevant
                c_size_t(0),  # No nails
                self)
        return bchr(0) * max(0, block_size - buf_len) + buf.raw

    @staticmethod
    def from_bytes(byte_string):
        result = Integer(0)
        _gmp.mpz_import(
                        result,
                        c_size_t(len(byte_string)),  # Amount of words to read
                        c_int(1),     # Big endian
                        c_size_t(1),  # Each word is 1 byte long
                        c_int(0),     # Endianess within a word - not relevant
                        c_size_t(0),  # No nails
                        byte_string)
        return result

    # Relations
    def _apply_and_return(self, func, term):
        int_type = self.__class__
        if not isinstance(term, int_type):
            term = int_type(term)
        return func(self, term)

    def __eq__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) == 0

    def __ne__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) != 0

    def __lt__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) < 0

    def __le__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) <= 0

    def __gt__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) > 0

    def __ge__(self, term):
        return self._apply_and_return(_gmp.mpz_cmp, term) >= 0

    def __nonzero__(self):
        return _gmp.mpz_cmp(self, self._zero_mpz_p) != 0

    # Arithmetic operations
    def _apply_in_new_int(self, func, *terms):
        int_type = self.__class__
        result = int_type(0)

        def convert(x):
            if isinstance(x, int_type):
                return x
            else:
                return int_type(x)

        terms = [convert(x) for x in terms]
        func(result, self, *terms)
        return result

    def __add__(self, term):
        return self._apply_in_new_int(_gmp.mpz_add, term)

    def __sub__(self, term):
        return self._apply_in_new_int(_gmp.mpz_sub, term)

    def __mul__(self, term):
        return self._apply_in_new_int(_gmp.mpz_mul, term)

    def __mod__(self, divisor):

        def mod_with_check(result, value, divisor):
            comp = _gmp.mpz_cmp(divisor, value._zero_mpz_p)
            if comp == 0:
                raise ZeroDivisionError("Division by zero")
            if comp < 0:
                raise ValueError("Modulus must be positive")
            _gmp.mpz_mod(result, value, divisor)

        return self._apply_in_new_int(mod_with_check, divisor)

    def __pow__(self, exponent, modulus=None):

        if exponent < 0:
            raise ValueError("Exponent must not be negative")

        if modulus is None:
            # Normal exponentiation
            int_type = self.__class__
            result = int_type(0)
            if exponent > 256:
                raise ValueError("Exponent is too big")
            _gmp.mpz_pow_ui(result,
                            self,   # Base
                            c_long(int(exponent))
                            )
            return result
        else:
            # Modular exponentiation
            if modulus == 0:
                raise ZeroDivisionError("Division by zero")
            if modulus < 0:
                raise ValueError("Modulus must be positive")
            return self._apply_in_new_int(_gmp.mpz_powm, exponent, modulus)

    # Boolean/bit operations
    def __and__(self, term):
        return self._apply_in_new_int(_gmp.mpz_and, term)

    def __or__(self, term):
        return self._apply_in_new_int(_gmp.mpz_ior, term)

    def __rshift__(self, pos):
        result = self.__class__(0)
        shift_amount = int(pos)
        if shift_amount < 0:
            raise ValueError("Negative shift count")
        _gmp.mpz_tdiv_q_2exp(result, self, c_int(shift_amount))
        return result

    def __irshift__(self, pos):
        shift_amount = int(pos)
        if shift_amount < 0:
            raise ValueError("Negative shift count")
        _gmp.mpz_tdiv_q_2exp(self, self, c_int(shift_amount))
        return self

    # Extra
    def is_odd(self):
        return _gmp.mpz_tstbit(self, c_int(0)) == 1

    def is_even(self):
        return _gmp.mpz_tstbit(self, c_int(0)) == 0

    def size_in_bits(self):
        if self < 0:
            raise ValueError("Conversion only valid for non-negative numbers")
        return _gmp.mpz_sizeinbase(self, c_int(2))

    def is_perfect_square(self):
        return _gmp.mpz_perfect_square_p(self) != 0

    @staticmethod
    def jacobi_symbol(a, n):

        if not isinstance(a, Integer):
            a = Integer(a)
        if not isinstance(n, Integer):
            n = Integer(n)
        if n <= 0 or n.is_even():
            raise ValueError("n must be positive even for the Jacobi symbol")
        return _gmp.mpz_jacobi(a, n)

    # Clean-up
    def __del__(self):

        if self._mpz_p is not None:
            _gmp.mpz_clear(self._mpz_p)
        self._mpz_p = None
