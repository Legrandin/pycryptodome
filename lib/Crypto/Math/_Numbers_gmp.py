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
_gmp.mpz_cmp = _gmp.lib.__gmpz_cmp
_gmp.mpz_powm = _gmp.lib.__gmpz_powm
_gmp.mpz_mod = _gmp.lib.__gmpz_mod
_gmp.mpz_neg = _gmp.lib.__gmpz_neg
_gmp.mpz_and = _gmp.lib.__gmpz_and
_gmp.mpz_clear = _gmp.lib.__gmpz_clear
_gmp.mpz_fdiv_q_2exp = _gmp.lib.__gmpz_fdiv_q_2exp
_gmp.mpz_tstbit = _gmp.lib.__gmpz_tstbit
_gmp.mpz_perfect_square_p = _gmp.lib.__gmpz_perfect_square_p


class _MPZ(Structure):
    _fields_ = [('_mp_alloc', c_int),
                ('_mp_size', c_int),
                ('_mp_d', c_void_p)]


class Natural(object):

    _zero_mpz = _MPZ()
    _zero_mpz_p = byref(_zero_mpz)
    _gmp.mpz_init_set_si(_zero_mpz_p, c_long(0))

    def __init__(self, value):

        self._mpz = None
        self._mpz_p = None

        self._set(value)

        if _gmp.mpz_cmp(self._mpz_p, self._zero_mpz_p) < 0:
            raise ValueError("Negative values are not natural")

    def _set(self, value):
        """Set this object to an integer value (possibly negative)"""

        if isinstance(value, float):
            raise ValueError("A floating point type is not a natural number")

        if self._mpz_p is not None:
            _gmp.mpz_clear(self._mpz_p)

        self._mpz = _MPZ()
        self._mpz_p = byref(self._mpz)

        if isinstance(value, Natural):
            _gmp.mpz_set(self._mpz_p, value._mpz_p)
        else:
            abs_value = abs(value)
            if abs_value < 256:
                _gmp.mpz_init_set_si(self._mpz_p, c_long(value))
            else:
                if _gmp.mpz_init_set_str(self._mpz_p, tobytes(str(abs_value)),
                                         c_int(10)) != 0:
                    _gmp.mpz_clear(self._mpz_p)
                    raise ValueError("Error converting '%d'" % value)
                if value < 0:
                    _gmp.mpz_neg(self._mpz_p, self._mpz_p)

        return self

    def to_bytes(self, block_size=0):

        buf_len = (_gmp.mpz_sizeinbase(self._mpz_p, c_int(2)) + 7) // 8
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
                self._mpz_p)
        return bchr(0) * max(0, block_size - buf_len) + buf.raw

    def __int__(self):

        buf_len = _gmp.mpz_sizeinbase(self._mpz_p, c_int(2)) // 3 + 3
        buf = create_string_buffer(buf_len)

        _gmp.gmp_snprintf(buf, c_size_t(buf_len), b("%Zd"), self._mpz_p)
        return int(buf.value)

    def __str__(self):
        return str(int(self))

    @staticmethod
    def from_bytes(byte_string):
        result = Natural(0)
        _gmp.mpz_import(
                        result._mpz_p,
                        c_size_t(len(byte_string)),  # Amount of words to read
                        c_int(1),     # Big endian
                        c_size_t(1),  # Each word is 1 byte long
                        c_int(0),     # Endianess within a word - not relevant
                        c_size_t(0),  # No nails
                        byte_string)
        return result

    # Arithmetic operations
    def __add__(self, term):

        result = Natural(0)
        if not isinstance(term, Natural):
            term = Natural(0)._set(term)
        _gmp.mpz_add(result._mpz_p, self._mpz_p, term._mpz_p)

        if _gmp.mpz_cmp(result._mpz_p, self._zero_mpz_p) < 0:
            raise ValueError("Result of addition is negative")

        return result

    def __sub__(self, term):

        result = Natural(0)
        if not isinstance(term, Natural):
            term = Natural(0)._set(term)
        _gmp.mpz_sub(result._mpz_p, self._mpz_p, term._mpz_p)

        if _gmp.mpz_cmp(result._mpz_p, self._zero_mpz_p) < 0:
            raise ValueError("Result of subtraction is negative")

        return result

    def __mod__(self, divisor):

        result = Natural(0)
        if not isinstance(divisor, Natural):
            divisor = Natural(divisor)

        if _gmp.mpz_cmp(divisor._mpz_p, self._zero_mpz_p) == 0:
            raise ZeroDivisionError("Division by zero")

        _gmp.mpz_mod(result._mpz_p, self._mpz_p, divisor._mpz_p)
        return result

    def __pow__(self, exponent, modulus):

        result = Natural(0)
        if not isinstance(exponent, Natural):
            exponent = Natural(exponent)
        if not isinstance(modulus, Natural):
            modulus = Natural(modulus)

        if modulus == 0:
            raise ValueError("Modulus must not be zero")

        _gmp.mpz_powm(result._mpz_p,
                      self._mpz_p,     # Base
                      exponent._mpz_p,
                      modulus._mpz_p
                      )
        return result

    # Boolean operations
    def __and__(self, term):

        result = Natural(0)
        if not isinstance(term, Natural):
            term = Natural(term)
        _gmp.mpz_and(result._mpz_p, self._mpz_p, term._mpz_p)
        return result

    def __irshift__(self, pos):
        _gmp.mpz_fdiv_q_2exp(self._mpz_p, self._mpz_p, c_int(int(pos)))
        return self

    def size_in_bits(self):
        return _gmp.mpz_sizeinbase(self._mpz_p, c_int(2))

    def is_odd(self):
        return _gmp.mpz_tstbit(self._mpz_p, 0) == 1

    def is_even(self):
        return _gmp.mpz_tstbit(self._mpz_p, 0) == 0

    # Relations
    def __eq__(self, term):

        if not isinstance(term, Natural):
            term = Natural(0)._set(term)
        return _gmp.mpz_cmp(self._mpz_p, term._mpz_p) == 0

    def __ne__(self, term):
        return not self.__eq__(term)

    def __lt__(self, term):

        if not isinstance(term, Natural):
            term = Natural(0)._set(term)
        return _gmp.mpz_cmp(self._mpz_p, term._mpz_p) < 0

    def __le__(self, term):
        return self.__lt__(term) or self.__eq__(term)

    def __gt__(self, term):
        return not self.__le__(term)

    def __ge__(self, term):
        return not self.__lt__(term)

    def __nonzero__(self):
        return _gmp.mpz_cmp(self._mpz_p, self._zero_mpz_p) != 0

    # Extra
    def is_perfect_square(self):
        return _gmp.mpz_perfect_square_p(self._mpz_p) != 0

    def __del__(self):

        if self._mpz_p is not None:
            _gmp.mpz_clear(self._mpz_p)
        self._mpz_p = None
