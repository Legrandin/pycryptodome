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

from ctypes import (CDLL, Structure, c_int, c_void_p, c_long, c_ulong,
                    byref, c_size_t, create_string_buffer)
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
_gmp.mpz_add_ui = _gmp.lib.__gmpz_add_ui
_gmp.mpz_sub_ui = _gmp.lib.__gmpz_sub_ui
_gmp.mpz_addmul = _gmp.lib.__gmpz_addmul
_gmp.mpz_addmul_ui = _gmp.lib.__gmpz_addmul_ui
_gmp.mpz_submul_ui = _gmp.lib.__gmpz_submul_ui
_gmp.mpz_import = _gmp.lib.__gmpz_import
_gmp.mpz_export = _gmp.lib.__gmpz_export
_gmp.mpz_sizeinbase = _gmp.lib.__gmpz_sizeinbase
_gmp.mpz_sub = _gmp.lib.__gmpz_sub
_gmp.mpz_mul = _gmp.lib.__gmpz_mul
_gmp.mpz_mul_si = _gmp.lib.__gmpz_mul_si
_gmp.mpz_cmp = _gmp.lib.__gmpz_cmp
_gmp.mpz_powm = _gmp.lib.__gmpz_powm
_gmp.mpz_powm_ui = _gmp.lib.__gmpz_powm_ui
_gmp.mpz_pow_ui = _gmp.lib.__gmpz_pow_ui
_gmp.mpz_mod = _gmp.lib.__gmpz_mod
_gmp.mpz_neg = _gmp.lib.__gmpz_neg
_gmp.mpz_and = _gmp.lib.__gmpz_and
_gmp.mpz_ior = _gmp.lib.__gmpz_ior
_gmp.mpz_clear = _gmp.lib.__gmpz_clear
_gmp.mpz_tdiv_q_2exp = _gmp.lib.__gmpz_tdiv_q_2exp
_gmp.mpz_fdiv_q = _gmp.lib.__gmpz_fdiv_q
_gmp.mpz_mul_2exp = _gmp.lib.__gmpz_mul_2exp
_gmp.mpz_tstbit = _gmp.lib.__gmpz_tstbit
_gmp.mpz_perfect_square_p = _gmp.lib.__gmpz_perfect_square_p
_gmp.mpz_jacobi = _gmp.lib.__gmpz_jacobi
_gmp.mpz_gcd = _gmp.lib.__gmpz_gcd
_gmp.mpz_gcd_ui = _gmp.lib.__gmpz_gcd_ui
_gmp.mpz_invert = _gmp.lib.__gmpz_invert
_gmp.mpz_divisible_p = _gmp.lib.__gmpz_divisible_p
_gmp.mpz_divisible_ui_p = _gmp.lib.__gmpz_divisible_ui_p


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

        if isinstance(value, (int, long)):
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
        else:
            _gmp.mpz_set(self, value)

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

    def __repr__(self):
        return "Integer(%s)" % str(self)

    def to_bytes(self, block_size=0):
        """Convert the number into a byte string.

        This method encodes the number in network order and prepends
        as many zero bytes as required. It only works for non-negative
        values.

        :Parameters:
          block_size : integer
            The exact size the output byte string must have.
            If zero, the string has the minimal length.
        :Returns:
          A byte string.
        :Raises:
          ``ValueError`` if the value is negative or if ``block_size`` is
          provided and the length of the byte string would exceed it.
        """

        if self < 0:
            raise ValueError("Conversion only valid for non-negative numbers")

        buf_len = (_gmp.mpz_sizeinbase(self, c_int(2)) + 7) // 8
        if buf_len > block_size > 0:
            raise ValueError("Number is too big to convert to byte string"
                             "of prescribed length")
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
        """Convert a byte string into a number.

        :Parameters:
          byte_string : byte string
            The input number, encoded in network order.
            It can only be non-negative.
        :Return:
          The ``Integer`` object carrying the same value as the input.
        """
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
        if not isinstance(term, Integer):
            term = Integer(term)
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

    def is_negative(self):
        return _gmp.mpz_cmp(self, self._zero_mpz_p) < 0

    # Arithmetic operations
    def _apply_in_new_int(self, func, *terms):
        result = Integer(0)

        def convert(x):
            if isinstance(x, Integer):
                return x
            else:
                return Integer(x)

        terms = [convert(x) for x in terms]
        func(result, self, *terms)
        return result

    def __add__(self, term):
        return self._apply_in_new_int(_gmp.mpz_add, term)

    def __sub__(self, term):
        return self._apply_in_new_int(_gmp.mpz_sub, term)

    def __mul__(self, term):
        return self._apply_in_new_int(_gmp.mpz_mul, term)

    def __floordiv__(self, divisor):
        if not isinstance(divisor, Integer):
            divisor = Integer(divisor)
        comp = _gmp.mpz_cmp(divisor, self._zero_mpz_p)
        if comp == 0:
            raise ZeroDivisionError("Division by zero")
        result = Integer(0)
        _gmp.mpz_fdiv_q(result, self, divisor)
        return result

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

        result = Integer(0)

        if modulus is None:
            if exponent < 0:
                raise ValueError("Exponent must not be negative")

            # Normal exponentiation
            result = Integer(0)
            if exponent > 256:
                raise ValueError("Exponent is too big")
            _gmp.mpz_pow_ui(result,
                            self,   # Base
                            c_long(int(exponent))
                            )
            return result
        else:
            # Modular exponentiation
            if not isinstance(modulus, Integer):
                modulus = Integer(modulus)
            if not modulus:
                raise ZeroDivisionError("Division by zero")
            if modulus.is_negative():
                raise ValueError("Modulus must be positive")
            if isinstance(exponent, (int, long)):
                if exponent < 0:
                    raise ValueError("Exponent must not be negative")
                exp_ulong = c_ulong(exponent)
                if exp_ulong.value == exponent:
                    _gmp.mpz_powm_ui(result, self, exp_ulong, modulus)
                    return result
                else:
                    exponent = Integer(exponent)
            elif exponent.is_negative():
                raise ValueError("Exponent must not be negative")
            _gmp.mpz_powm(result, self, exponent, modulus)
            return result

    def __iadd__(self, term):
        if isinstance(term, (int, long)):
            op2_p = c_ulong(term)
            op2_m = c_ulong(-term)
            if op2_p.value == term:
                _gmp.mpz_add_ui(self, self, op2_p)
                return self
            elif op2_m.value == -term:
                _gmp.mpz_sub_ui(self, self, op2_m)
                return self
            else:
                term = Integer(term)
        _gmp.mpz_add(self, self, term)
        return self

    def __imul__(self, term):
        if isinstance(term, (int, long)):
            op2 = c_long(term)
            if op2.value == term:
                _gmp.mpz_mul_si(self, self, op2)
                return self
            else:
                term = Integer(term)
        _gmp.mpz_mul(self, self, term)
        return self

    def __imod__(self, divisor):
        if not isinstance(divisor, Integer):
            divisor = Integer(divisor)
        comp = _gmp.mpz_cmp(divisor, divisor._zero_mpz_p)
        if comp == 0:
            raise ZeroDivisionError("Division by zero")
        if comp < 0:
            raise ValueError("Modulus must be positive")
        _gmp.mpz_mod(self, self, divisor)
        return self

    # Boolean/bit operations
    def __and__(self, term):
        return self._apply_in_new_int(_gmp.mpz_and, term)

    def __or__(self, term):
        return self._apply_in_new_int(_gmp.mpz_ior, term)

    def __rshift__(self, pos):
        result = Integer(0)
        shift_amount = c_ulong(int(pos))
        if shift_amount.value != pos:
            raise ValueError("Incorrect shift count")
        _gmp.mpz_tdiv_q_2exp(result, self, shift_amount)
        return result

    def __irshift__(self, pos):
        shift_amount = c_ulong(int(pos))
        if shift_amount.value != pos:
            raise ValueError("Incorrect shift count")
        _gmp.mpz_tdiv_q_2exp(self, self, shift_amount)
        return self

    def __lshift__(self, pos):
        result = Integer(0)
        shift_amount = c_ulong(int(pos))
        if shift_amount.value != pos:
            raise ValueError("Incorrect shift count")
        _gmp.mpz_mul_2exp(result, self, shift_amount)
        return result

    def __ilshift__(self, pos):
        shift_amount = c_ulong(int(pos))
        if shift_amount.value != pos:
            raise ValueError("Incorrect shift count")
        _gmp.mpz_mul_2exp(self, self, shift_amount)
        return self

    def get_bit(self, n):
        """Return True if the n-th bit is set to 1.
        Bit 0 is the least significant."""

        bit_pos = c_ulong(int(n))
        if bit_pos.value != n:
            raise ValueError("Incorrect bit position")
        return bool(_gmp.mpz_tstbit(self, bit_pos))

    # Extra
    def is_odd(self):
        return _gmp.mpz_tstbit(self, c_int(0)) == 1

    def is_even(self):
        return _gmp.mpz_tstbit(self, c_int(0)) == 0

    def size_in_bits(self):
        """Return the minimum number of bits that can encode the number."""

        if self < 0:
            raise ValueError("Conversion only valid for non-negative numbers")
        return _gmp.mpz_sizeinbase(self, c_int(2))

    def is_perfect_square(self):
        return _gmp.mpz_perfect_square_p(self) != 0

    def fail_if_divisible_by(self, small_prime):
        """Raise an exception if the small prime is a divisor."""

        if type(small_prime) == Integer:
            if _gmp.mpz_divisible_p(self, small_prime):
                raise ValueError("The value is composite")
        else:
            d = c_ulong(small_prime)
            if d.value != small_prime:
                self.fail_if_divisible_by(Integer(small_prime))
                return
            if _gmp.mpz_divisible_ui_p(self, d):
                raise ValueError("The value is composite")

    def multiply_accumulate(self, a, b):
        """Increment the number by the product of a and b."""

        if not isinstance(a, Integer):
            a = Integer(a)
        if isinstance(b, (int, long)):
            op2 = c_ulong(b)
            if op2.value == b:
                _gmp.mpz_addmul_ui(self, a, op2)
                return self
            else:
                op2 = c_ulong(-b)
                if op2.value == -b:
                    _gmp.mpz_submul_ui(self, a, op2)
                    return self
            b = Integer(b)
        _gmp.mpz_addmul(self, a, b)
        return self

    def set(self, source):
        if not isinstance(source, Integer):
            source = Integer(source)
        _gmp.mpz_set(self, source)
        return self

    def inverse(self, modulus):
        """Compute the inverse of this number in the ring of
        modulo integers.

        Raise an exception if no inverse exists.
        """

        if not isinstance(modulus, Integer):
            modulus = Integer(modulus)
        comp = _gmp.mpz_cmp(modulus, self._zero_mpz_p)
        if comp == 0:
            raise ZeroDivisionError("Modulus cannot be zero")
        if comp < 0:
            raise ValueError("Modulus must be positive")
        result = Integer(0)
        _gmp.mpz_invert(result, self, modulus)
        if not result:
            raise ValueError("No inverse value can be computed")
        return result

    def gcd(self, term):
        """Compute the greatest common denominator between this
        number and another term."""

        result = Integer(0)
        if isinstance(term, (int, long)):
            b = c_ulong(term)
            if b.value == term:
                _gmp.mpz_gcd_ui(result, self, b)
                return result
            term = Integer(term)
        _gmp.mpz_gcd(result, self, term)
        return result

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

        try:
            if self._mpz_p is not None:
                _gmp.mpz_clear(self._mpz_p)
            self._mpz_p = None
        except AttributeError:
            pass
