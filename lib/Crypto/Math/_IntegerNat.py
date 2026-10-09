# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Natural numbers (0, 1, 2, ...) with constant-time arithmetic.

All the arithmetic runs in C (module ``Crypto.Math._nat``).
Each number has a public bound on its size (``_bits``): the value is
always smaller than ``2**_bits``. The bound of a result only depends on
the bounds of the operands, never on their values, and the C code always
works on all the words that the bound requires.

Some methods return information that depends on the value by
definition, and leak it on purpose: the result of comparisons,
``bool()``, ``is_odd()``, ``is_even()``, ``get_bit()``,
``is_perfect_square()``, ``size_in_bits()``, ``size_in_bytes()``,
the length of ``to_bytes()`` without a block size, and the fact that
an exception is raised.
``__int__``, ``__str__``, ``__repr__`` and ``_public_trim()``
are not constant time, and are only meant for public values.
"""

from __future__ import annotations

import operator
from typing import Any, Optional, Union

from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    backend,
    c_size_t,
    c_uint8_ptr,
    c_ulonglong,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

from ._IntegerBase import IntegerBase

_nat_cdecl = """
int nat_new(void **out, size_t nw);
void nat_free(void *x);
int nat_copy(void *out, const void *a);
int nat_from_bytes(void *out, const uint8_t *in, size_t len, int little_endian);
int nat_to_bytes(uint8_t *out, size_t len, const void *a, int little_endian);
int nat_from_uint64(void *out, uint64_t v);
int nat_bit_length(const void *a);
int nat_is_zero(const void *a);
int nat_is_odd(const void *a);
int nat_cmp(const void *a, const void *b);
int nat_get_bit(const void *a, size_t n);
int nat_add(void *out, const void *a, const void *b);
int nat_sub(void *out, const void *a, const void *b);
int nat_mul(void *out, const void *a, const void *b);
int nat_muladd(void *out, const void *c, const void *a, const void *b);
int nat_and(void *out, const void *a, const void *b);
int nat_or(void *out, const void *a, const void *b);
int nat_shl(void *out, const void *a, size_t k);
int nat_shr(void *out, const void *a, size_t k);
int nat_divmod(void *q, void *r, const void *a, const void *b);
int nat_mod_small(void *out, const void *a, uint64_t d);
int nat_mulmod(void *out, const void *a, const void *b, const void *m);
int nat_submod(void *out, const void *a, const void *b, const void *m);
int nat_powmod(void *out, const void *a, const void *e, const void *m);
int nat_invmod(void *out, const void *a, const void *m);
int nat_gcd(void *out, const void *a, const void *b);
int nat_jacobi(void *out, const void *a, const void *n, int negate);
int nat_isqrt(void *out, const void *a);
int nat_miller_rabin(void *out, const void *n, const void *base);
int nat_lucas(void *out, const void *n, uint64_t abs_d, int negative_d);
"""

_lib = load_pycryptodome_raw_lib("Crypto.Math._nat", _nat_cdecl)
implementation = {"library": "nat", "api": backend}

# Errors from src/errors.h
_ERR_VALUE = 14

# Same as NAT_MAX_WORDS in src/nat.h
_MAX_BITS = 64 * (1 << 14)

IntLike = Union[IntegerBase, int]


def _check(result: int, what: str) -> None:
    if result:
        raise ValueError("Error %d in %s" % (result, what))


def _new_nat(bits: int) -> SmartPointer:
    """Allocate a C number that can hold values smaller than 2**bits"""

    if bits > _MAX_BITS:
        raise ValueError("Integer too large (%d bits)" % bits)
    nw = max(1, (bits + 63) // 64)
    raw = VoidPointer()
    _check(_lib.nat_new(raw.address_of(), c_size_t(nw)), "nat_new")
    return SmartPointer(raw.get(), _lib.nat_free)


class IntegerNat(IntegerBase):
    """A natural number (0, 1, 2, ...), with constant-time arithmetic"""

    _p: SmartPointer
    _bits: int

    def __init__(self, value: Union[IntegerBase, int], _min_bits: int = 0) -> None:
        if isinstance(value, IntegerNat):
            self._alloc(max(value._bits, _min_bits))
            _lib.nat_copy(self._p.get(), value._p.get())
            return

        if isinstance(value, float):
            raise ValueError("A floating point type is not a natural number")
        if isinstance(value, IntegerBase):
            value = int(value)
        value = operator.index(value)
        if value < 0:
            raise ValueError("Integer cannot be negative")

        nbytes = max(1, (value.bit_length() + 7) // 8)
        self._alloc(max(value.bit_length(), _min_bits))
        data = value.to_bytes(nbytes, "little")
        _check(_lib.nat_from_bytes(self._p.get(), data, c_size_t(nbytes), 1), "nat_from_bytes")

    # Internal helpers

    def _alloc(self, bits: int) -> None:
        self._bits = max(1, bits)
        self._p = _new_nat(self._bits)

    @classmethod
    def _make(cls, bits: int) -> IntegerNat:
        """A new number equal to 0, with the given bound"""
        obj = cls.__new__(cls)
        obj._alloc(bits)
        return obj

    def _adopt(self, other: IntegerNat) -> IntegerNat:
        """Take the value and the bound of another (temporary) number"""
        self._p = other._p
        self._bits = other._bits
        return self

    @staticmethod
    def _conv(term: Any) -> IntegerNat:
        """Convert an operand into an IntegerNat.

        TypeError if it is not an integer, ValueError if it is negative.
        """
        if isinstance(term, IntegerNat):
            return term
        if isinstance(term, float):
            raise TypeError("A floating point type is not a natural number")
        if isinstance(term, IntegerBase):
            return IntegerNat(int(term))
        return IntegerNat(operator.index(term))

    def _nw(self) -> int:
        return max(1, (self._bits + 63) // 64)

    def _is_zero(self) -> bool:
        return bool(_lib.nat_is_zero(self._p.get()))

    def _resize(self, bits: int) -> IntegerNat:
        """Set the bound to exactly ``bits``.

        Raise ValueError if the value does not fit; only that fact leaks.
        """
        if not (self >> bits)._is_zero():
            raise ValueError("Value does not fit into %d bits" % bits)
        result = IntegerNat._make(bits)
        _lib.nat_copy(result._p.get(), self._p.get())
        return self._adopt(result)

    def _public_trim(self) -> IntegerNat:
        """Shrink the bound to the actual size of the value.

        Not constant time: only for public values.
        """
        return self._resize(self.size_in_bits())

    def _sub_mod(self, term: IntLike, modulus: IntLike) -> IntegerNat:
        """Return (self - term) mod modulus, for self and term smaller than the modulus"""
        term = self._conv(term)
        modulus = self._conv(modulus)
        result = IntegerNat._make(modulus._bits)
        _check(_lib.nat_submod(result._p.get(), self._p.get(), term._p.get(), modulus._p.get()), "nat_submod")
        return result

    # Conversions

    def __int__(self) -> int:
        nbytes = 8 * self._nw()
        buf = create_string_buffer(nbytes)
        _check(_lib.nat_to_bytes(buf, c_size_t(nbytes), self._p.get(), 1), "nat_to_bytes")
        return int.from_bytes(get_raw_buffer(buf), "little")

    def __index__(self) -> int:
        return int(self)

    def __str__(self) -> str:
        return str(int(self))

    def __repr__(self) -> str:
        return "Integer(%s)" % str(self)

    def to_bytes(self, block_size: Optional[int] = 0, byteorder: str = "big") -> bytes:
        if byteorder not in ("big", "little"):
            raise ValueError("Incorrect byteorder")
        if not block_size:
            block_size = self.size_in_bytes()
        buf = create_string_buffer(block_size)
        result = _lib.nat_to_bytes(buf, c_size_t(block_size), self._p.get(), int(byteorder == "little"))
        if result == _ERR_VALUE:
            raise ValueError("Value too large to encode")
        _check(result, "nat_to_bytes")
        return get_raw_buffer(buf)

    @classmethod
    def from_bytes(
        cls, byte_string: Union[bytes, bytearray, memoryview], byteorder: str = "big", _min_bits: int = 0
    ) -> IntegerNat:
        if byteorder not in ("big", "little"):
            raise ValueError("Incorrect byteorder")
        length = len(byte_string)
        result = cls._make(max(8 * length, _min_bits))
        _check(
            _lib.nat_from_bytes(
                result._p.get(), c_uint8_ptr(byte_string), c_size_t(length), int(byteorder == "little")
            ),
            "nat_from_bytes",
        )
        return result

    # Relations

    def _cmp(self, term: Any) -> int:
        if isinstance(term, int) and term < 0:
            return 1
        # Keep a reference to the converted term until the C call is done
        other = self._conv(term)
        return _lib.nat_cmp(self._p.get(), other._p.get())

    def __eq__(self, term: object) -> bool:
        if term is None:
            return False
        try:
            return self._cmp(term) == 0
        except (TypeError, ValueError):
            return NotImplemented

    def __ne__(self, term: object) -> bool:
        result = self.__eq__(term)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, term: IntLike) -> bool:
        return self._cmp(term) < 0

    def __le__(self, term: IntLike) -> bool:
        return self._cmp(term) <= 0

    def __gt__(self, term: IntLike) -> bool:
        return self._cmp(term) > 0

    def __ge__(self, term: IntLike) -> bool:
        return self._cmp(term) >= 0

    def __bool__(self) -> bool:
        return not self._is_zero()

    def is_negative(self) -> bool:
        return False

    # Arithmetic operations

    def __add__(self, term: IntLike) -> IntegerNat:
        try:
            term = self._conv(term)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(max(self._bits, term._bits) + 1)
        _check(_lib.nat_add(result._p.get(), self._p.get(), term._p.get()), "nat_add")
        return result

    __radd__ = __add__

    def __sub__(self, term: IntLike) -> IntegerNat:
        try:
            term = self._conv(term)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(max(self._bits, term._bits))
        error = _lib.nat_sub(result._p.get(), self._p.get(), term._p.get())
        if error == _ERR_VALUE:
            raise ValueError("The result of the subtraction would be negative")
        _check(error, "nat_sub")
        return result

    def __rsub__(self, term: int) -> IntegerNat:
        try:
            term_nat = self._conv(term)
        except TypeError:
            return NotImplemented
        return term_nat - self

    def __mul__(self, factor: IntLike) -> IntegerNat:
        try:
            factor = self._conv(factor)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(self._bits + factor._bits)
        _check(_lib.nat_mul(result._p.get(), self._p.get(), factor._p.get()), "nat_mul")
        return result

    __rmul__ = __mul__

    def __floordiv__(self, divisor: IntLike) -> IntegerNat:
        divisor = self._conv(divisor)
        if divisor._is_zero():
            raise ZeroDivisionError("Division by zero")
        result = IntegerNat._make(self._bits)
        _check(_lib.nat_divmod(result._p.get(), None, self._p.get(), divisor._p.get()), "nat_divmod")
        return result

    def __mod__(self, divisor: IntLike) -> IntegerNat:
        if isinstance(divisor, int) and divisor < 0:
            raise ValueError("Modulus must be positive")
        divisor = self._conv(divisor)
        if divisor._is_zero():
            raise ZeroDivisionError("Modulus cannot be zero")
        result = IntegerNat._make(divisor._bits)
        _check(_lib.nat_divmod(None, result._p.get(), self._p.get(), divisor._p.get()), "nat_divmod")
        return result

    def _check_modulus(self, modulus: Any) -> IntegerNat:
        if isinstance(modulus, int) and modulus < 0:
            raise ValueError("Modulus must be positive")
        modulus = self._conv(modulus)
        if modulus._is_zero():
            raise ZeroDivisionError("Modulus cannot be zero")
        return modulus

    def inplace_pow(self, exponent: IntLike, modulus: Optional[IntLike] = None) -> IntegerNat:
        if isinstance(exponent, int) and exponent < 0:
            raise ValueError("Exponent must not be negative")
        exponent = self._conv(exponent)

        if modulus is None:
            # The exponent must be public: it is converted to a Python int
            exp_value = int(exponent)
            result = IntegerNat(1)
            for bit in bin(exp_value)[2:]:
                result = result * result
                if bit == "1":
                    result = result * self
            return self._adopt(result)

        modulus = self._check_modulus(modulus)
        result = IntegerNat._make(modulus._bits)
        _check(
            _lib.nat_powmod(result._p.get(), self._p.get(), exponent._p.get(), modulus._p.get()), "nat_powmod"
        )
        return self._adopt(result)

    def __pow__(self, exponent: IntLike, modulus: Optional[IntLike] = None) -> IntegerNat:
        result = IntegerNat(self)
        return result.inplace_pow(exponent, modulus)

    def __abs__(self) -> IntegerNat:
        return IntegerNat(self)

    def sqrt(self, modulus: Optional[IntLike] = None) -> IntegerNat:
        if modulus is None:
            result = IntegerNat._make(self._bits // 2 + 1)
            _check(_lib.nat_isqrt(result._p.get(), self._p.get()), "nat_isqrt")
            return result

        if isinstance(modulus, int) and modulus <= 0:
            raise ValueError("Modulus must be positive")
        modulus = self._conv(modulus)
        if modulus._is_zero():
            raise ValueError("Modulus must be positive")
        return IntegerNat(self._tonelli_shanks(self % modulus, modulus))

    def __iadd__(self, term: IntLike) -> IntegerNat:
        return self._adopt(self + term)

    def __isub__(self, term: IntLike) -> IntegerNat:
        return self._adopt(self - term)

    def __imul__(self, term: IntLike) -> IntegerNat:
        return self._adopt(self * term)

    def __imod__(self, term: IntLike) -> IntegerNat:
        return self._adopt(self % term)

    # Boolean/bit operations

    def __and__(self, term: IntLike) -> IntegerNat:
        term = self._conv(term)
        result = IntegerNat._make(min(self._bits, term._bits))
        _check(_lib.nat_and(result._p.get(), self._p.get(), term._p.get()), "nat_and")
        return result

    def __or__(self, term: IntLike) -> IntegerNat:
        term = self._conv(term)
        result = IntegerNat._make(max(self._bits, term._bits))
        _check(_lib.nat_or(result._p.get(), self._p.get(), term._p.get()), "nat_or")
        return result

    @staticmethod
    def _shift_count(pos: IntLike) -> int:
        value = int(pos)
        if value < 0:
            raise ValueError("negative shift count")
        return value

    def __rshift__(self, pos: IntLike) -> IntegerNat:
        count = self._shift_count(pos)
        if count >= self._bits:
            return IntegerNat(0)
        result = IntegerNat._make(self._bits - count)
        _check(_lib.nat_shr(result._p.get(), self._p.get(), c_size_t(count)), "nat_shr")
        return result

    def __irshift__(self, pos: IntLike) -> IntegerNat:
        return self._adopt(self >> pos)

    def __lshift__(self, pos: IntLike) -> IntegerNat:
        count = self._shift_count(pos)
        if self._bits + count > _MAX_BITS:
            raise ValueError("Incorrect shift count")
        result = IntegerNat._make(self._bits + count)
        _check(_lib.nat_shl(result._p.get(), self._p.get(), c_size_t(count)), "nat_shl")
        return result

    def __ilshift__(self, pos: IntLike) -> IntegerNat:
        return self._adopt(self << pos)

    def get_bit(self, n: IntLike) -> bool:
        bit = int(n)
        if bit < 0:
            raise ValueError("negative bit count")
        if bit >= 64 * self._nw():
            return False
        return bool(_lib.nat_get_bit(self._p.get(), c_size_t(bit)))

    # Extra

    def is_odd(self) -> bool:
        return bool(_lib.nat_is_odd(self._p.get()))

    def is_even(self) -> bool:
        return not self.is_odd()

    def size_in_bits(self) -> int:
        return max(1, _lib.nat_bit_length(self._p.get()))

    def size_in_bytes(self) -> int:
        return (self.size_in_bits() - 1) // 8 + 1

    def is_perfect_square(self) -> bool:
        root = self.sqrt()
        return root * root == self

    def fail_if_divisible_by(self, small_prime: IntLike) -> None:
        divisor = int(small_prime)
        if 0 < divisor < 2**32:
            remainder = IntegerNat._make(64)
            _check(
                _lib.nat_mod_small(remainder._p.get(), self._p.get(), c_ulonglong(divisor)), "nat_mod_small"
            )
        else:
            remainder = self % divisor
        if remainder._is_zero():
            raise ValueError("Value is composite")

    def multiply_accumulate(self, a: IntLike, b: IntLike) -> IntegerNat:
        a = self._conv(a)
        b = self._conv(b)
        result = IntegerNat._make(max(self._bits, a._bits + b._bits) + 1)
        _check(_lib.nat_muladd(result._p.get(), self._p.get(), a._p.get(), b._p.get()), "nat_muladd")
        return self._adopt(result)

    def set(self, source: IntLike) -> IntegerNat:
        return self._adopt(IntegerNat(source))

    def inplace_inverse(self, modulus: IntLike) -> IntegerNat:
        modulus = self._check_modulus(modulus)
        result = IntegerNat._make(modulus._bits)
        error = _lib.nat_invmod(result._p.get(), self._p.get(), modulus._p.get())
        if error == _ERR_VALUE:
            raise ValueError("No inverse value can be computed")
        _check(error, "nat_invmod")
        return self._adopt(result)

    def inverse(self, modulus: IntLike) -> IntegerNat:
        result = IntegerNat(self)
        return result.inplace_inverse(modulus)

    def gcd(self, term: IntLike) -> IntegerNat:
        term = self._conv(term)
        result = IntegerNat._make(max(self._bits, term._bits))
        _check(_lib.nat_gcd(result._p.get(), self._p.get(), term._p.get()), "nat_gcd")
        return result

    def lcm(self, term: IntLike) -> IntegerNat:
        term = self._conv(term)
        gcd = self.gcd(term)
        # Only the fact that both numbers are zero leaks
        if gcd._is_zero():
            return IntegerNat(0)
        return (self * term) // gcd

    @staticmethod
    def jacobi_symbol(a: IntLike, n: IntLike) -> int:
        if isinstance(n, int) and n <= 0:
            raise ValueError("n must be a positive integer")
        n = IntegerNat._conv(n)
        if n._is_zero():
            raise ValueError("n must be a positive integer")
        if not n.is_odd():
            raise ValueError("n must be odd for the Jacobi symbol")

        # A negative a can only be a (public) Python int
        negate = 0
        if isinstance(a, int) and a < 0:
            a, negate = -a, 1
        a = IntegerNat._conv(a)

        result = IntegerNat._make(64)
        _check(_lib.nat_jacobi(result._p.get(), a._p.get(), n._p.get(), negate), "nat_jacobi")
        return int(result) - 1

    @staticmethod
    def _mult_modulo_bytes(term1: IntLike, term2: IntLike, modulus: IntLike) -> bytes:
        if isinstance(modulus, int) and modulus < 0:
            raise ValueError("Modulus must be positive")
        modulus = IntegerNat._conv(modulus)
        if modulus._is_zero():
            raise ZeroDivisionError("Modulus cannot be zero")
        if not modulus.is_odd():
            raise ValueError("Odd modulus is required")

        # Python ints are public and may be negative
        if isinstance(term1, int):
            term1 = term1 % int(modulus)
        if isinstance(term2, int):
            term2 = term2 % int(modulus)
        term1 = IntegerNat._conv(term1)
        term2 = IntegerNat._conv(term2)

        result = IntegerNat._make(modulus._bits)
        _check(
            _lib.nat_mulmod(result._p.get(), term1._p.get(), term2._p.get(), modulus._p.get()), "nat_mulmod"
        )
        return result.to_bytes(modulus.size_in_bytes())

    # Primality tests (the candidate is usually a secret prime)

    def _miller_rabin(self, base: IntLike) -> bool:
        """One round of Miller-Rabin; self must be odd and at least 5,
        and base in [2, self-2]."""
        base = self._conv(base)
        result = IntegerNat._make(64)
        _check(_lib.nat_miller_rabin(result._p.get(), self._p.get(), base._p.get()), "nat_miller_rabin")
        return not result._is_zero()

    def _lucas(self, d: int) -> bool:
        """Lucas test with P=1 and Q=(1-D)/4; self must be odd and at least 3.
        D is a public Python int."""
        result = IntegerNat._make(64)
        _check(_lib.nat_lucas(result._p.get(), self._p.get(), c_ulonglong(abs(d)), int(d < 0)), "nat_lucas")
        return not result._is_zero()
