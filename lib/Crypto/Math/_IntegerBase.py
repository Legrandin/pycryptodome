# SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

# mypy: disable-error-code="empty-body"

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, Union

from Crypto import Random

if TYPE_CHECKING:
    # Crypto.Math.Numbers.Integer is statically typed as IntegerBase,
    # so type checkers must consider it instantiable.
    _F = TypeVar("_F")

    def abstractmethod(func: _F) -> _F:
        return func
else:
    from abc import abstractmethod

RandFunc = Callable[[int], bytes]


class IntegerBase(ABC):
    if TYPE_CHECKING:

        def __init__(self, value: Union[IntegerBase, int]) -> None: ...

    # Conversions
    @abstractmethod
    def __int__(self) -> int:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def to_bytes(self, block_size: Optional[int] = 0, byteorder: str = "big") -> bytes:
        pass

    @staticmethod
    @abstractmethod
    def from_bytes(byte_string: Union[bytes, bytearray, memoryview], byteorder: str = "big") -> IntegerBase:
        pass

    # Relations
    @abstractmethod
    def __eq__(self, term: object) -> bool:
        pass

    @abstractmethod
    def __ne__(self, term: object) -> bool:
        pass

    @abstractmethod
    def __lt__(self, term: Union[IntegerBase, int]) -> bool:
        pass

    @abstractmethod
    def __le__(self, term: Union[IntegerBase, int]) -> bool:
        pass

    @abstractmethod
    def __gt__(self, term: Union[IntegerBase, int]) -> bool:
        pass

    @abstractmethod
    def __ge__(self, term: Union[IntegerBase, int]) -> bool:
        pass

    @abstractmethod
    def __bool__(self):
        pass

    @abstractmethod
    def is_negative(self) -> bool:
        pass

    # Arithmetic operations
    @abstractmethod
    def __add__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __sub__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __mul__(self, factor: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __floordiv__(self, divisor: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __mod__(self, divisor: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def inplace_pow(
        self, exponent: Union[IntegerBase, int], modulus: Optional[Union[IntegerBase, int]] = None
    ) -> IntegerBase:
        pass

    @abstractmethod
    def __pow__(
        self, exponent: Union[IntegerBase, int], modulus: Optional[Union[IntegerBase, int]] = None
    ) -> IntegerBase:
        pass

    @abstractmethod
    def __abs__(self) -> IntegerBase:
        pass

    @abstractmethod
    def sqrt(self, modulus: Optional[Union[IntegerBase, int]] = None) -> IntegerBase:
        pass

    @abstractmethod
    def __iadd__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __isub__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __imul__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __imod__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    # Boolean/bit operations
    @abstractmethod
    def __and__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __or__(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __rshift__(self, pos: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __irshift__(self, pos: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __lshift__(self, pos: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def __ilshift__(self, pos: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def get_bit(self, n: int) -> bool:
        pass

    # Extra
    @abstractmethod
    def is_odd(self) -> bool:
        pass

    @abstractmethod
    def is_even(self) -> bool:
        pass

    @abstractmethod
    def size_in_bits(self) -> int:
        pass

    @abstractmethod
    def size_in_bytes(self) -> int:
        pass

    @abstractmethod
    def is_perfect_square(self) -> bool:
        pass

    @abstractmethod
    def fail_if_divisible_by(self, small_prime: Union[IntegerBase, int]) -> None:
        pass

    @abstractmethod
    def multiply_accumulate(self, a: Union[IntegerBase, int], b: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def set(self, source: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def inplace_inverse(self, modulus: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def inverse(self, modulus: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def gcd(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @abstractmethod
    def lcm(self, term: Union[IntegerBase, int]) -> IntegerBase:
        pass

    @staticmethod
    @abstractmethod
    def jacobi_symbol(a: Union[IntegerBase, int], n: Union[IntegerBase, int]) -> int:
        pass

    @staticmethod
    def _tonelli_shanks(n: Any, p: Any) -> Any:
        """Tonelli-shanks algorithm for computing the square root
        of n modulo a prime p.

        n must be in the range [0..p-1].
        p must be at least even.

        The return value r is the square root of modulo p. If non-zero,
        another solution will also exist (p-r).

        Note we cannot assume that p is really a prime: if it's not,
        we can either raise an exception or return the correct value.
        """

        # See https://rosettacode.org/wiki/Tonelli-Shanks_algorithm

        if n in (0, 1):
            return n

        if p % 4 == 3:
            root = pow(n, (p + 1) // 4, p)
            if pow(root, 2, p) != n:
                raise ValueError("Cannot compute square root")
            return root

        s = 1
        q = (p - 1) // 2
        while not (q & 1):
            s += 1
            q >>= 1

        z = n.__class__(2)
        while True:
            euler = pow(z, (p - 1) // 2, p)
            if euler == 1:
                z += 1
                continue
            if euler == p - 1:
                break
            # Most probably p is not a prime
            raise ValueError("Cannot compute square root")

        m = s
        c = pow(z, q, p)
        t = pow(n, q, p)
        r = pow(n, (q + 1) // 2, p)

        while t != 1:
            for i in range(m):
                if pow(t, 2**i, p) == 1:
                    break
            if i == m:
                raise ValueError("Cannot compute square root of %d mod %d" % (n, p))
            b = pow(c, 2 ** (m - i - 1), p)
            m = i
            c = b**2 % p
            t = (t * b**2) % p
            r = (r * b) % p

        if pow(r, 2, p) != n:
            raise ValueError("Cannot compute square root")

        return r

    @classmethod
    def random(
        cls,
        *,
        exact_bits: Optional[int] = None,
        max_bits: Optional[int] = None,
        randfunc: Optional[RandFunc] = None,
    ) -> IntegerBase:
        """Generate a random natural integer of a certain size.

        :Keywords:
          exact_bits : positive integer
            The length in bits of the resulting random Integer number.
            The number is guaranteed to fulfil the relation:

                2^bits > result >= 2^(bits - 1)

          max_bits : positive integer
            The maximum length in bits of the resulting random Integer number.
            The number is guaranteed to fulfil the relation:

                2^bits > result >=0

          randfunc : callable
            A function that returns a random byte string. The length of the
            byte string is passed as parameter. Optional.
            If not provided (or ``None``), randomness is read from the system RNG.

        :Return: a Integer object
        """

        if randfunc is None:
            randfunc = Random.new().read

        if exact_bits is not None:
            if max_bits is not None:
                raise ValueError("'exact_bits' and 'max_bits' are mutually exclusive")
            bits = exact_bits
        elif max_bits is not None:
            bits = max_bits
        else:
            raise ValueError("Either 'exact_bits' or 'max_bits' must be specified")

        bytes_needed = ((bits - 1) // 8) + 1
        significant_bits_msb = 8 - (bytes_needed * 8 - bits)
        msb = randfunc(1)[0]
        if exact_bits is not None:
            msb |= 1 << (significant_bits_msb - 1)
        msb &= (1 << significant_bits_msb) - 1

        return cls.from_bytes(bytes([msb]) + randfunc(bytes_needed - 1))

    @classmethod
    def random_range(
        cls,
        *,
        min_inclusive: Optional[Union[IntegerBase, int]] = None,
        max_inclusive: Optional[Union[IntegerBase, int]] = None,
        max_exclusive: Optional[Union[IntegerBase, int]] = None,
        randfunc: Optional[RandFunc] = None,
    ) -> IntegerBase:
        """Generate a random integer within a given internal.

        :Keywords:
          min_inclusive : integer
            The lower end of the interval (inclusive).
          max_inclusive : integer
            The higher end of the interval (inclusive).
          max_exclusive : integer
            The higher end of the interval (exclusive).
          randfunc : callable
            A function that returns a random byte string. The length of the
            byte string is passed as parameter. Optional.
            If not provided (or ``None``), randomness is read from the system RNG.
        :Returns:
            An Integer randomly taken in the given interval.
        """

        if max_inclusive is not None and max_exclusive is not None:
            raise ValueError("max_inclusive and max_exclusive cannot be both specified")
        if max_exclusive is not None:
            max_inclusive = max_exclusive - 1
        if min_inclusive is None or max_inclusive is None:
            raise ValueError("Missing keyword to identify the interval")

        if randfunc is None:
            randfunc = Random.new().read

        norm_maximum = cls(max_inclusive) - min_inclusive
        bits_needed = norm_maximum.size_in_bits()

        while True:
            norm_candidate = cls.random(max_bits=bits_needed, randfunc=randfunc)
            if norm_candidate <= norm_maximum:
                return norm_candidate + min_inclusive

    @staticmethod
    @abstractmethod
    def _mult_modulo_bytes(
        term1: Union[IntegerBase, int], term2: Union[IntegerBase, int], modulus: Union[IntegerBase, int]
    ) -> bytes:
        """Multiply two integers, take the modulo, and encode as big endian.
        This specialized method is used for RSA decryption.

        Args:
          term1 : integer
            The first term of the multiplication, non-negative.
          term2 : integer
            The second term of the multiplication, non-negative.
          modulus: integer
            The modulus, a positive odd number.
        :Returns:
            A byte string, with the result of the modular multiplication
            encoded in big endian mode.
            It is as long as the modulus would be, with zero padding
            on the left if needed.
        """
