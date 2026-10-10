#
#  SelfTest/Math/test_nat.py: Self-test for the constant-time natural numbers
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Differential tests of Crypto.Math._IntegerNat against Python ints.

Each operand gets a random bound (``_min_bits``), so that the C code is
exercised with numbers of different sizes, and with values that do not
fill the words they are stored into.
"""

import math
import random

import pytest

try:
    from Crypto.Math import _IntegerNat
    from Crypto.Math._IntegerNat import IntegerNat

    _nat_error = None
except (ImportError, OSError) as e:
    _nat_error = e

pytestmark = pytest.mark.skipif(_nat_error is not None, reason="Nat library not available (%s)" % _nat_error)

# Run every test with each build of the C library available on this machine
_implementations = []
if _nat_error is None:
    _implementations.append(pytest.param(_IntegerNat._portable_lib, id="portable"))
    if _IntegerNat._bmi2_adx_lib is not None:
        _implementations.append(pytest.param(_IntegerNat._bmi2_adx_lib, id="bmi2_adx"))


@pytest.fixture(autouse=True, params=_implementations or [pytest.param(None, id="unavailable")])
def nat_implementation(request, monkeypatch):
    if request.param is not None:
        monkeypatch.setattr(_IntegerNat, "_lib", request.param)


def _edge_values(words):
    """Values at the borders of 64-bit words"""
    result = [0, 1, 2]
    for w in range(1, words + 1):
        top = 1 << (64 * w)
        result += [top - 1, top - 2, top >> 1, (top >> 1) - 1, (top >> 1) + 1]
    return result


class _Gen:
    def __init__(self, seed, max_bits=400):
        self.rnd = random.Random(seed)
        self.max_bits = max_bits
        self.edges = _edge_values((max_bits + 63) // 64)

    def value(self):
        kind = self.rnd.random()
        if kind < 0.25:
            return self.rnd.choice(self.edges)
        return self.rnd.getrandbits(self.rnd.randint(1, self.max_bits))

    def nat(self, value):
        extra = self.rnd.choice((0, 0, 1, 63, 64, 65, 200))
        return IntegerNat(value, _min_bits=value.bit_length() + extra)


def _jacobi(a, n):
    a %= n
    t = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                t = -t
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            t = -t
        a %= n
    return t if n == 1 else 0


def _miller_rabin(n, base):
    d, a = n - 1, 0
    while d % 2 == 0:
        d //= 2
        a += 1
    z = pow(base, d, n)
    if z in (1, n - 1):
        return True
    for _ in range(a - 1):
        z = z * z % n
        if z == n - 1:
            return True
    return False


def _lucas(n, d):
    """U_{n+1} == 0 mod n, for P=1 and Q=(1-D)/4"""
    k = n + 1
    u, v = 0, 2
    inv2 = pow(2, -1, n)
    for i in range(k.bit_length() - 1, -1, -1):
        u, v = u * v % n, (v * v + d * u * u) * inv2 % n
        if (k >> i) & 1:
            u, v = (u + v) * inv2 % n, (v + d * u) * inv2 % n
    return u == 0


class TestNatArithmetic:
    def test_basic(self):
        gen = _Gen(1)
        for _ in range(300):
            a, b = gen.value(), gen.value()
            x, y = gen.nat(a), gen.nat(b)

            assert int(x) == a
            assert x.size_in_bits() == max(1, a.bit_length())
            assert (x == y) == (a == b)
            assert (x < y) == (a < b)
            assert (x > y) == (a > b)
            assert x + y == a + b
            assert x * y == a * b
            assert x & y == a & b
            assert x | y == a | b
            if a >= b:
                assert x - y == a - b
            else:
                with pytest.raises(ValueError):
                    x - y
            if b:
                assert x // y == a // b
                assert x % y == a % b
            k = gen.rnd.randrange(300)
            assert x << k == a << k
            assert x >> k == a >> k
            assert x.get_bit(k) == bool((a >> k) & 1)
            c = gen.value()
            z = gen.nat(c)
            z.multiply_accumulate(x, y)
            assert z == c + a * b

    def test_bytes(self):
        gen = _Gen(2)
        for _ in range(200):
            a = gen.value()
            x = gen.nat(a)
            length = max(1, (a.bit_length() + 7) // 8) + gen.rnd.randint(0, 9)
            for order in ("big", "little"):
                encoded = x.to_bytes(length, order)
                assert encoded == a.to_bytes(length, order)
                assert IntegerNat.from_bytes(encoded, order) == a
            if a.bit_length() > 8:
                with pytest.raises(ValueError):
                    x.to_bytes((a.bit_length() - 1) // 8)

    def test_number_theory(self):
        gen = _Gen(3)
        for _ in range(200):
            a, b = gen.value(), gen.value()
            x, y = gen.nat(a), gen.nat(b)
            assert x.gcd(y) == math.gcd(a, b)
            assert x.sqrt() == math.isqrt(a)
            assert x.is_perfect_square() == (math.isqrt(a) ** 2 == a)
            n = b | 1
            assert IntegerNat.jacobi_symbol(x, n) == _jacobi(a, n)
            assert IntegerNat.jacobi_symbol(-(a % 1000) - 1, n) == _jacobi(-(a % 1000) - 1, n)
            d = gen.rnd.randrange(1, 2**32)
            if a % d == 0:
                with pytest.raises(ValueError):
                    x.fail_if_divisible_by(d)
            else:
                x.fail_if_divisible_by(d)

    def test_modular(self):
        gen = _Gen(4)
        for _ in range(150):
            a, e, m = gen.value(), gen.value(), gen.value() or 1
            x, ex = gen.nat(a), gen.nat(e)
            for mod in (m, m | 1, (m & ~1) or 2):
                mx = gen.nat(mod)
                assert pow(x, ex, mx) == pow(a, e, mod)
                try:
                    expected = pow(a, -1, mod)
                except ValueError:
                    with pytest.raises(ValueError):
                        x.inverse(mx)
                else:
                    assert x.inverse(mx) == expected
                ar, br = a % mod, gen.value() % mod
                assert gen.nat(ar)._sub_mod(gen.nat(br), mx) == (ar - br) % mod
            if m & 1:
                assert IntegerNat._mult_modulo_bytes(x, ex, m) == (a * e % m).to_bytes(
                    max(1, (m.bit_length() + 7) // 8), "big"
                )

    @pytest.mark.slow
    def test_large_modexp(self):
        gen = _Gen(5, max_bits=4096)
        for bits in (1024, 2048, 3072, 4096):
            m = gen.rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
            a = gen.rnd.getrandbits(bits) % m
            e = gen.rnd.getrandbits(bits)
            assert pow(IntegerNat(a), IntegerNat(e), IntegerNat(m)) == pow(a, e, m)
            if math.gcd(a, m) == 1:
                assert IntegerNat(a).inverse(m) == pow(a, -1, m)


class TestNatPrimality:
    _candidates = [
        5, 7, 9, 15, 21, 25, 561, 1105, 3215031751, 2**61 - 1, 2**89 - 1, 2**127 - 1,
        (2**61 - 1) * (2**89 - 1), 2**64 + 13, 2**128 + 51,
    ]  # fmt: skip

    def test_miller_rabin(self):
        rnd = random.Random(6)
        cands = self._candidates + [rnd.getrandbits(rnd.randint(8, 300)) | 1 for _ in range(60)]
        for n in cands:
            if n < 5:
                continue
            x = IntegerNat(n, _min_bits=n.bit_length() + rnd.choice((0, 64)))
            for _ in range(3):
                base = rnd.randrange(2, n - 1)
                assert x._miller_rabin(base) == _miller_rabin(n, base), (n, base)

    def test_lucas(self):
        rnd = random.Random(7)
        cands = self._candidates + [rnd.getrandbits(rnd.randint(8, 300)) | 1 for _ in range(60)]
        for n in cands:
            x = IntegerNat(n, _min_bits=n.bit_length() + rnd.choice((0, 64)))
            for d in (5, -7, 9, -11, 13, -15, 17):
                assert x._lucas(d) == _lucas(n, d), (n, d)
