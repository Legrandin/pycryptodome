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

from Crypto.Math.Numbers import Integer
from Crypto import Random

COMPOSITE = 0
PROBABLY_PRIME = 1


def miller_rabin_test(candidate, iterations, randfunc=None):
    """Perform a Miller-Rabin primality test on an integer.

    The test is specified in Section C.3.1 of `FIPS PUB 186-4`__.

    :Parameters:
      :candidate: integer
        The number to test for primality.
      :iterations: integer
        The maximum number of iterations to perform before
        declaring a candidate a probable prime.
      :randfunc: callable
        An RNG function where bases are taken from.

    :Returns:
      ``Primality.COMPOSITE`` or ``Primality.PROBABLY_PRIME``.

    .. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if not isinstance(candidate, Integer):
        candidate = Integer(candidate)

    if candidate.is_even():
        return COMPOSITE

    one = Integer(1)
    minus_one = Integer(candidate - 1)

    if randfunc is None:
        randfunc = Random.new().read

    # Step 1 and 2
    m = Integer(minus_one)
    a = 0
    while m.is_even():
        m >>= 1
        a += 1

    # Skip step 3

    # Step 4
    for i in xrange(iterations):

        # Step 4.1-2
        base = 1
        while base in (one, minus_one):
            base = Integer.random_range(2, candidate - 2)

        # Step 4.3-4.4
        z = pow(base, m, candidate)
        if z in (one, minus_one):
            continue

        # Step 4.5
        for j in xrange(1, a):
            z = pow(z, 2, candidate)
            if z == minus_one:
                break
            if z == one:
                return COMPOSITE
        else:
            return COMPOSITE

    # Step 5
    return PROBABLY_PRIME


def lucas_test(candidate):
    """Perform a Lucas primality test on an integer.

    The test is specified in Section C.3.3 of `FIPS PUB 186-4`__.

    :Parameters:
      :candidate: integer
        The number to test for primality.

    :Returns:
      ``Primality.COMPOSITE`` or ``Primality.PROBABLY_PRIME``.

    .. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if not isinstance(candidate, Integer):
        candidate = Integer(candidate)

    # Step 1
    if candidate.is_even() or candidate.is_perfect_square():
        return COMPOSITE

    # Step 2
    def alternate(modulus):
        sgn = 1
        value = 5
        for x in xrange(10):
            yield sgn * value
            sgn, value = -sgn, value + 2

    for D in alternate(int(candidate)):
        js = Integer.jacobi_symbol(D, candidate)
        if js == 0:
            return COMPOSITE
        if js == -1:
            break
    else:
        return COMPOSITE
    # Found D. P=1 and Q=(1-D)/4 (note that Q is guaranteed to be an integer)

    # Step 3
    # This is \delta(n) = n - jacobi(D/n)
    K = candidate + 1
    # Step 4
    r = K.size_in_bits() - 1
    # Step 5
    # U_1=1 and V_1=P
    U_i = Integer(1)
    V_i = Integer(1)
    U_temp = Integer(0)
    V_temp = Integer(0)
    # Step 6
    for i in xrange(r - 1, -1, -1):
        # Square
        # U_temp = U_i * V_i % candidate
        U_temp.set(U_i)
        U_temp *= V_i
        U_temp %= candidate
        # V_temp = (((V_i ** 2 + (U_i ** 2 * D)) * K) >> 1) % candidate
        V_temp.set(U_i)
        V_temp *= U_i
        V_temp *= D
        V_temp.multiply_accumulate(V_i, V_i)
        if V_temp.is_odd():
            V_temp += candidate
        V_temp >>= 1
        V_temp %= candidate
        # Multiply
        if K.get_bit(i):
            # U_i = (((U_temp + V_temp) * K) >> 1) % candidate
            U_i.set(U_temp)
            U_i += V_temp
            if U_i.is_odd():
                U_i += candidate
            U_i >>= 1
            U_i %= candidate
            # V_i = (((V_temp + U_temp * D) * K) >> 1) % candidate
            V_i.set(V_temp)
            V_i.multiply_accumulate(U_temp, D)
            if V_i.is_odd():
                V_i += candidate
            V_i >>= 1
            V_i %= candidate
        else:
            U_i.set(U_temp)
            V_i.set(V_temp)
    # Step 7
    if U_i == 0:
        return PROBABLY_PRIME
    return COMPOSITE


def generate_probable_prime(bit_size, randfunc=None):
    """Generate a random probable prime.

    The prime will not have any specific properties
    (E.g. it will not be a _strong prime_).

    Random numbers are evaluated for primality until one
    passes all tests, consisting of a certain number of
    Miller-Rabin tests with random bases followed by
    a single Lucas test.

    The number of Miller-Rabin iterations is chosen such that
    the probability that the output number is a non-prime is
    less than 1E-30 (roughly 2**{-100}).

    This approach is compliant to `FIPS PUB 186-4`__.

    :Parameters:
      :bit_size:
        The desired size in bits of the probable prime.
        It must be at least 160.
      :randfunc: callable
        An RNG function where candidate primes are taken from.

    :Return:
        A probable prime in the range 2**bit_size > p > 2**(bit_size-1).

    .. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if bit_size < 160:
        raise ValueError("Prime number is not big enough.")

    if randfunc is None:
        randfunc = Random.new().read

    # These are the number of Miller-Rabin iterations s.t. p(k, t) < 1E-30,
    # with p(k, t) being the probability that a randomly chosen k-bit number
    # is composite but still survives t MR iterations.
    mr_ranges = ((220, 30), (280, 20), (390, 15), (512, 10),
                 (620, 7), (740, 6), (890, 5), (1200, 4),
                 (1700, 3), (3700, 2))
    try:
        mr_iterations = list(filter(lambda x: bit_size < x[0],
                                    mr_ranges))[0][1]
    except IndexError:
        mr_iterations = 1

    from Crypto.Util.number import sieve_base
    sieve_base = sieve_base[:100]

    while True:

        small_divisor_found = True
        while small_divisor_found:
            candidate = Integer.random(exact_bits=bit_size, randfunc=randfunc) | 1
            for p in sieve_base:
                if candidate.is_divisible_by_ulong(p):
                    break
            else:
                small_divisor_found = False

        if miller_rabin_test(candidate, mr_iterations, randfunc=randfunc) == COMPOSITE:
            continue
        if lucas_test(candidate) == PROBABLY_PRIME:
            break

    return candidate
