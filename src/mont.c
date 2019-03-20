/* ===================================================================
 *
 * Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include <assert.h>

#include "common.h"
#include "endianess.h"
#include "multiply.h"
#include "modexp_utils.h"
#include "mont.h"

#if SYS_BITS == 32
#include "multiply_32.c"
#else
#if SYS_BITS == 64
#include "multiply_64.c"
#else
#error You must define the macro SYS_BITS
#endif
#endif

#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#endif

#if defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#endif

static inline unsigned is_odd(uint64_t x)
{
    return 1 == (x & 1);
}

static inline unsigned is_even(uint64_t x)
{
    return !is_odd(x);
}

/**
 * Compute the inverse modulo 2⁶⁴ of a 64-bit odd integer.
 *
 * See https://crypto.stackexchange.com/questions/47493/how-to-determine-the-multiplicative-inverse-modulo-64-or-other-power-of-two
 */
STATIC uint64_t inverse64(uint64_t a)
{
    uint64_t x;

    assert(1 & a);
    x = ((a << 1 ^ a) & 4) << 1 ^ a;
    x += x - a*x*x;
    x += x - a*x*x;
    x += x - a*x*x;
    x += x - a*x*x;
    assert((x*a & 0xFFFFFFFFFFFFFFFFULL) == 1);

    return x;
}

/**
 * Check if a multi-word integer x is greater than or equal to y.
 *
 * @param x     The first term
 * @param y     The second term
 * @param nw    The number of words that make up x and y
 * @return      1 if x>=y, 0 if x<y
 */
STATIC int ge(const uint64_t *x, const uint64_t *y, size_t nw)
{
    unsigned mask = (unsigned)-1;
    unsigned result = 0;
    size_t i, j;

    i = nw - 1;
    for (j=0; j<nw; j++, i--) {
        unsigned greater, lower;

        greater = x[i] > y[i];
        lower = x[i] < y[i];
        result |= mask & (greater | (lower << 1));
        mask &= (greater ^ lower) - 1;
    }

    return result<2;
}

/*
 * Subtract a multi-word integer b from a.
 *
 * @param out   The location where the multi-word result is stored
 * @param a     Number to subtract from
 * @param b     Number to subtract
 * @param nw    The number of words of both a and b
 * @result      0 if there is no borrow, 1 otherwise
 */
STATIC unsigned sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw)
{
    size_t i;
    unsigned borrow1 , borrow2;

    borrow2 = 0;
    for (i=0; i<nw; i++) {
        borrow1 = b[i] > a[i];
        out[i] = a[i] - b[i];

        borrow1 |= borrow2 > out[i];
        out[i] -= borrow2;

        borrow2 = borrow1;
    }

    return borrow2;
}

/*
 * Compute R² mod N, where R is the smallest power of 2⁶⁴ larger than N.
 *
 * @param r2_mod_n  The location where the result is stored at
 * @param n         The modulus N
 * @param nw        The number of 64-bit words of both r2_mod_n and n
 */
STATIC void rsquare(uint64_t *r2_mod_n, uint64_t *n, size_t nw)
{
    size_t i;
    size_t R_bits;

    memset(r2_mod_n, 0, sizeof(uint64_t)*nw);

    /**
     * Start with R2=1, double 2*bitlen(R) times,
     * and reduce it as soon as it exceeds n
     */
    r2_mod_n[0] = 1;
    R_bits = nw * sizeof(uint64_t) * 8;
    for (i=0; i<R_bits*2; i++) {
        unsigned overflow;
        size_t j;
        
        /** Double, by shifting left by one bit **/
        overflow = (unsigned)(r2_mod_n[nw-1] >> 63);
        for (j=nw-1; j>0; j--) {
            r2_mod_n[j] = (r2_mod_n[j] << 1) + (r2_mod_n[j-1] >> 63);
        }
        /** Fill-in with zeroes **/
        r2_mod_n[0] <<= 1;
        
        /** Subtract n if the result exceeds it **/
        while (overflow || ge(r2_mod_n, n, nw)) {
            sub(r2_mod_n, r2_mod_n, n, nw);
            overflow = 0;
        }
    }
}

/*
 * Multiply a multi-word integer a by a 64-bit scalar k and
 * then add the result to the multi-word integer t.
 *
 * @param t     The multi-word integer accumulator
 * @param tw    The number of words of t
 * @param a     The multi-word integer to multiply with the scalar
 * @param aw    The number of words of a
 * @param k     The 64-bit scalar multiplier
 */
STATIC void addmul(uint64_t *t, size_t tw, const uint64_t *a, size_t aw, uint64_t k)
{
    size_t i;
    uint64_t carry;

    carry = 0;
    for (i=0; i<aw; i++) {
        uint64_t prod_lo, prod_hi;

        DP_MULT(a[i], k, prod_lo, prod_hi);
    
        prod_lo += carry;
        prod_hi += prod_lo < carry;

        t[i] += prod_lo;
        prod_hi += t[i] < prod_lo;

        carry = prod_hi;
    }

    for (; carry; i++) {
        t[i] += carry;
        carry = t[i] < carry;
    }

    assert(i <= tw);
}

/**
 * Multiply two multi-word integers.
 *
 * @param t     The location where the result is stored. It is twice as big as
 *              either a or b (it is an array of  2*nw words).
 * @param a     The first term, array of nw words.
 * @param b     The second term, array of nw words.
 * @param nw    The number of words of both a and b.
 *
 */
STATIC void product(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t nw)
{
    size_t i;

    memset(t, 0, 2*sizeof(uint64_t)*nw);
    
    for (i=0; i<(nw ^ (nw & 1)); i+=2) {
        addmul128(&t[i], a, b[i], b[i+1], nw);
    }

    if (is_odd(nw)) {
        addmul(&t[nw-1], nw+2, a, nw, b[nw-1]);
    }
}

/*
 * Select a number out of two, in constant time.
 *
 * @param out   The location where the multi-word result is stored
 * @param a     The first choice, selected if cond is true (non-zero)
 * @param b     The second choice, selected if cond is false (zero)
 * @param cond  The flag that drives the selection
 * @param words The number of words of a, b, and out
 * @return      0 for success, the appropriate code otherwise.
 */
STATIC int mont_select(uint64_t *out, const uint64_t *a, const uint64_t *b, unsigned cond, size_t words)
{
    uint64_t mask;
#if defined(USE_SSE2)
    unsigned pairs, i;
    __m128i r0, r1, r2, r3, r4, r5;

    pairs = (unsigned)words / 2;
    mask = (uint64_t)((cond != 0) - 1); /* 0 for a, 1s for b */
   
    r0 = _mm_set1_epi64((__m64)mask);
    for (i=0; i<pairs; i++, a+=2, b+=2, out+=2) {
        r1 = _mm_loadu_si128((__m128i const*)b);
        r2 = _mm_loadu_si128((__m128i const*)a);
        r3 = _mm_and_si128(r0, r1);
        r4 = _mm_andnot_si128(r0, r2);
        r5 = _mm_or_si128(r3, r4);
        _mm_storeu_si128((__m128i*)out, r5);
    }

    if (words & 1) {
        *out = (*b & mask) ^ (*a & ~mask);
    }
#else
    unsigned i;

    mask = (uint64_t)((cond != 0) - 1);
    for (i=0; i<words; i++) {
        *out++ = (*b++ & mask) ^ (*a++ & ~mask);
    }
#endif

    return 0;
}

/*
 * Add two multi-word numbers with modulo arithmetic.
 *
 * @param out       The locaton where the multi-word result (nw words) is stored
 * @param a         The first term (nw words)
 * @param b         The second term (nw words)
 * @param modulus   The modulus (nw words)
 * @param tmp1      A temporary area (nw words)
 * @param tmp2      A temporary area (nw words)
 * @param nw        The number of 64-bit words in all parameters
 */
void add_mod(uint64_t* out, const uint64_t* a, const uint64_t* b, const uint64_t *modulus, uint64_t *tmp1, uint64_t *tmp2, size_t nw)
{
    unsigned i;
    unsigned carry, borrow1, borrow2;

    /*
     * Compute sum in tmp1[], and subtract modulus[]
     * from tmp1[] into tmp2[].
     */
    borrow2 = 0;
    for (i=0, carry=0; i<nw; i++) {
        tmp1[i] = a[i] + carry;
        carry = tmp1[i] < carry;
        tmp1[i] += b[i];
        carry += tmp1[i] < b[i];

        borrow1 = modulus[i] > tmp1[i];
        tmp2[i] = tmp1[i] - modulus[i];
        borrow1 |= borrow2 > tmp2[i];
        tmp2[i] -= borrow2;
        borrow2 = borrow1;
    }

    /*
     * If there is no borrow or if there is carry,
     * tmp1[] is larger than modulus, so we must return tmp2[].
     */
    mont_select(out, tmp2, tmp1, carry | (borrow2 ^ 1), nw);
}

/*
 * Montgomery modular multiplication, that is a*b*R mod N.
 *
 * @param out   The location where the result is stored
 * @param a     The first term (already in Montgomery form, a*R mod N)
 * @param b     The second term (already in Montgomery form, b*R mod N)
 * @param n     The modulus (in normal form), such that R>N
 * @param m0    Least-significant word of the opposite of the inverse of n modulo R, that is, -n[0]⁻¹ mod R
 * @param t     Temporary, internal result; it must have been created with mont_number(&p,SCRATCHPAD_NR,ctx).
 * @param nw    Number of words making up the 3 integers: out, a, and b.
 *              It also defines R as 2^(64*nw).
 *
 * Useful read: https://alicebob.cryptoland.net/understanding-the-montgomery-reduction-algorithm/
 */
#if SCRATCHPAD_NR < 4
#error Scratchpad is too small
#endif
STATIC void mont_mult_generic(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw)
{
    size_t i;
    uint64_t *t2;
    unsigned cond;

    t2 = &t[2*nw+1];    /** Point to last nw words **/

    if (a == b) {
        square_w(t, a, nw);
    } else {
        product(t, a, b, nw);
    }

    t[2*nw] = 0; /** MSW **/

    /** Clear lower words (two at a time) **/
    for (i=0; i<(nw ^ (nw & 1)); i+=2) {
        uint64_t k0, k1, ti1, prod_lo, prod_hi;

        /** Multiplier for n that will make t[i+0] go 0 **/
        k0 = t[i] * m0;
        
        /** Simulate Muladd for digit 0 **/
        DP_MULT(k0, n[0], prod_lo, prod_hi);
        prod_lo += t[i];
        prod_hi += prod_lo < t[i];

        /** Expected digit 1 **/
        ti1 = t[i+1] + n[1]*k0 + prod_hi;
        
        /** Multiplier for n that will make t[i+1] go 0 **/
        k1 = ti1 * m0;
        
        addmul128(&t[i], n, k0, k1, nw);
    }

    /** One left for odd number of words **/
    if (is_odd(nw)) {
        addmul(&t[nw-1], nw+2, n, nw, t[nw-1]*m0);
    }
    
    assert(t[2*nw] <= 1); /** MSW **/

    /** t[0..nw-1] == 0 **/
    
    /** Divide by R and possibly subtract n **/
    sub(t2, &t[nw], n, nw);
    cond = (unsigned)(t[2*nw] | (uint64_t)ge(&t[nw], n, nw));
    mont_select(out, t2, &t[nw], cond, (unsigned)nw);
}

STATIC void mont_mult_p256(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw)
{
    unsigned i;
    uint64_t *t2;
    unsigned cond;
#define WORDS_64        4U
#define PREDIV_WORDS_64 (2*WORDS_64+1)      /** Size of the number to divide by R **/
#define WORDS_32        (WORDS_64*2)
#define PREDIV_WORDS_32 (2*PREDIV_WORDS_64)

#if SYS_BITS == 32
    uint32_t t32[18];
#endif

    assert(nw == 4);
    assert(m0 == 1);

    t2 = &t[PREDIV_WORDS_64];    /** Point to last WORDS_64 words **/

    if (a == b) {
        square_w(t, a, WORDS_64);
    } else {
        product(t, a, b, WORDS_64);
    }

    t[PREDIV_WORDS_64-1] = 0; /** MSW **/

#if SYS_BITS == 32
    for (i=0; i<PREDIV_WORDS_64; i++) {
        t32[2*i] = (uint32_t)t[i];
        t32[2*i+1] = (uint32_t)(t[i] >> 32);
    }

    for (i=0; i<WORDS_32; i++) {
        uint32_t k, carry;
        uint64_t prod, k2;
        unsigned j;

        k = t32[i];
        k2 = ((uint64_t)k<<32) - k;

        /* p[0] = 2³²-1 */
        prod = k2 + t32[i+0];
        t32[i+0] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* p[1] = 2³²-1 */
        prod = k2 + t32[i+1] + carry;
        t32[i+1] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* p[2] = 2³²-1 */
        prod = k2 + t32[i+2] + carry;
        t32[i+2] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* p[3] = 0 */
        t32[i+3] += carry;
        carry = t32[i+3] < carry;
        /* p[4] = 0 */
        t32[i+4] += carry;
        carry = t32[i+4] < carry;
        /* p[5] = 0 */
        t32[i+5] += carry;
        carry = t32[i+5] < carry;
        /* p[6] = 1 */
        t32[i+6] += carry;
        carry = t32[i+6] < carry;
        t32[i+6] += k;
        carry |= t32[i+6] < k;
        /* p[7] = 2³²-1 */
        prod = k2 + t32[i+7] + carry;
        t32[i+7] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);

        for (j=WORDS_32; carry; j++) {
            t32[i+j] += carry;
            carry = t32[i+j] < carry;
        }
    }

    for (i=0; i<PREDIV_WORDS_64; i++) {
        t[i] = ((uint64_t)t32[2*i+1]<<32) + t32[2*i];
    }

#elif SYS_BITS == 64

    for (i=0; i<WORDS_64; i++) {
        unsigned j;
        uint64_t carry, k;
        uint64_t prod_lo, prod_hi;

        k = t[i];

        /* n[0] = 2⁶⁴ - 1 */
        prod_lo = -k;
        prod_hi = k - (k!=0);
        t[i+0] += prod_lo;
        prod_hi += t[i+0] < prod_lo;
        carry = prod_hi;

        /* n[1] = 2³² - 1 */
        DP_MULT(n[1], k, prod_lo, prod_hi);
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+1] += prod_lo;
        prod_hi += t[i+1] < prod_lo;
        carry = prod_hi;

        /* n[2] = 0 */
        t[i+2] += carry;
        carry = t[i+2] < carry;

        /* n[3] = 2⁶⁴ - 2³² + 1 */
        DP_MULT(n[3], k, prod_lo, prod_hi);
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+3] += prod_lo;
        prod_hi += t[i+3] < prod_lo;
        carry = prod_hi;

        for (j=WORDS_64; carry; j++) {
            t[i+j] += carry;
            carry = t[i+j] < carry;
        }
    }
#else
#error You must define the SYS_BITS macro
#endif

    assert(t[PREDIV_WORDS_64-1] <= 1); /** MSW **/

    /** t[0..nw-1] == 0 **/

    /** Divide by R and possibly subtract n **/
    sub(t2, &t[nw], n, WORDS_64);
    cond = (unsigned)(t[PREDIV_WORDS_64-1] | (uint64_t)ge(&t[WORDS_64], n, WORDS_64));
    mont_select(out, t2, &t[WORDS_64], cond, WORDS_64);

#undef WORDS_64
#undef PREDIV_WORDS_64
#undef WORDS_32
#undef PREDIV_WORDS_32
}

STATIC void mont_mult_p384(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw)
{
    size_t i;
    uint64_t *t2;
    unsigned cond;
#define WORDS_64        6U
#define PREDIV_WORDS_64 (2*WORDS_64+1)      /** Size of the number to divide by R **/
#define WORDS_32        (WORDS_64*2)
#define PREDIV_WORDS_32 (2*PREDIV_WORDS_64)

#if SYS_BITS == 32
    uint32_t t32[PREDIV_WORDS_32];
#endif

    assert(nw == WORDS_64);
    assert(m0 == 0x0000000100000001U);

    t2 = &t[PREDIV_WORDS_64];    /** Point to last WORDS_64 words **/

    if (a == b) {
        square_w(t, a, WORDS_64);
    } else {
        product(t, a, b, WORDS_64);
    }

    t[PREDIV_WORDS_64-1] = 0; /** MSW **/

#if SYS_BITS == 32
    for (i=0; i<PREDIV_WORDS_64; i++) {
        t32[2*i] = (uint32_t)t[i];
        t32[2*i+1] = (uint32_t)(t[i] >> 32);
    }

    for (i=0; i<WORDS_32; i++) {
        uint32_t k, carry;
        uint64_t prod, k2, k3;
        unsigned j;

        k = t32[i];
        k2 = ((uint64_t)k<<32) - k;
        k3 = k2 - k;

        /* n32[0] = 2³² - 1 */
        prod = k2 + t32[i+0];
        t32[i+0] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[1] = 0 */
        prod = (uint64_t)t32[i+1] + carry;
        t32[i+1] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[2] = 0 */
        prod = (uint64_t)t32[i+2] + carry;
        t32[i+2] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[3] = 2³² - 1 */
        prod = k2 + t32[i+3] + carry;
        t32[i+3] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[4] = 2³² - 2 */
        prod = k3 + t32[i+4] + carry;
        t32[i+4] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[5] = 2³² - 1 */
        prod = k2 + t32[i+5] + carry;
        t32[i+5] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[6] = 2³² - 1 */
        prod = k2 + t32[i+6] + carry;
        t32[i+6] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[7] = 2³² - 1 */
        prod = k2 + t32[i+7] + carry;
        t32[i+7] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[8] = 2³² - 1 */
        prod = k2 + t32[i+8] + carry;
        t32[i+8] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[9] = 2³² - 1 */
        prod = k2 + t32[i+9] + carry;
        t32[i+9] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[10] = 2³² - 1 */
        prod = k2 + t32[i+10] + carry;
        t32[i+10] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);
        /* n32[11] = 2³² - 1 */
        prod = k2 + t32[i+11] + carry;
        t32[i+11] = (uint32_t)prod;
        carry = (uint32_t)(prod >> 32);

        for (j=WORDS_32; carry; j++) {
            t32[i+j] += carry;
            carry = t32[i+j] < carry;
        }
    }

    for (i=0; i<PREDIV_WORDS_64; i++) {
        t[i] = ((uint64_t)t32[2*i+1]<<32) + t32[2*i];
    }

#elif SYS_BITS == 64

    for (i=0; i<WORDS_64; i++) {
        unsigned j;
        uint64_t carry;
        uint64_t k, k2_lo, k2_hi;
        uint64_t prod_lo, prod_hi;

        k = t[i] + (t[i] << 32);
        k2_lo = -k;
        k2_hi = k - (k!=0);

        /* n[0] = 2³² - 1 */
        DP_MULT(n[0], k, prod_lo, prod_hi);
        t[i+0] += prod_lo;
        prod_hi += t[i+0] < prod_lo;
        carry = prod_hi;
        /* n[1] = 2⁶⁴ - 2³² */
        DP_MULT(n[1], k, prod_lo, prod_hi);
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+1] += prod_lo;
        prod_hi += t[i+1] < prod_lo;
        carry = prod_hi;
        /* n[2] = 2⁶⁴ - 2 */
        DP_MULT(n[2], k, prod_lo, prod_hi);
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+2] += prod_lo;
        prod_hi += t[i+2] < prod_lo;
        carry = prod_hi;
        /* n[3] = 2⁶⁴ - 1 */
        prod_lo = k2_lo;
        prod_hi = k2_hi;
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+3] += prod_lo;
        prod_hi += t[i+3] < prod_lo;
        carry = prod_hi;
        /* n[4] = 2⁶⁴ - 1 */
        prod_lo = k2_lo;
        prod_hi = k2_hi;
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+4] += prod_lo;
        prod_hi += t[i+4] < prod_lo;
        carry = prod_hi;
        /* n[5] = 2⁶⁴ - 1 */
        prod_lo = k2_lo;
        prod_hi = k2_hi;
        prod_lo += carry;
        prod_hi += prod_lo < carry;
        t[i+5] += prod_lo;
        prod_hi += t[i+5] < prod_lo;
        carry = prod_hi;

        for (j=WORDS_64; carry; j++) {
            t[i+j] += carry;
            carry = t[i+j] < carry;
        }
    }
#else
#error You must define the SYS_BITS macro
#endif

    assert(t[PREDIV_WORDS_64-1] <= 1); /** MSW **/

    /** Words t[0..WORDS_64-1] have all been set to zero **/

    /** Divide by R and possibly subtract n **/
    sub(t2, &t[WORDS_64], n, WORDS_64);
    cond = (unsigned)(t[PREDIV_WORDS_64-1] | (uint64_t)ge(&t[WORDS_64], n, WORDS_64));
    mont_select(out, t2, &t[WORDS_64], cond, WORDS_64);

#undef WORDS_64
#undef PREDIV_WORDS_64
#undef WORDS_32
#undef PREDIV_WORDS_32
}

STATIC void mont_mult_p521(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw)
{
    uint64_t *s, *tmp1, *tmp2;

    assert(nw == 9);
    assert(m0 == 1);

    /*
     * A number in the form:
     *      x*2⁵²¹ + y
     * is congruent modulo 2⁵²¹-1 to:
     *      x + y
     */

    /* This is how we use the scratchpad:
     *  1) The first 2 numbers hold the result of the multiplication,
     *     and the first number also the first term of the addition
     *  3) The third holds the second term of the addition
     *  2) The fourth and fourth number are temporaries for add()
     */

    s = t + (9*2);
    tmp1 = t + (9*3);
    tmp2 = t + (9*4);

    if (a == b) {
        square_w(t, a, 9);
    } else {
        product(t, a, b, 9);
    }

    /* t is a 1042-bit number, occupying 17 words (of the total 18); the MSW (t[16]) only has 18 bits */
    s[0] = (t[8] >> 9)  | (t[9] << 55);     t[8] &= 0x1FF;
    s[1] = (t[9] >> 9)  | (t[10] << 55);
    s[2] = (t[10] >> 9) | (t[11] << 55);
    s[3] = (t[11] >> 9) | (t[12] << 55);
    s[4] = (t[12] >> 9) | (t[13] << 55);
    s[5] = (t[13] >> 9) | (t[14] << 55);
    s[6] = (t[14] >> 9) | (t[15] << 55);
    s[7] = (t[15] >> 9) | (t[16] << 55);
    s[8] = t[16] >> 9;

    add_mod(out, t, s, n, tmp1, tmp2, nw);
}

/* ---- PUBLIC FUNCTIONS ---- */

void mont_context_free(MontContext *ctx)
{
    if (NULL == ctx)
        return;
    free(ctx->one);
    free(ctx->r2_mod_n);
    free(ctx->r_mod_n);
    free(ctx->modulus);
    free(ctx->modulus_min_2);
    free(ctx);
}

/*
 * Return how many bytes a big endian multi-word number takes in memory.
 */
size_t mont_bytes(const MontContext *ctx)
{
    if (NULL == ctx)
        return 0;
    return ctx->bytes;
}

/*
 * Allocate memory for an array of numbers in Montgomery form
 * and initialize it to 0.
 *
 * @param out   The location where the address of the newly allocated
 *              array will be placed in.
 *              The caller is responsible for deallocating the memory
 *              using free().
 * @param count How many numbers the array contains.
 * @param ctx   The Montgomery context.
 * @return      0 if successful, the relevant error code otherwise.
 *
 */
int mont_number(uint64_t **out, unsigned count, const MontContext *ctx)
{
    if (NULL == out || NULL == ctx)
        return ERR_NULL;

    *out = (uint64_t*)calloc(count * ctx->words, sizeof(uint64_t));
    if (NULL == *out)
        return ERR_MEMORY;

    return 0;
}

int mont_random_number(uint64_t **out, unsigned count, uint64_t seed, const MontContext *ctx)
{
    int res;
    unsigned i;
    uint64_t *number;

    res = mont_number(out, count, ctx);
    if (res)
        return res;

    number = *out;
    expand_seed(seed, (uint8_t*)number, count * ctx->bytes);
    for (i=0; i<count; i++, number += ctx->words) {
        number[ctx->words-1] = 0;
    }
    return 0;
}

/*
 * Transform a big endian-encoded number into Montgomery form, by performing memory allocation.
 *
 * @param out       The location where the pointer to the newly allocated memory will be put in.
 *                  The memory will contain the number encoded in Montgomery form.
 *                  The caller is responsible for deallocating the memory.
 * @param ctx       Montgomery context, as created by mont_context_init().
 * @param number    The big endian-encoded number to transform, strictly smaller than the modulus.
 * @param len       The length of the big-endian number in bytes (this may be
 *                  smaller than the output of mont_bytes(ctx)).
 * @return          0 in case of success, the relevant error code otherwise.
 */
int mont_from_bytes(uint64_t **out, const uint8_t *number, size_t len, const MontContext *ctx)
{
    uint64_t *encoded = NULL;
    uint64_t *tmp1 = NULL;
    uint64_t *scratchpad = NULL;
    int res = 0;

    if (NULL == out || NULL == ctx || NULL == number)
        return ERR_NULL;

    *out = NULL;

    /** Removing leading zeroes but avoid a zero-length string **/
    if (0 == len)
        return ERR_NOT_ENOUGH_DATA;
    while (len>1 && *number==0) {
        len--;
        number++;
    }

    if (ctx->bytes < len)
        return ERR_VALUE;

    /** The caller will deallocate this memory **/
    *out = encoded = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == encoded)
        return ERR_MEMORY;

    /** Input number, loaded in words **/
    tmp1 = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == tmp1) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    bytes_to_words(tmp1, ctx->words, number, len);

    /** Make sure number<modulus **/
    if (ge(tmp1, ctx->modulus, ctx->words)) {
        res = ERR_VALUE;
        goto cleanup;
    }

    /** Scratchpad **/
    scratchpad = (uint64_t*)calloc(SCRATCHPAD_NR, ctx->words*sizeof(uint64_t));
    if (NULL == scratchpad) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    if (ctx->modulus_type != ModulusP521)
        mont_mult_generic(encoded, tmp1, ctx->r2_mod_n, ctx->modulus, ctx->m0, scratchpad, ctx->words);
    else
        mont_copy(encoded, tmp1, ctx);
    res = 0;

cleanup:
    free(scratchpad);
    free(tmp1);
    if (res != 0) {
        free(encoded);
        *out = NULL;
    }
    return res;
}

/*
 * Transform a number from Montgomery representation to big endian-encoding.
 *
 * @param number        The location where the number will be put in, encoded
 *                      in big-endian form and with zero padding on the left.
 * @param len           Space allocate at number, at least ctx->modulus_len bytes.
 * @param ctx           The address of the Montgomery context.
 * @param mont_number   The number in Montgomery form to transform.
 * @return              0 if successful, the relevant error code otherwise.
 */
int mont_to_bytes(uint8_t *number, size_t len, const uint64_t* mont_number, const MontContext *ctx)
{
    uint64_t *tmp1 = NULL;
    uint64_t *scratchpad = NULL;
    int res;

    if (NULL == number || NULL == ctx || NULL == mont_number)
        return ERR_NULL;

    if (len < ctx->modulus_len)
        return ERR_NOT_ENOUGH_DATA;

    /** Number in normal form, but still in words **/
    tmp1 = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == tmp1)
        return ERR_MEMORY;

    /** Scratchpad **/
    scratchpad = (uint64_t*)calloc(SCRATCHPAD_NR, ctx->words*sizeof(uint64_t));
    if (NULL == scratchpad) {
        free(tmp1);
        return ERR_MEMORY;
    }

    if (ctx->modulus_type != ModulusP521)
        mont_mult_generic(tmp1, mont_number, ctx->one, ctx->modulus, ctx->m0, scratchpad, ctx->words);
    else
        mont_copy(tmp1, mont_number, ctx);
    res = words_to_bytes(number, len, tmp1, ctx->words);

    free(scratchpad);
    free(tmp1);
    return res;
}

/*
 * Add two numbers in Montgomery representation.
 *
 * @param out   The location where the result will be stored; it must have been created with mont_number(&p,1,ctx).
 * @param a     The first term.
 * @param b     The second term.
 * @param tmp   Temporary, internal result; it must have been created with mont_number(&p,SCRATCHPAD_NR,ctx).
 * @param ctx   The Montgomery context.
 * @return      0 for success, the relevant error code otherwise.
 */
int mont_add(uint64_t* out, const uint64_t* a, const uint64_t* b, uint64_t *tmp, const MontContext *ctx)
{
    if (NULL == out || NULL == a || NULL == b || NULL == tmp || NULL == ctx)
        return ERR_NULL;
    add_mod(out, a, b, ctx->modulus, tmp, tmp + ctx->words, ctx->words);
    return 0;
}

/*
 * Multiply two numbers in Montgomery representation.
 *
 * @param out   The location where the result will be stored at; it must have been created with mont_number(&p,1,ctx)
 * @param a     The first term.
 * @param b     The second term.
 * @param tmp   Temporary, internal result; it must have been created with mont_number(&p,SCRATCHPAD_NR,ctx).
 * @param ctx   The Montgomery context.
 * @return      0 for success, the relevant error code otherwise.
 */
int mont_mult(uint64_t* out, const uint64_t* a, const uint64_t *b, uint64_t *tmp, const MontContext *ctx)
{
    if (NULL == out || NULL == a || NULL == b || NULL == tmp || NULL == ctx)
        return ERR_NULL;

    switch (ctx->modulus_type) {
        case ModulusP256:
            mont_mult_p256(out, a, b, ctx->modulus, ctx->m0, tmp, ctx->words);
            break;
        case ModulusP384:
            mont_mult_p384(out, a, b, ctx->modulus, ctx->m0, tmp, ctx->words);
            break;
        case ModulusP521:
            mont_mult_p521(out, a, b, ctx->modulus, ctx->m0, tmp, ctx->words);
            break;
        case ModulusGeneric:
            mont_mult_generic(out, a, b, ctx->modulus, ctx->m0, tmp, ctx->words);
            break;
    }

    return 0;
}

/*
 * Subtract integer b from a.
 *
 * @param out   The location where the result is stored at; it must have been created with mont_number(&p,1,ctx).
 *              It can be the same as either a or b.
 * @param a     The number it will be subtracted from.
 * @param b     The number to subtract.
 * @param tmp   Temporary, internal result; it must have been created with mont_number(&p,2,ctx).
 * @param ctx   The Montgomery context.
 * @return      0 for success, the relevant error code otherwise.
 */
int mont_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, uint64_t *tmp, const MontContext *ctx)
{
    unsigned i;
    unsigned carry, borrow1 , borrow2;
    uint64_t *scratchpad;

    if (NULL == out || NULL == a || NULL == b || NULL == tmp || NULL == ctx)
        return ERR_NULL;

    scratchpad = tmp + ctx->words;

    /*
     * Compute difference in tmp[], and add modulus[]
     * to tmp[] into scratchpad[].
     */
    borrow2 = 0;
    carry = 0;
    for (i=0; i<ctx->words; i++) {
        borrow1 = b[i] > a[i];
        tmp[i] = a[i] - b[i];
        borrow1 |= borrow2 > tmp[i];
        tmp[i] -= borrow2;
        borrow2 = borrow1;

        scratchpad[i] = tmp[i] + carry;
        carry = scratchpad[i] < carry;
        scratchpad[i] += ctx->modulus[i];
        carry += scratchpad[i] < ctx->modulus[i];
    }

    /*
     * If there is no borrow, tmp[] is smaller than modulus.
     */
    mont_select(out, scratchpad, tmp, borrow2, ctx->words);

    return 0;
}

/*
 * Compute the modular inverse of an integer in Montgomery form.
 *
 * Condition: the modulus defining the Montgomery context MUST BE a non-secret prime number.
 *
 * @param out   The location where the result will be stored at; it must have
 *              been allocated with mont_number(&p, 1, ctx).
 * @param a     The number to compute the modular inverse of, already in Montgomery form.
 * @param ctx   The Montgomery context.
 * @return      0 for success, the relevant error code otherwise.
 */
int mont_inv_prime(uint64_t *out, uint64_t *a, const MontContext *ctx)
{
    unsigned idx_word;
    uint64_t bit;
    uint64_t *tmp1 = NULL;
    uint64_t *scratchpad = NULL;
    uint64_t *exponent = NULL;
    int res;

    if (NULL == out || NULL == a || NULL == ctx)
        return ERR_NULL;

    tmp1 = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == tmp1)
        return ERR_MEMORY;

    scratchpad = (uint64_t*)calloc(SCRATCHPAD_NR, ctx->words*sizeof(uint64_t));
    if (NULL == scratchpad) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    /** Exponent is guaranteed to be >0 **/
    exponent = ctx->modulus_min_2;

    /* Find most significant bit */
    idx_word = ctx->words-1;
    for (;;) {
        if (exponent[idx_word] != 0)
            break;
        if (idx_word-- == 0)
            break;
    }
    for (bit = (uint64_t)1U << 63; 0 == (exponent[idx_word] & bit); bit>>=1);

    /* Start from 1 (in Montgomery form, which is R mod N) */
    memcpy(out, ctx->r_mod_n, ctx->bytes);

    /** Left-to-right exponentiation **/
    for (;;) {
        while (bit > 0) {
            mont_mult(tmp1, out, out, scratchpad, ctx);
            if (exponent[idx_word] & bit) {
                mont_mult(out, tmp1, a, scratchpad, ctx);
            } else {
                memcpy(out, tmp1, ctx->bytes);
            }
            bit >>= 1;
        }
        if (idx_word-- == 0)
            break;
        bit = (uint64_t)1 << 63;
    }
    res = 0;

cleanup:
    free(tmp1);
    free(scratchpad);
    return res;
}

/*
 * Assign a value to a number in Montgomer form.
 *
 * @param out   The location where the result is stored at; it must have been created with mont_number(&p,1,ctx).
 * @param x     The value to set.
 * @param tmp   Temporary scratchpad with 4*nw+1 words (it can be created with mont_number(&p,5,ctx).
 *              It is ignored for x=0 and x=1.
 * @param ctx   The Montgomery context.
 * @return      0 for success, the relevant error code otherwise.
 */
int mont_set(uint64_t *out, uint64_t x, uint64_t* tmp, const MontContext *ctx)
{
    uint64_t *scratchpad;

    if (NULL == out || NULL == ctx)
        return ERR_NULL;

    if (x == 0) {
        memset(out, 0, ctx->bytes);
        return 0;
    }
    if (x == 1) {
        mont_copy(out, ctx->r_mod_n, ctx);
        return 0;
    }

    if (NULL == tmp)
        return ERR_NULL;

    memset(tmp, 0, ctx->bytes);
    tmp[0] = x;

    scratchpad = &tmp[ctx->words];

    if (ctx->modulus_type != ModulusP521)
        mont_mult_generic(out, tmp, ctx->r2_mod_n, ctx->modulus, ctx->m0, scratchpad, ctx->words);
    else
        mont_copy(out, tmp, ctx);
    return 0;
}

static int cmp_modulus(const uint8_t *mod1, size_t mod1_len, const uint8_t *mod2, size_t mod2_len)
{
    size_t diff;

    if (mod1_len > mod2_len) {
        diff = mod1_len - mod2_len;
        if (0 != memcmp(mod1+diff, mod2, mod2_len))
            return -1;
        if (NULL != memchr_not(mod1, 0, diff))
            return -1;
    } else {
        diff = mod2_len - mod1_len;
        if (0 != memcmp(mod2+diff, mod1, mod1_len))
            return -1;
        if (NULL != memchr_not(mod2, 0, diff))
            return -1;
    }
    return 0;
}

/*
 * Create a new context for the Montgomery and the given odd modulus.
 *
 * @param out       The locate where the pointer to the newly allocated data will be stored at.
 *                  The memory will contain the new Montgomery context.
 * @param modulus   The modulus encoded in big endian form.
 * @param mod_len   The length of the modulus in bytes.
 * @return          0 for success, the appropriate code otherwise.
 */
int mont_context_init(MontContext **out, const uint8_t *modulus, size_t mod_len)
{
    const uint8_t p256_mod[32] = "\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const uint8_t p384_mod[48] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff";
    const uint8_t p521_mod[66] = "\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    uint64_t *scratchpad = NULL;
    MontContext *ctx;
    int res;

    if (NULL == out || NULL == modulus)
        return ERR_NULL;

    /** Consume leading zeros **/
    while (mod_len>0 && *modulus==0) {
        modulus++;
        mod_len--;
    }
    if (0 == mod_len)
        return ERR_MODULUS;

    /** Ensure modulus is odd and at least 3, otherwise we can't compute its inverse over B **/
    if (is_even(modulus[mod_len-1]))
        return ERR_MODULUS;
    if (mod_len==1 && modulus[0]==1)
        return ERR_MODULUS;

    *out = ctx = (MontContext*)calloc(1, sizeof(MontContext));
    if (NULL == ctx)
        return ERR_MEMORY;

    /* Check if the modulus has a special form */
    /* For P-521, modulo reduction is very simple so the Montgomery
     * representation is not actually used.
     */
    ctx->modulus_type = ModulusGeneric;
    switch (mod_len) {
        case sizeof(p256_mod):
            if (0 == cmp_modulus(modulus, mod_len, p256_mod, sizeof(p256_mod))) {
                ctx->modulus_type = ModulusP256;
            }
            break;
        case sizeof(p384_mod):
            if (0 == cmp_modulus(modulus, mod_len, p384_mod, sizeof(p384_mod))) {
                ctx->modulus_type = ModulusP384;
            }
            break;
        case sizeof(p521_mod):
            if (0 == cmp_modulus(modulus, mod_len, p521_mod, sizeof(p521_mod))) {
                ctx->modulus_type = ModulusP521;
            }
            break;
    }

    ctx->words = ((unsigned)mod_len + 7) / 8;
    ctx->bytes = (unsigned)(ctx->words * sizeof(uint64_t));
    ctx->modulus_len = (unsigned)mod_len;

    /** Load modulus N **/
    ctx->modulus = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (0 == ctx->modulus) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    bytes_to_words(ctx->modulus, ctx->words, modulus, mod_len);

    /** Prepare 1 **/
    ctx->one = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == ctx->one) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    ctx->one[0] = 1;

    /** Pre-compute R² mod N **/
    /** Pre-compute -n[0]⁻¹ mod R **/
    ctx->r2_mod_n = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (0 == ctx->r2_mod_n) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    if (ctx->modulus_type != ModulusP521) {
        rsquare(ctx->r2_mod_n, ctx->modulus, ctx->words);
        ctx->m0 = inverse64(~ctx->modulus[0]+1);
    } else {
        memcpy(ctx->r2_mod_n, ctx->one, ctx->words * sizeof(uint64_t));
        ctx->m0 = 1U;
    }

    /** Pre-compute R mod N **/
    ctx->r_mod_n = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == ctx->r_mod_n) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    scratchpad = (uint64_t*)calloc(SCRATCHPAD_NR, ctx->words*sizeof(uint64_t));
    if (NULL == scratchpad) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    if (ctx->modulus_type != ModulusP521)
        mont_mult_generic(ctx->r_mod_n, ctx->one, ctx->r2_mod_n, ctx->modulus, ctx->m0, scratchpad, ctx->words);
    else
        memcpy(ctx->r_mod_n, ctx->one, ctx->words * sizeof(uint64_t));

    /** Pre-compute modulus - 2 **/
    /** Modulus is guaranteed to be >= 3 **/
    ctx->modulus_min_2 = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    if (NULL == ctx->modulus_min_2) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    sub(ctx->modulus_min_2, ctx->modulus, ctx->one, ctx->words);
    sub(ctx->modulus_min_2, ctx->modulus_min_2, ctx->one, ctx->words);

    res = 0;

cleanup:
    free(scratchpad);
    if (res != 0) {
        mont_context_free(ctx);
    }
    return res;
}

int mont_is_zero(const uint64_t *a, const MontContext *ctx)
{
    unsigned i;
    uint64_t sum = 0;

    if (NULL == a || NULL == ctx)
        return -1;

    for (i=0; i<ctx->words; i++) {
        sum |= *a++;
    }

    return (sum == 0);
}

int mont_is_one(const uint64_t *a, const MontContext *ctx)
{
    unsigned i;
    uint64_t sum = 0;

    if (NULL == a || NULL == ctx)
        return -1;

    for (i=0; i<ctx->words; i++) {
        sum |= a[i] ^ ctx->r_mod_n[i];
    }

    return (sum == 0);
}

int mont_is_equal(const uint64_t *a, const uint64_t *b, const MontContext *ctx)
{
    unsigned i;
    uint64_t result = 0;

    if (NULL == a || NULL == b || NULL == ctx)
        return -1;

    for (i=0; i<ctx->words; i++) {
        result |= *a++ ^ *b++;
    }

    return (result == 0);
}

int mont_copy(uint64_t *out, const uint64_t *a, const MontContext *ctx)
{
    unsigned i;

    if (NULL == out || NULL == a || NULL == ctx)
        return ERR_NULL;

    for (i=0; i<ctx->words; i++) {
        *out++ = *a++;
    }

    return 0;
}
