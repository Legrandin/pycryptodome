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

#include "common.h"

FAKE_INIT(ghash_clmul)

#include <wmmintrin.h>

#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

/**
 * This module implement the basic GHASH multiplication, as described in
 * NIST SP 800-38D.
 *
 * Specifically, we perform the multiplication of two elements in GF(2^128)
 * represented as polynomials, modulo P(x) = x^128 + x^7 + x + 1.
 *
 * The coefficients of the two polynomials are encoded little endian
 * byte wise, but big endian bit wise (within a byte).
 *
 * In other words, the 16-bit byte string in memory:
 *
 *      0x40 0x01
 *
 * represents the polynomial:
 *
 *      x^15 + x^2 = 0x8002
 *
 * Of course, polynomials in this case have degree 127, not 15.
 *
 * Internally, we prefer to operate with the conventional representation of
 * bits within a byte (leftmost bit is LSB). To that end, as explained in [3],
 * it is possible to work with the *reflected* values.
 *
 * References:
 * [1] http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.447.379&rep=rep1&type=pdf
 * [2] https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
 * [3] https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html
 */

/**
 * Perform the Montgomery reduction on a polynomial of degree 255,
 * using basis x^128 and modulus p(x) = x^128 + x^127 + x^126 + x^121 + 1.
 *
 * See at the bottom for an explaination.
 */
static inline __m128i reduce(__m128i prod_high, __m128i prod_low)
{
    const uint64_t c2 = 0xc200000000000000U;
    __m128i t1, t2, t3, t4, t7;
   
    t1 = prod_high;     // U3:U2
    t7 = prod_low;      // U1:U0
    t3 = _mm_loadl_epi64((__m128i*)&c2);
    t2 = _mm_clmulepi64_si128(t3, t7, 0x00);    // A
    t4 = _mm_shuffle_epi32(t7, _MM_SHUFFLE(1,0,3,2));   // U0:U1
    t4 = _mm_xor_si128(t4, t2); // B
    t2 = _mm_clmulepi64_si128(t3, t4, 0x00);    // C
    t4 = _mm_shuffle_epi32(t4, _MM_SHUFFLE(1,0,3,2));   // B0:B1
    t4 = _mm_xor_si128(t4, t2); // D
    t1 = _mm_xor_si128(t1, t4); // T
    
    return t1;
}

/**
 * Perform the carry-less multiplication of two polynomials of degree 127.
 */
static inline void clmult(__m128i *prod_high, __m128i *prod_low, __m128i *a, __m128i *b)
{
    __m128i c, d, e, f, g, h, i;

    c = _mm_clmulepi64_si128(*a, *b, 0x00);   // A0*B0
    d = _mm_clmulepi64_si128(*a, *b, 0x11);   // A1*B1
    e = _mm_clmulepi64_si128(*a, *b, 0x10);   // A0*B1
    f = _mm_clmulepi64_si128(*a, *b, 0x01);   // A1*B0
    g = _mm_xor_si128(e, f);                // E1+F1:E0+F0
    h = _mm_slli_si128(g, 8);               // E0+F0:0
    i = _mm_srli_si128(g, 8);               // 0:E1+F1
    *prod_high = _mm_xor_si128(d, i);
    *prod_low  = _mm_xor_si128(c, h);
}

/**
 * Multiply a polynomial of degree 127 by x, modulo p(x) = x^128 + x^127 + x^126 + x^121 + 1
 */
static inline __m128i multx(__m128i a)
{
    int msb;
    int64_t r;
    uint64_t p0, p1;
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;

    msb = _mm_movemask_epi8(a) >> 15;       // Bit 0 is a[127]
    r = (msb ^ 1) - 1;                      // Msb is copied in all 64 positions
    p0 = (uint64_t)r & 0x0000000000000001U; // Zero or XOR mask (low)
    p1 = (uint64_t)r & 0xc200000000000000U; // Zero or XOR mask (high)
    t0 = _mm_loadl_epi64((__m128i*)&p0);
    t1 = _mm_loadl_epi64((__m128i*)&p1);
    t2 = _mm_unpacklo_epi64(t0, t1);        // Zero or XOR mask

    // Shift value a left by 1 bit
    t3 = _mm_slli_si128(a, 8);     // Shift a left by 64 bits (lower 64 bits are zero)
    t4 = _mm_srli_epi64(t3, 63);    // Bit 64 is now a[63], all other bits are 0
    t5 = _mm_slli_epi64(a, 1);      // Shift left by 1 bit, but bit 64 is zero, not a[63]
    t6 = _mm_or_si128(t4, t5);      // Actual result of shift left by 1 bit

    // XOR conditional mask
    t7 = _mm_xor_si128(t2, t6);
    
    return t7;
}

/** Swap bytes in an XMM register **/
static inline __m128i swap(__m128i a)
{
    __m128i mask;

    mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(a, mask);
}

/**
 * Multiply two polynomials A and B in GF(2^128) modulo x^128 + x^7 + x + 1.
 *
 * b[] is actually pre-swapped and pre-multiplied by x.
 *
 * We use the fundamental result that the product is equivalent to:
 *
 *  A * (B * x) * x^{-128} modulo x^128 + x^127 + x^126 + x^121 + 1
 */
static inline __m128i ghash_mult(__m128i *a, __m128i *bx)
{
    __m128i a128, prod_hi, prod_lo, result;

    a128 = swap(*a);
    clmult(&prod_hi, &prod_lo, &a128, bx);
    result = reduce(prod_hi, prod_lo);
    return swap(result);
}

EXPORT_SYM int ghash_expand_clmul(const uint8_t h[16], __m128i **expanded)
{
    __m128i h128;

    if (NULL==h || NULL==expanded)
        return ERR_NULL;

    *expanded = align_alloc(16, 16);
    if (NULL == *expanded)
        return ERR_MEMORY;

    /** Pre-swap and pre-multiply h by x **/
    h128 = swap(_mm_loadu_si128((__m128i*)h));
    **expanded = multx(h128);

    return 0;
}

EXPORT_SYM int ghash_destroy_clmul(__m128i *expanded)
{
    align_free(expanded);
    return 0;
}

EXPORT_SYM int ghash_clmul(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t len,
        const uint8_t y_in[16],
        __m128i *expanded
        )
{
    unsigned i;
    __m128i y_temp;

    if (NULL==y_out || NULL==block_data || NULL==y_in || NULL==expanded)
        return ERR_NULL;

    if (len % 16)
        return ERR_NOT_ENOUGH_DATA;

    y_temp = _mm_loadu_si128((__m128i*)y_in);
    for (i=0; i<len; i+=16) {
        __m128i x, data;

        data = _mm_loadu_si128((__m128i*)&block_data[i]);
        x = _mm_xor_si128(y_temp, data);
        y_temp = ghash_mult(&x, expanded);
    }

    _mm_storeu_si128((__m128i*)y_out, y_temp);
    return 0;
}

/**
 * The function reduce() computes the Montgomery reduction
 * of U (input, 256 bits) with FastREDC algorithm:
 *
 *  Q = ((U mod X^128) * p' mod X^128
 *  T = (U + Q*p) div X^128
 *
 * where:
 *  p = 1:C200000000000000:1 = 1:c2:1
 *  p' = p^{-1} mod X^128 = C200000000000000:1 = c2:1
 *
 * U3:U2 : U1:U0 (256 bit)
 * Q1:Q0 (128 bit)
 * T1:T0 (128 bit)
 *
 * Q = (U mod X^128) * p' mod X^128
 *   = (U1:U0) * p' mod X^128 = (U1:U0) * (c2:1) mod X^128 = Q1:Q0
 *   Q0 = U0
 *   Q1 = L(U0*c2) + U1
 *
 * T = (U + Q*p) div X^128 = T1:T0
 *
 * Q*p = S = Q1:Q0 * 1:c2:1
 *   S0 = Q0 (dropped)
 *   S1 = L(c2*Q0) + Q1 (dropped)
 *   S2 = Q0 + L(c2*Q1) + H(c2*Q0)
 *   S3 = Q1 + H(c2*Q1)
 *
 * T0 = S2 + U2
 * T1 = S3 + U3
 *
 * Q1 = L(U0*c2) + U1
 * T0 = U0 + L(c2*Q1) + H(c2*U0) + U2
 * T1 = Q1 + H(c2*Q1) + U3
 *
 * A = c2*U0
 * Q1 = A0 + U1
 * T0 = U0 + L(c2*Q1) + A1 + U2
 * T1 = Q1 + H(c2*Q1) + U3
 *
 * A = c2*U0
 * B = A + U0:U1 = B1:Q1
 * T0 = L(c2*B0) + B1 + U2
 * T1 = B0 + H(c2*B0) + U3
 *
 * A = c2*U0
 * B = A + U0:U1
 * C = c2*B0
 * T0 = C0 + B1 + U2
 * T1 = B0 + C1 + U3
 *
 * A = c2*U0
 * B = A + U0:U1
 * C = c2*B0
 * D = C + B0:B1
 * T0 = D0 + U2
 * T1 = D1 + U3
 */



