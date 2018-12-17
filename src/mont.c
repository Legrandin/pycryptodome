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

typedef struct mont_context {
    unsigned words;
    uint64_t *modulus;
    uint64_t *r2;   /* R^2 mod N */ 
    uint64_t m0;
} MontContext;

static inline unsigned is_odd(uint64_t x)
{
    return 1 == (x & 1);
}

static inline unsigned is_even(uint64_t x)
{
    return !is_odd(x);
}

/**
 * Compute the inverse modulo 2^64 of a 64-bit odd integer.
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
 * Check if big integer x is greater or equal to y.
 *
 * @param x     The first term
 * @param y     The second term
 * @param nw    The number of words that make up both x and y
 * @return      1 if x>=y, 0 if x<y
 */
STATIC int ge(const uint64_t *x, const uint64_t *y, size_t nw)
{
    size_t i, j;

    i = nw-1;
    for (j=0; j<nw; j++, i--) {
        if (x[i] == y[i]) {
            continue;
        }
        return x[i] > y[i];
    }
    return 1;
}

/*
 * Subtract integer b from a, leaving the difference in a.
 *
 * @param a     Number to subtract from
 * @param b     Number to subtract
 * @param nw    The number of words that make up both a and b
 * @result      0 if there is no borrow, 1 otherwise
 */
STATIC uint64_t sub(uint64_t *a, const uint64_t *b, size_t nw)
{
    unsigned i;
    uint64_t borrow1 , borrow2;

    borrow2 = 0;
    for (i=0; i<nw; i++) {
        borrow1 = b[i] > a[i];
        a[i] -= b[i];

        borrow1 |= borrow2 > a[i];
        a[i] -= borrow2;

        borrow2 = borrow1;
    }

    return borrow2;
}

/*
 * Compute R^2 mod N, where R is the smallest power of 2^64
 * which is larger than N.
 *
 * @param r2    Where the result is stored to
 * @param n     The modulus N
 * @param nw    The number of 64-bit words that make up r2 and n
 */
STATIC void rsquare(uint64_t *r2, uint64_t *n, size_t nw)
{
    size_t i;
    size_t R_bits;

    memset(r2, 0, sizeof(uint64_t)*nw);

    /**
     * Start with R2=1, double 2*bitlen(R) times,
     * and reduce it as soon as it exceeds n
     */
    r2[0] = 1;
    R_bits = nw * sizeof(uint64_t) * 8;
    for (i=0; i<R_bits*2; i++) {
        unsigned overflow;
        size_t j;
        
        /** Double, by shifting left by one bit **/
        overflow = (unsigned)(r2[nw-1] >> 63);
        for (j=nw-1; j>0; j--) {
            r2[j] = (r2[j] << 1) + (r2[j-1] >> 63);
        }
        /** Fill-in with zeroes **/
        r2[0] <<= 1;
        
        /** Subtract n if the result exceeds it **/
        while (overflow || ge(r2, n, nw)) {
            sub(r2, n, nw);
            overflow = 0;
        }
    }
}

/*
 * Multiply a big integer a by a 64-bit scalar k and add the result to big
 * integer t.
 *
 * @param t     The big integer the result of the
 *              multiplication will be added to
 * @param tw    The number of words that make up t
 * @param a     The big integer to multiply with the scalar
 * @param aw    The number of words that make up a
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
 * Multiply two big integers.
 *
 * @param t Where to store the result. Array of  2*nw words.
 * @param a The first term, array of nw words.
 * @param a The first term, array of nw words.
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
 * Montgomery modular multiplication, that is a*b*R mod N.
 *
 * @param out   The location where the result is stored
 * @param a     The first term (already in Montgomery form, a*R mod N)
 * @param b     The second term (already in Montgomery form, b*R mod N)
 * @param b     The modulus (in normal form), such that R>N
 * @param m0    Least-significant word of the oppossite of the inverse of n modulo R, that is, inv(-n[0], R)
 * @param t     Temporary scratchpad with 2*nw+1 words
 * @param nw    Number of words making up the 3 integers: out, a, and b.
 *              It also defines R as 2^(64*nw).
 *
 * Useful read: https://alicebob.cryptoland.net/understanding-the-montgomery-reduction-algorithm/
 */
STATIC void mont_mult(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw)
{
    unsigned i;

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

    /** Divide by R and possibly subtract n **/
    if (t[2*nw] == 1 || ge(&t[nw], n, nw)) {
        sub(&t[nw], n, nw);
    }
    memcpy(out, &t[nw], sizeof(uint64_t)*nw);
}

/*
 * Create a new context for Montgomery form in the given odd modulus.
 *
 * @param out       The memory area where the pointer to the new Montgomery context
 *                  structure is writter into.
 * @param modulus   The modulus encoded in big endian form.
 * @param mod_len   The length of the modulus.
 * @return          0 for success, the appropriate code otherwise.
 */
int mont_init(MontContext **out, const uint8_t *modulus, size_t mod_len)
{
    MontContext *ctx;

    if (NULL == modulus || NULL == out)
        return ERR_NULL;

    if (0 == mod_len || is_even(modulus[mod_len-1]))
        return ERR_VALUE;

    *out = ctx = (MontContext*)calloc(1, sizeof(MontContext));
    if (NULL == ctx)
        return ERR_MEMORY;

    ctx->words = (mod_len + 7) / 8;

    /** Load modulus N **/
    ctx->modulus = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    bytes_to_words(ctx->modulus, ctx->words, modulus, mod_len);
   
    /** Pre-compute R^2 mod N **/
    ctx->r2 = (uint64_t*)calloc(ctx->words, sizeof(uint64_t));
    rsquare(ctx->r2, ctx->modulus, ctx->words);

    /** Pre-compute -n[0]^{-1} mod R **/
    ctx->m0 = inverse64(~ctx->modulus[0]+1);

    return 0;
}

