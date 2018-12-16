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

typedef struct mont_context {
    unsigned words;
    uint64_t *modulus;
    uint64_t *r2;   /* R^2 mod N */ 
    uint64_t m0;
} MontContext;

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
 * Subtract integer a from integer b, leaving the difference in a.
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

    if (0 == mod_len || 0 == (modulus[mod_len-1] & 1))
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

