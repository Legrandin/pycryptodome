/*
Copyright (c) 2017, Helder Eijs <helderijs@gmail.com>
All rights reserved. 

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met: 

 * Redistributions of source code must retain the above copyright notice, 
   this list of conditions and the following disclaimer. 
 * Redistributions in binary form must reproduce the above copyright 
   notice, this list of conditions and the following disclaimer in the 
   documentation and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY 
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
DAMAGE. 
*/

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "pycrypto_common.h"

FAKE_INIT(montgomery)

#include "multiply.h"

void *malloc_aligned(size_t size, size_t alignment);
void free_aligned(void *ptr);

#ifdef _MSC_VER

void *malloc_aligned(size_t size, size_t alignment)
{
    return _aligned_malloc(size, alignment);
}

void free_aligned(void *ptr)
{
    _aligned_free(ptr);
}

#else

void *malloc_aligned(size_t size, size_t alignment)
{
    void *ptr;
    int result;

    result = posix_memalign(&ptr, alignment, size);
    if (result) {
        return NULL;
    }
    
    return ptr;
}

void free_aligned(void *ptr)
{
    free(ptr);
}

#endif

/** Multiplication will be replaced by a look-up **/
/** Do not change this value! **/
#define WINDOW_SIZE 4

#if 0
static void print_words_w(const uint8_t *str, const uint64_t *x, unsigned words)
{
    int i;
    printf("%s = 0x", str);
    for (i=words-1; i>=0; i--) {
        printf("%016" PRIx64, x[i]);
    }
    printf("\n");
}
#endif

/**
 * Convert a number in[], originally encoded as raw bytes (big endian)
 * into words x[] (little endian). The output array x[] must
 * be correctly sized.
 *
 * The length of the array in[] may not be a multiple of 8, in which
 * case the most significant word of x[] gets padded with zeroes.
 */
static void bytes_to_words(uint64_t *x, const uint8_t *in, size_t len, size_t words)
{
    int i, j;
    size_t partial;

    if (words == 0 || len == 0) {
        return;
    }

    assert(len<=words*8);
    assert(len>(words-1)*8);

    memset(x, 0, words*8);

    partial = len % 8;
    if (partial == 0) {
        partial = 8;
    }

    for (j=0; j<partial; j++) {
        x[words-1] = (x[words-1] << 8) | *in++;
    }

    if (words == 1) {
        return;
    }

    for (i=words-2; i>=0; i--) {
        for (j=0; j<8; j++) {
            x[i] = (x[i] << 8) | *in++;
        }
    }
}

/**
 * Convert a number in[], originally encoded in words (little endian)
 * into bytes (big endian). The output array out[] must
 * have appropriate size.
 */
static void words_to_bytes(uint8_t *out, const uint64_t *x, size_t len, size_t words)
{
    int i, j;
    size_t partial;

    if (words == 0 || len == 0) {
        return;
    }

    assert(len<=words*8);
    assert(len>(words-1)*8);

    partial = len % 8;
    if (partial == 0) {
        partial = 8;
    }

    for (j=partial-1; j>=0; j--) {
        *out++ = (uint8_t)(x[words-1] >> (8*j));
    }

    if (words == 1) {
        return;
    }

    for (i=words-2; i>=0; i--) {
        for (j=7; j>=0; j--) {
            *out++ = x[i] >> (8*j);
        }
    }
}

/**
 * Compute inverse modulo 2**64
 *
 * See https://crypto.stackexchange.com/questions/47493/how-to-determine-the-multiplicative-inverse-modulo-64-or-other-power-of-two
 */
static uint64_t inverse64(uint64_t a)
{
    uint64_t x;

    assert(1 & a);
    x = ((a << 1 ^ a) & 4) << 1 ^ a;
    x += x - a*x*x;
    x += x - a*x*x;
    x += x - a*x*x;
    x += x - a*x*x;
    assert((x*a & 0xFFFFFFFFFFFFFFFFUL) == 1);
    
    return x;
}

/**
 * Multiply a[] by k and add the result to t[].
 */
static void addmul(uint64_t *t, const uint64_t *a, uint64_t k, size_t words)
{
    size_t i;
    uint64_t carry;

    carry = 0;
    for (i=0; i<words; i++) {
        uint64_t pr_lo, pr_hi;

        DP_MULT(a[i], k, pr_lo, pr_hi);
    
        pr_lo += carry;
        pr_hi += pr_lo < carry;

        t[i] += pr_lo;
        pr_hi += t[i] < pr_lo;

        carry = pr_hi; 
    }

    for (; carry; i++) {
        t[i] += carry;
        carry = t[i] < carry;
    }
}

/**
 * Multiply a[] by b[] and store the result into t[].
 */
static void product(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t words)
{
        size_t i;

        memset(t, 0, 2*sizeof(uint64_t)*words);
        
        for (i=0; i<(words & ~1); i+=2) {
            addmul128(&t[i], a, b[i], b[i+1], words);
        }

        if (words & 1) {
            addmul(&t[words-1], a, b[words-1], words);
        }
}

/**
 * Compare two integers.
 * Return 1 is x>=y, 0 if x<y.
 */
static int ge(const uint64_t *x, const uint64_t *y, size_t words)
{
    int i;

    for (i=words-1; i>=0; i--) {
        if (x[i] == y[i]) {
            continue;
        }
        return x[i] > y[i];
    }
    return 1;
}

/**
 * Subtract b[] from a[].
 */
static void sub(uint64_t *a, const uint64_t *b, size_t words)
{
    int i;
    uint64_t borrow1 , borrow2;

    borrow1 = borrow2 = 0;
    for (i=0; i<words; i++) {
        borrow1 = b[i] > a[i];
        a[i] -= b[i];

        borrow1 |= borrow2 > a[i];
        a[i] -= borrow2;

        borrow2 = borrow1;
    }
}

/*
 * If n[] is L=words*64 bit long, let R be 2^L.
 * Then n < R.
 * This function computes R^2 mod n.
 */
static void rsquare(uint64_t *x, uint64_t *n, size_t words)
{
    int i, j;
    size_t elle;

    memset(x, 0, sizeof(uint64_t)*words);
    elle = words * sizeof(uint64_t) * 8;

    /**
     * Start with 1, double 2*L times,
     * and reduce it as soon as it exceeds n
     */
    x[0] = 1;
    for (i=0; i<elle*2; i++) {
        int overflow;
        
        /** Double, by shifting left by one bit **/
        overflow = x[words-1] >> 63;
        for (j=words-1; j>0; j--) {
            x[j] = (x[j] << 1) + (x[j-1] >> 63);
        }
        /** Fill-in with zeroes **/
        x[0] <<= 1;
        
        /** Subtract n if the result exceeds it **/
        while (overflow || ge(x, n, words)) {
            sub(x, n, words);
            overflow = 0;
        }
    }
}

/**
 * Montgomery multiplicaton.
 * Input:
 * - a[], 1st term, in Montgomery form
 * - b[], 2nd term, in Montgomery form
 * - n[], modulus
 * - m0, LSW of the opposite of the inverse of n modulo R, a single word
 * - t[], temp buffer, 2*words+1
 *
 * https://alicebob.cryptoland.net/understanding-the-montgomery-reduction-algorithm/
 */
static void mont_mult(uint64_t *out, uint64_t *a, uint64_t *b, uint64_t *n, uint64_t m0, uint64_t *t, size_t words)
{
    int i;

    if (a == b) {
        square_w(t, a, words);
    } else {
        product(t, a, b, words);
    }

    t[2*words] = 0; /** MSW **/

    /** Clear lower words (two at a time) **/
    for (i=0; i<(words & ~1); i+=2) {
        uint64_t k0, k1, ti1, pr_lo, pr_hi;

        /** Multiplier for n that will make t[i+0] go 0 **/
        k0 = t[i] * m0;
        
        /** Simulate Muladd for digit 0 **/
        DP_MULT(k0, n[0], pr_lo, pr_hi);
        pr_lo += t[i];
        pr_hi += pr_lo < t[i];

        /** Expected digit 1 **/
        ti1 = t[i+1] + n[1]*k0 + pr_hi;
        
        /** Multiplier for n that will make t[i+1] go 0 **/
        k1 = ti1 * m0;
        
        addmul128(&t[i], n, k0, k1, words);
    }
    
    /** One left for odd number of words **/
    if (words & 1) {
        addmul(&t[words-1], n, t[words-1]*m0, words);
    }
    
    assert(t[2*words] <= 1); /** MSW **/

    /** Divide by R and possibly subtract n **/
    if (t[2*words] == 1 || ge(&t[words], n, words)) {
        sub(&t[words], n, words);
    }
    memcpy(out, &t[words], sizeof(uint64_t)*words);
}

static void scatter(uint32_t *prot, uint64_t *powers[], size_t words, uint64_t seed)
{
    size_t i, j;
    uint32_t *x;

    uint8_t alpha, beta;

    alpha = seed | 1;
    beta = seed >> 8;

    /** Each of the 16 multipliers is split into
     * 32-bit words. Words are set 64 bytes apart
     * in memory **/

    for (i=0; i<16; i++) {
        x = &prot[(alpha*i+beta) & 0xF];
        for (j=0; j<words; j++, x+=32) {
            *x      = (uint32_t) powers[i][j];
            *(x+16) = powers[i][j] >> 32;
        }
    }
}

static void gather(uint64_t *out, const uint32_t *prot, size_t idx, size_t words, uint64_t seed)
{
    size_t j;
    const uint32_t *x;

    uint8_t alpha, beta;

    alpha = seed | 1;
    beta = seed >> 8;

    x = &prot[(alpha*idx+beta) & 0xF];
    for (j=0; j<words; j++, x+=32) {
        out[j] = *x | ((uint64_t)*(x+16) << 32);
    }
}

EXPORT_SYM int monty_pow(const uint8_t *base,
               const uint8_t *exp,
               const uint8_t *modulus,
               uint8_t       *out,
               size_t len,
               uint64_t seed)
{
    uint64_t *a, *n, *r2, *one, *x, *t;
    uint64_t *powers[1 << WINDOW_SIZE];
    uint64_t *powers_idx;
    uint32_t *prot;
    uint64_t m0;
    int i, j, scan_exp;
    size_t words;
    unsigned nr_windows, available, tg;
    int error = 0;
    size_t exp_len;

    /** All pointers are NULL **/
    a = n = r2 = one = x = t = powers_idx = NULL;
    prot = NULL;
    memset(powers, 0, (1<<WINDOW_SIZE) *sizeof(uint64_t*));
    
    if (!base || !exp || !modulus || !out || len==0) {
        return 1;
    }
    
    /** Odd modulus only **/
    if (!(modulus[len-1] & 1)) {
        return 2;
    }

    words = (len+7) / 8;
    memset(out, 0, len);

    /** Allocate space **/
    #define allocate(x, y) do {             \
        x = calloc(y, sizeof(uint64_t));    \
        if (x == NULL) {                    \
            error = 3;                      \
            goto cleanup;                   \
        }} while(0)
    
    allocate(a, words);
    allocate(n, words);
    allocate(one, words);
    allocate(x, words);
    allocate(r2, words);
    allocate(t, 2*words+1);
    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        allocate(powers[i], words);
    }
    allocate(powers_idx, words);
    prot = malloc_aligned((1<<WINDOW_SIZE)*words*8, 64);
    if (NULL == prot) {
        error = 3;
        goto cleanup;
    }
    #undef allocate

    /** Take in numbers **/
    bytes_to_words(a, base, len, words);
    bytes_to_words(n, modulus, len, words);

    /** Set one **/
    one[0] = 1;

    /** Pre-compute R^2 mod n **/
    rsquare(r2, n, words);

    /** Pre-compute -n[0]^{-1} mod R **/
    m0 = inverse64(-n[0]);

    /** Convert base to Montgomery form **/
    mont_mult(a, a, r2, n, m0, t, words);
    
    /** Result is initially 1 in Montgomery form **/
    x[0] = 1;
    mont_mult(x, x, r2, n, m0, t, words);

    /** Pre-compute powers a^0 mod n, a^1 mod n, a^2 mod n, ... a^(2^WINDOW_SIZE-1) mod n **/
    memcpy(powers[0], x, sizeof(uint64_t)*words);
    memcpy(powers[1], a, sizeof(uint64_t)*words);
    for (i=1; i<(1 << (WINDOW_SIZE-1)); i++) {
        mont_mult(powers[i*2], powers[i], powers[i], n, m0, t, words);
        mont_mult(powers[i*2+1], powers[i*2], a, n, m0, t, words);
    }
    scatter(prot, powers, words, seed);

    /** Ignore leading zero bytes in the exponent **/
    exp_len = len;
    for (i=0; i<len && *exp==0; i++) {
        exp_len--;
        exp++;
    }
    if (exp_len == 0) {
        memcpy(out, one, sizeof(uint64_t)*words);
        return 0;
    }
    /** Total number of windows covering the exponent **/
    nr_windows = (exp_len*8+WINDOW_SIZE-1)/WINDOW_SIZE;
    /** Number of bits for the first (partial) digit (<=WINDOW_SIZE) **/
    tg = (exp_len*8) % WINDOW_SIZE;
    if (tg == 0) {
        tg = WINDOW_SIZE;
    }
    /** Number of rightmost bits that can be used in the current byte **/
    available = 8;
    /** Index to the byte in the big-endian exponent currently scanned **/
    scan_exp = 0;
    for (i=0; i<nr_windows; i++, tg=WINDOW_SIZE) {
        unsigned index, tc;

        /** Scan the next byte **/
        if (available == 0) {
            available = 8;
            scan_exp++;
        }

        /** Try to consume as much as possible from the current byte **/
        tc = available > tg ? tg : available;
        index = (exp[scan_exp] >> (available - tc)) & ((1 << tc) - 1);
        available -= tc;
        tg -= tc;
        
        /** A few bits (<8) might still be needed from the next byte **/
        if (tg != 0) {
            index = (index << tg) | (exp[++scan_exp] >> (8 - tg));
            available = 8 - tg;
        }

        /** Left-to-right exponentiation with fixed window **/       
        for (j=0; j<WINDOW_SIZE; j++) {
            mont_mult(x, x, x, n, m0, t, words);
        }
        gather(powers_idx, prot, index, words, seed);
        mont_mult(x, x, powers_idx, n, m0, t, words);
    }

    /** Transform result back in normal form **/    
    mont_mult(x, x, one, n, m0, t, words);
    words_to_bytes(out, x, len, words);

cleanup:
    free(a);
    free(n);
    free(one);
    free(x);
    free(r2);
    free(t);
    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        free(powers[i]);
    }
    free(powers_idx);
    free_aligned(prot);

    return error;
}

#ifdef MAIN

#define BIT_SIZE 2048

int main(void)
{
    int i;

    uint8_t a[BIT_SIZE/8], b[BIT_SIZE/8];

    for (i=0; i<(BIT_SIZE/8); i++) {
        a[i] = i | 0x81;
    }

    for (i=0; i<100; i++) {
        monty_pow(a, a, a, b, BIT_SIZE/8, 0xAAAA);
    }
}
#endif
