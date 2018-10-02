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
#include "common.h"

FAKE_INIT(montgomery)

#include "multiply.h"
#include "montgomery_utils.h"

#define CACHE_LINE_SIZE 64

/** Multiplication will be replaced by a look-up **/
/** Do not change this value! **/
#define WINDOW_SIZE 4

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
    assert((x*a & 0xFFFFFFFFFFFFFFFFULL) == 1);
    
    return x;
}

/**
 * Multiply a[] by k and add the result to t[].
 */
STATIC void addmul(uint64_t *t, const uint64_t *a, uint64_t k, size_t a_words, size_t t_words)
{
    size_t i;
    uint64_t carry;

    carry = 0;
    for (i=0; i<a_words; i++) {
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

    assert(i <= t_words);
}

/**
 * Multiply a[] by b[] and store the result into t[].
 *
 * a[] and b[] must have the same length.
 *
 * t[] will be twice as long.
 */
STATIC void product(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t words)
{
        size_t i;

        memset(t, 0, 2*sizeof(uint64_t)*words);
        
        for (i=0; i<(words & ~1U); i+=2) {
            addmul128(&t[i], a, b[i], b[i+1], words);
        }

        if (words & 1) {
            addmul(&t[words-1], a, b[words-1], words, words+2);
        }
}

/**
 * Compare two integers.
 * Return 1 is x>=y, 0 if x<y.
 */
static int ge(const uint64_t *x, const uint64_t *y, size_t words)
{
    size_t i, j;

    i=words-1;
    for (j=0; j<words; j++, i--) {
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
static uint64_t sub(uint64_t *a, size_t a_words, const uint64_t *b, size_t b_words)
{
    unsigned i;
    uint64_t borrow1 , borrow2;

    borrow2 = 0;
    for (i=0; i<b_words; i++) {
        borrow1 = b[i] > a[i];
        a[i] -= b[i];

        borrow1 |= borrow2 > a[i];
        a[i] -= borrow2;

        borrow2 = borrow1;
    }

    for (; borrow2>0 && i<a_words; i++) {
        borrow1 = borrow2 > a[i];
        a[i] -= borrow2;
        borrow2 = borrow1;
    }

    return borrow2;
}

/*
 * If n[] is L=words*64 bit long, let R be 2^L.
 * Then n < R.
 * This function computes R^2 mod n.
 */
static void rsquare(uint64_t *x, uint64_t *n, size_t words)
{
    size_t i;
    size_t elle;

    memset(x, 0, sizeof(uint64_t)*words);
    elle = words * sizeof(uint64_t) * 8;

    /**
     * Start with 1, double 2*L times,
     * and reduce it as soon as it exceeds n
     */
    x[0] = 1;
    for (i=0; i<elle*2; i++) {
        unsigned overflow;
        size_t j;
        
        /** Double, by shifting left by one bit **/
        overflow = (unsigned)(x[words-1] >> 63);
        for (j=words-1; j>0; j--) {
            x[j] = (x[j] << 1) + (x[j-1] >> 63);
        }
        /** Fill-in with zeroes **/
        x[0] <<= 1;
        
        /** Subtract n if the result exceeds it **/
        while (overflow || ge(x, n, words)) {
            sub(x, words, n, words);
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
static void mont_mult(uint64_t *out, uint64_t *a, uint64_t *b, uint64_t *n, uint64_t m0, uint64_t *t, size_t abn_words)
{
    unsigned i;

    if (a == b) {
        square_w(t, a, abn_words);
    } else {
        product(t, a, b, abn_words);
    }

    t[2*abn_words] = 0; /** MSW **/

    /** Clear lower words (two at a time) **/
    for (i=0; i<(abn_words & ~1U); i+=2) {
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
        
        addmul128(&t[i], n, k0, k1, abn_words);
    }
    
    /** One left for odd number of words **/
    if (abn_words & 1) {
        addmul(&t[abn_words-1], n, t[abn_words-1]*m0, abn_words, abn_words+2);
    }
    
    assert(t[2*abn_words] <= 1); /** MSW **/

    /** Divide by R and possibly subtract n **/
    if (t[2*abn_words] == 1 || ge(&t[abn_words], n, abn_words)) {
        sub(&t[abn_words], abn_words, n, abn_words);
    }
    memcpy(out, &t[abn_words], sizeof(uint64_t)*abn_words);
}

/**
 * Spread 16 multipliers in memory, to attempt to prevent an attacker from
 * easily inferring which one is being accessed based on the cache side-channel.
 *
 * @out prot[]   An array of 16*8*words bytes (organized in 32-bit words),
 *               aligned to the cache line boundary (64 bytes).
 *               Multipliers will be scattered in here.
 * @in  powers[] An array of 16 pointers to multipliers.
 * @in  words    The number of 64-bit words in a multiplier.
 * @in  seed     An array of 2*words bytes with the pseudorandom seed bytes.
 *
 * We assume a cache line is 64-bytes long. Every cache line will contain 16 32-bit
 * words, each taken from a different multiplier.
 * The word of each multiplier is 64-bits long though: one cache line therefore
 * contains the lower halves and the following the higher halves.
 *
 * The relationship between multiplier and position within each cache line is
 * randomized by means of the external seed.
 */
static void scatter(uint32_t *prot, uint64_t *powers[], size_t words, uint8_t *seed)
{
    size_t i, j;

    /** Layout of prot[]
     *
     *  - 16 32-bit pieces; each piece is the lower half of word[0] for a multiplier.
     *    Relation piece-to-multiplier depends on seed[0..1].
     *  - 16 32-bit pieces; each piece is the higher half of word[0] for a multiplier.
     *    Relation piece-to-multiplier depends on seed[0..1].
     *  - 16 32-bit pieces; each piece is the lower half of word[1] for a multiplier.
     *    Relation piece-to-multiplier depends on seed[2..3].
     *  - 16 32-bit pieces; each piece is the higher half of word[1] for a multiplier.
     *    Relation piece-to-multiplier depends on seed[2..3].
     *  - and so on...
     *
     * **/

    for (j=0; j<words; j++) {
        uint8_t alpha, beta;
    
        alpha = seed[2*j] | 1;  /** Must be invertible modulo 2^8 **/
        beta  = seed[2*j+1];

        for (i=0; i<16; i++) {
            uint32_t *x;
        
            x  = &prot[(alpha*i+beta) & 0xF];
            *x = (uint32_t) powers[i][j];
            *(x+16) = (uint32_t)(powers[i][j] >> 32);
        }

        prot += 32;     /** Two cache lines **/
    }
}

/**
 * Does the opposite of scatter(), by collecting a specific multiplier.
 *
 * Note that idx contains 4 bits of the exponent and it is most likely a secret.
 */
static void gather(uint64_t *out, const uint32_t *prot, size_t idx, size_t words, uint8_t *seed)
{
    size_t j;
    
    for (j=0; j<words; j++) {
        uint8_t alpha, beta;
        const uint32_t *x;
    
        alpha = seed[2*j] | 1;
        beta  = seed[2*j+1];
    
        x = &prot[(alpha*idx+beta) & 0xF];
        out[j] = *x | ((uint64_t)*(x+16) << 32);

        prot += 32;     /** Two cache lines **/
    }
}

struct Montgomery {
    uint64_t *base;
    uint64_t *modulus;
    uint64_t *r_square;
    uint64_t *one;
    uint64_t *x;
    uint64_t *t;
    uint64_t *powers[1 << WINDOW_SIZE];
    uint64_t *power_idx;
    uint32_t *prot;
    uint8_t  *seed;
};

/** Allocate space **/
#define allocate(x, y) do {             \
    x = calloc(y, sizeof(uint64_t));    \
    if (x == NULL) {                    \
        return 1;                       \
    }} while(0)


int allocate_montgomery(struct Montgomery *m, size_t words)
{
    int i;
    int result;

    memset(m, 0, sizeof *m);

    allocate(m->base, words);
    allocate(m->modulus, words);
    allocate(m->r_square, words);
    allocate(m->one, words);
    allocate(m->x, words);
    allocate(m->t, 2*words+1);
    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        allocate(m->powers[i], words);
    }
    allocate(m->power_idx, words);
    
    m->prot = align_alloc((1<<WINDOW_SIZE)*words*8, CACHE_LINE_SIZE);
    if (NULL == m->prot) {
        return 1;
    }

    allocate(m->seed, 2*words);

    result = 0;
    return result;
}

#undef allocate

void deallocate_montgomery(struct Montgomery *m)
{
    int i;

    free(m->base);
    free(m->modulus);
    free(m->r_square);
    free(m->one);
    free(m->x);
    free(m->t);
    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        free(m->powers[i]);
    }
    free(m->power_idx);
   
    align_free(m->prot); 

    free(m->seed);
    
    memset(m, 0, sizeof *m);
}

EXPORT_SYM int monty_pow(const uint8_t *base,
               const uint8_t *exp,
               const uint8_t *modulus,
               uint8_t       *out,
               size_t len,
               uint64_t seed)
{
    uint64_t m0;
    unsigned i, j;
    size_t words;
    size_t exp_len;

    struct Montgomery monty;
    struct BitWindow bit_window;

    if (!base || !exp || !modulus || !out || len==0) {
        return 1;
    }
    
    /** Odd (and non-zero) modulus only **/
    if (!(modulus[len-1] & 1)) {
        return 2;
    }

    words = (len+7) / 8;
    memset(out, 0, len);
    
    if (allocate_montgomery(&monty, words)) {
        deallocate_montgomery(&monty);
        return 3;
    }

    /** Compute full seed (2*words bytes) **/
    expand_seed(seed, monty.seed, 2*words);

    /** Take in numbers **/
    bytes_to_words(monty.base, base, len, words);
    bytes_to_words(monty.modulus, modulus, len, words);

    /** Set one **/
    monty.one[0] = 1;

    /** Pre-compute R^2 mod n **/
    rsquare(monty.r_square, monty.modulus, words);

    /** Pre-compute -n[0]^{-1} mod R **/
    m0 = inverse64(~monty.modulus[0]+1);

    /** Convert base to Montgomery form **/
    mont_mult(monty.base, monty.base, monty.r_square, monty.modulus, m0, monty.t, words);
    
    /** Result is initially 1 in Montgomery form **/
    monty.x[0] = 1;
    mont_mult(monty.x, monty.x, monty.r_square, monty.modulus, m0, monty.t, words);

    /** Pre-compute powers a^0 mod n, a^1 mod n, a^2 mod n, ... a^(2^WINDOW_SIZE-1) mod n **/
    memcpy(monty.powers[0], monty.x,    sizeof(uint64_t)*words);
    memcpy(monty.powers[1], monty.base, sizeof(uint64_t)*words);
    for (i=1; i<(1 << (WINDOW_SIZE-1)); i++) {
        mont_mult(monty.powers[i*2],   monty.powers[i],   monty.powers[i], monty.modulus, m0, monty.t, words);
        mont_mult(monty.powers[i*2+1], monty.powers[i*2], monty.base,      monty.modulus, m0, monty.t, words);
    }
    scatter(monty.prot, monty.powers, words, monty.seed);

    /** Ignore leading zero bytes in the exponent **/
    exp_len = len;
    for (i=0; i<len && *exp==0; i++) {
        exp_len--;
        exp++;
    }
    if (exp_len == 0) {
        words_to_bytes(out, monty.one, len, words);
        return 0;
    }

    bit_window = init_bit_window(WINDOW_SIZE, exp, exp_len);
    
    for (i=0; i < bit_window.nr_windows; i++) {
        unsigned index;

        /** Left-to-right exponentiation with fixed window **/       
        for (j=0; j<WINDOW_SIZE; j++) {
            mont_mult(monty.x, monty.x, monty.x, monty.modulus, m0, monty.t, words);
        }
        
        index = get_next_digit(&bit_window);
        gather(monty.power_idx, monty.prot, index, words, monty.seed);
        
        mont_mult(monty.x, monty.x, monty.power_idx, monty.modulus, m0, monty.t, words);
    }

    /** Transform result back in normal form **/    
    mont_mult(monty.x, monty.x, monty.one, monty.modulus, m0, monty.t, words);
    words_to_bytes(out, monty.x, len, words);

    deallocate_montgomery(&monty);

    return 0;
}

#ifdef MAIN

int main(void)
{
    uint16_t length;
    uint8_t *base, *modulus, *exponent, *out;
    int result;

    fread(&length, 2, 1, stdin);

    base = malloc(length);
    modulus = malloc(length);
    exponent = malloc(length);
    out = malloc(length);

    fread(base, 1, length, stdin);
    fread(modulus, 1, length, stdin);
    fread(exponent, 1, length, stdin);
    fread(out, 1, length, stdin);

    result = monty_pow(base, exponent, modulus, out, length, 12);
    
    free(base);
    free(modulus);
    free(exponent);
    free(out);

    return result;
}

#endif

#ifdef PROFILE
int main(void)
{
    uint8_t base[256], exponent[256], modulus[256], out[256];
    int length = 256, i, j;

    for (i=0; i<256; i++) {
        base[i] = i | 0x80 | 1;
        exponent[i] = base[i] = modulus[i] = base[i];
    }

    for (j=0; j<50; j++) {
    monty_pow(base, exponent, modulus, out, length, 12);
    }

}
#endif
