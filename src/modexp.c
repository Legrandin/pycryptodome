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

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "endianess.h"

FAKE_INIT(modexp)

#include "mont.h"
#include "modexp_utils.h"

#define CACHE_LINE_SIZE 64

/** Multiplication will be replaced by a look-up **/
/** Do not change this value! **/
#define WINDOW_SIZE 4

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
static void scatter(uint32_t *prot, uint64_t *powers[], size_t words, const uint8_t *seed)
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
static void gather(uint64_t *out, const uint32_t *prot, size_t idx, size_t words, const uint8_t *seed)
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

EXPORT_SYM int monty_pow(
               uint8_t       *out,
               const uint8_t *base,
               const uint8_t *exp,
               const uint8_t *modulus,
               size_t        len,
               uint64_t      seed)
{
    unsigned i, j;
    size_t words;
    size_t exp_len;
    int res;

    MontContext *ctx = NULL;
    uint8_t *mont_seed = NULL;
    uint64_t *powers[1 << WINDOW_SIZE] = { NULL };
    uint64_t *power_idx = NULL;
    uint32_t *prot = NULL;
    uint64_t *mont_base = NULL;
    uint64_t *x = NULL;
    uint64_t *scratchpad = NULL;
    uint8_t *buf_out = NULL;

    struct BitWindow bit_window;

    if (!base || !exp || !modulus || !out)
        return ERR_NULL;

    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;

    /* Allocations **/
    res = mont_context_init(&ctx, modulus, len);
    if (res)
        return res;
    words = ctx->words;

    mont_seed = (uint8_t*)calloc(2*words, sizeof(uint64_t));
    if (NULL == mont_seed) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        res = mont_number(powers+i, 1, ctx);
        if (res) goto cleanup;
    }

    res = mont_number(&power_idx, 1, ctx);
    if (res) goto cleanup;

    prot = align_alloc((1<<WINDOW_SIZE)*words*8, CACHE_LINE_SIZE);
    if (NULL == prot) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    res = mont_from_bytes(&mont_base, base, len, ctx);
    if (res) goto cleanup;

    res = mont_number(&x, 1, ctx);
    if (res) goto cleanup;

    res = mont_number(&scratchpad, SCRATCHPAD_NR, ctx);
    if (res) goto cleanup;

    buf_out = (uint8_t*)calloc(1, mont_bytes(ctx));
    if (NULL == buf_out) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    /** Compute full seed (2*words bytes) **/
    expand_seed(seed, mont_seed, 2*words);

    /** Result is initially 1 in Montgomery form **/
    mont_set(x, 1, NULL, ctx);

    /** Pre-compute powers a^0 mod n, a^1 mod n, a^2 mod n, ... a^(2^WINDOW_SIZE-1) mod n **/
    mont_copy(powers[0], x, ctx);
    mont_copy(powers[1], mont_base, ctx);
    for (i=1; i<(1 << (WINDOW_SIZE-1)); i++) {
        mont_mult(powers[i*2],   powers[i],   powers[i], scratchpad, ctx);
        mont_mult(powers[i*2+1], powers[i*2], mont_base,      scratchpad, ctx);
    }
    scatter(prot, powers, words, mont_seed);

    /** Ignore leading zero bytes in the exponent **/
    exp_len = len;
    for (i=0; i<len && *exp==0; i++) {
        exp_len--;
        exp++;
    }
    if (exp_len == 0) {
        memset(out, 0, len);
        out[len-1] = 1;
        res = 0;
        goto cleanup;
    }

    bit_window = init_bit_window(WINDOW_SIZE, exp, exp_len);
    
    for (i=0; i < bit_window.nr_windows; i++) {
        unsigned index;

        /** Left-to-right exponentiation with fixed window **/
        for (j=0; j<WINDOW_SIZE; j++) {
            mont_mult(x, x, x, scratchpad, ctx);
        }
        
        index = get_next_digit(&bit_window);
        gather(power_idx, prot, index, words, mont_seed);
        
        mont_mult(x, x, power_idx, scratchpad, ctx);
    }

    /** Transform result back into big-endian, byte form **/
    mont_to_bytes(buf_out, x, ctx);
    memset(out, 0, len);
    if (mont_bytes(ctx)>len)
        memcpy(out, buf_out+(mont_bytes(ctx)-len), len);
    else
        memcpy(out+(len-mont_bytes(ctx)), buf_out, mont_bytes(ctx));

cleanup:
    mont_context_free(ctx);
    free(mont_seed);
    for (i=0; i<(1 << WINDOW_SIZE); i++) {
        free(powers[i]);
    }
    free(power_idx);
    align_free(prot);
    free(mont_base);
    free(x);
    free(scratchpad);
    free(buf_out);

    return res;
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

    result = monty_pow(out, base, exponent, modulus, length, 12);
    
    free(mont_base);
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
    base[0] = 0x7F;

    for (j=0; j<50; j++) {
    monty_pow(out, base, exponent, modulus, length, 12);
    }

}
#endif
