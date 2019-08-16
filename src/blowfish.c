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
#include "endianess.h"
#include "block_base.h"

#include "blowfish_init.c"

#ifdef EKS
#define NON_STANDARD_START_OPERATION
#define MODULE_NAME EKSBlowfish
FAKE_INIT(raw_eksblowfish)
#else
#define MODULE_NAME Blowfish
FAKE_INIT(raw_blowfish)
#endif

#define BLOCK_SIZE  8
#define KEY_SIZE    0

struct block_state {
    uint32_t S[4][256];
    uint32_t P[18];
};

static inline void swap(uint32_t *L, uint32_t *R)
{
    uint32_t tmp;

    tmp = *L;
    *L = *R;
    *R = tmp;
}

static inline uint32_t F(const struct block_state *ctx, uint32_t x)
{
    uint8_t a, b, c, d;
    uint32_t res;

    a = (x >> 24) & 0xFF;
    b = (x >> 16) & 0xFF;
    c = (x >> 8)  & 0xFF;
    d = (x >> 0)  & 0xFF;

    res =  ctx->S[0][a] + ctx->S[1][b];
    res ^= ctx->S[2][c];
    res += ctx->S[3][d];

    return res;
}

static void bf_encrypt(const struct block_state *state, uint32_t *Lx, uint32_t *Rx)
{
    unsigned i;
    uint32_t L, R;

    L = *Lx;
    R = *Rx;

    for (i=0; i<16; i++) {
        L ^= state->P[i];
        R ^= F(state, L);
        swap(&L, &R);
    }

    swap(&L, &R);
    R ^= state->P[16];
    L ^= state->P[17];

    *Lx = L;
    *Rx = R;
}

static void bf_decrypt(const struct block_state *state, uint32_t *Lx, uint32_t *Rx)
{
    unsigned i;
    uint32_t L, R;

    L = *Lx;
    R = *Rx;

    L ^= state->P[17];
    R ^= state->P[16];
    swap(&L, &R);

    for (i=0; i<16; i++) {
        swap(&L, &R);
        R ^= F(state, L);
        L ^= state->P[15-i];
    }

    *Lx = L;
    *Rx = R;
}

static inline void xorP(uint32_t P[18], const uint8_t *key, size_t keylength)
{
    uint8_t P_buf[4*18];
    size_t P_idx;
    unsigned i;

    P_idx = 0;
    while (P_idx < sizeof(P_buf)) {
        size_t tc;

        tc = MIN(keylength, sizeof(P_buf) - P_idx);
        memcpy(P_buf + P_idx, key, tc);

        P_idx += tc;
    }

    P_idx = 0;
    for (i=0; i<18; i++) {
        P[i] ^= LOAD_U32_BIG(P_buf + P_idx);
        P_idx += 4;
    }
}

static inline void encryptState(struct block_state *state, const uint8_t *key, size_t keylength)
{
    unsigned i, j;
    uint32_t L, R;

    xorP(state->P, key, keylength);

    L = R = 0;
    for (i=0; i<18; i+=2) {
        bf_encrypt(state, &L, &R);
        state->P[i] = L;
        state->P[i+1] = R;
    }
    for (j=0; j<4; j++) {
        for (i=0; i<256; i+=2) {
            bf_encrypt(state, &L, &R);
            state->S[j][i] = L;
            state->S[j][i+1] = R;
        }
    }
}

#ifndef EKS

static int block_init(struct block_state *state, const uint8_t *key, size_t keylength)
{
    /* Allowed key length: 32 to 448 bits */
    if (keylength < 4 || keylength > 56) {
        return ERR_KEY_SIZE;
    }

    memcpy(state->S, S_init, sizeof S_init);
    memcpy(state->P, P_init, sizeof P_init);

    encryptState(state, key, keylength);

    return 0;
}

#else

static void encryptStateWithSalt(struct block_state *state, const uint8_t *key, size_t keylength, const uint8_t salt[16])
{
    uint32_t S1, S2, S3, S4;
    uint32_t L, R;
    unsigned i, j;

    xorP(state->P, key, keylength);

    S1 = LOAD_U32_BIG(salt);
    S2 = LOAD_U32_BIG(salt+4);
    S3 = LOAD_U32_BIG(salt+8);
    S4 = LOAD_U32_BIG(salt+12);

    L = R = 0;
    for (i=0;;) {
        L ^= S1;
        R ^= S2;
        bf_encrypt(state, &L, &R);
        state->P[i++] = L;
        state->P[i++] = R;

        if (i == 18) break;

        L ^= S3;
        R ^= S4;
        bf_encrypt(state, &L, &R);
        state->P[i++] = L;
        state->P[i++] = R;
    }

    for (j=0; j<4; j++) {
        for (i=0; i<256;) {
            L ^= S3;
            R ^= S4;
            bf_encrypt(state, &L, &R);
            state->S[j][i++] = L;
            state->S[j][i++] = R;

            L ^= S1;
            R ^= S2;
            bf_encrypt(state, &L, &R);
            state->S[j][i++] = L;
            state->S[j][i++] = R;
        }
    }
}

static int block_init(struct block_state *state, const uint8_t *key, size_t keylength, const uint8_t salt[16], unsigned cost)
{
    unsigned i;

    if (keylength > 72) {
        return ERR_KEY_SIZE;
    }

    /* InitState */
    memcpy(state->S, S_init, sizeof S_init);
    memcpy(state->P, P_init, sizeof P_init);

    encryptStateWithSalt(state, key, keylength, salt);

    for (i=0; i<(1U << cost); i++) {
        encryptState(state, key, keylength);
        encryptState(state, salt, 16);
    }

    return 0;
}

#endif

static void block_finalize(struct block_state* state)
{
}

static inline void block_encrypt(struct block_state *state, const uint8_t *in, uint8_t *out)
{
    uint32_t L, R;

    L = LOAD_U32_BIG(in);
    R = LOAD_U32_BIG(in + 4);
    bf_encrypt(state, &L, &R);
    STORE_U32_BIG(out, L);
    STORE_U32_BIG(out + 4, R);
}

static inline void block_decrypt(struct block_state *state, const uint8_t *in, uint8_t *out)
{
    uint32_t L, R;

    L = LOAD_U32_BIG(in);
    R = LOAD_U32_BIG(in + 4);
    bf_decrypt(state, &L, &R);
    STORE_U32_BIG(out, L);
    STORE_U32_BIG(out + 4, R);
}

#include "block_common.c"

#ifdef EKS
EXPORT_SYM int CIPHER_START_OPERATION(const uint8_t key[], size_t key_len, const uint8_t salt[16], unsigned cost, CIPHER_STATE_TYPE **pResult)
{
    BlockBase *block_base;

    if ((key == NULL) || (pResult == NULL))
        return ERR_NULL;

    *pResult = calloc(1, sizeof(CIPHER_STATE_TYPE));
    if (NULL == *pResult)
        return ERR_MEMORY;

    block_base = &((*pResult)->base_state);
    block_base->encrypt = &CIPHER_ENCRYPT;
    block_base->decrypt = &CIPHER_DECRYPT;
    block_base->destructor = &CIPHER_STOP_OPERATION;
    block_base->block_len = BLOCK_SIZE;

    return block_init(&(*pResult)->algo_state, (unsigned char*)key, key_len, salt, cost);
}
#endif
