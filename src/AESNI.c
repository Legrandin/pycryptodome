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
#include "block_base.h"
#include <wmmintrin.h>
#include <stdlib.h>

FAKE_INIT(raw_aesni)

#define MODULE_NAME AESNI
#define BLOCK_SIZE 16

struct block_state {
    __m128i *erk;   /** 11, 13 or 15 elements **/
    __m128i *drk;
    unsigned rounds;
};

/*
 * See https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf
 */

enum SubType { OnlySub, SubRotXor };

static uint32_t sub_rot(uint32_t w, unsigned idx /** round/Nk **/, enum SubType subType)
{
    uint32_t result;
    __m128i x, y, z;

    assert((idx>=1) && (idx<=10));

    x = _mm_castps_si128(_mm_load1_ps((float const*)&w));   /* { W, W, W, W } */
    
    switch (idx) {
    case 1:  y = _mm_aeskeygenassist_si128(x, 0x01); break;
    case 2:  y = _mm_aeskeygenassist_si128(x, 0x02); break;
    case 3:  y = _mm_aeskeygenassist_si128(x, 0x04); break;
    case 4:  y = _mm_aeskeygenassist_si128(x, 0x08); break;
    case 5:  y = _mm_aeskeygenassist_si128(x, 0x10); break;
    case 6:  y = _mm_aeskeygenassist_si128(x, 0x20); break;
    case 7:  y = _mm_aeskeygenassist_si128(x, 0x40); break;
    case 8:  y = _mm_aeskeygenassist_si128(x, 0x80); break;
    case 9:  y = _mm_aeskeygenassist_si128(x, 0x1b); break;
    case 10: y = _mm_aeskeygenassist_si128(x, 0x36); break;
    }

    /** Y0 contains SubWord(W) **/
    /** Y1 contains RotWord(SubWord(W)) xor RCON **/
    
    z = y;
    if (subType == SubRotXor) {
        z = _mm_srli_si128(y, 4);
    }
    _mm_store_ss((float*)&result, _mm_castsi128_ps(z));
    return result;
}

static int expand_key(__m128i *erk, __m128i *drk, const uint8_t *key, unsigned Nk, unsigned Nr)
{
    uint32_t rk[4*(14+2)];
    unsigned tot_words;
    unsigned i;

    assert(
            ((Nk==4) && (Nr==10)) ||    /** AES-128 **/
            ((Nk==6) && (Nr==12)) ||    /** AES-192 **/
            ((Nk==8) && (Nr==14))       /** AES-256 **/
    );

    tot_words = 4*(Nr+1);

    for (i=0; i<Nk; i++) {
        rk[i] = LOAD_U32_LITTLE(key);
        key += 4;
    }

    for (i=Nk; i<tot_words; i++) {
        uint32_t tmp;

        tmp = rk[i-1];
        if (i % Nk == 0) {
            tmp = sub_rot(tmp, i/Nk, SubRotXor);
        } else {
            if ((i % Nk == 4) && (Nk == 8)) {  // AES-256 only
                tmp = sub_rot(tmp, i/Nk, OnlySub);
            }
        }
        rk[i] = rk[i-Nk] ^ tmp;
    }

    for (i=0; i<tot_words; i+=4) {
        *erk++ = _mm_loadu_si128((__m128i*)&rk[i]);
    }

    erk--;  /** Point to the last round **/
    *drk++ = *erk--;
    for (i=0; i<Nr-1; i++) {
        *drk++ = _mm_aesimc_si128(*erk--);
    }
    *drk = *erk;

    return 0;
}

static void block_finalize(struct block_state* state)
{
    align_free(state->erk);
    align_free(state->drk);
}

static int block_init(struct block_state* state, const uint8_t* key, size_t keylen)
{
    unsigned Nr;
    const unsigned Nb = 4;
    int result;

    switch (keylen) {
        case 16: Nr = 10; break;
        case 24: Nr = 12; break;
        case 32: Nr = 14; break;
        default: abort();
    }

    state->rounds = Nr;
    state->erk = align_alloc(Nb*(Nr+1)*sizeof(uint32_t), 16);
    if (state->erk == NULL) {
        result = ERR_MEMORY;
        goto error;
    }
    
    state->drk = align_alloc(Nb*(Nr+1)*sizeof(uint32_t), 16);
    if (state->drk == NULL) {
        result = ERR_MEMORY;
        goto error;
    }
    
    result = expand_key(state->erk, state->drk, key, (unsigned)keylen/4, Nr);
    if (result) {
        goto error;
    }
    return 0;

error:
    block_finalize(state);
    return result;
}

static void block_encrypt(struct block_state* state, const uint8_t* in, uint8_t* out)
{
    __m128i pt, data;
    unsigned rounds = state->rounds;

    pt = _mm_loadu_si128((__m128i*)in);
    data = _mm_xor_si128(pt, state->erk[0]);
    data = _mm_aesenc_si128(data, state->erk[1]);
    data = _mm_aesenc_si128(data, state->erk[2]);
    data = _mm_aesenc_si128(data, state->erk[3]);
    data = _mm_aesenc_si128(data, state->erk[4]);
    data = _mm_aesenc_si128(data, state->erk[5]);
    data = _mm_aesenc_si128(data, state->erk[6]);
    data = _mm_aesenc_si128(data, state->erk[7]);
    data = _mm_aesenc_si128(data, state->erk[8]);
    data = _mm_aesenc_si128(data, state->erk[9]);
    if (rounds > 10) {
        data = _mm_aesenc_si128(data, state->erk[10]);
        data = _mm_aesenc_si128(data, state->erk[11]);
        if (rounds > 12) {
            data = _mm_aesenc_si128(data, state->erk[12]);
            data = _mm_aesenc_si128(data, state->erk[13]);
        }
    }
    data = _mm_aesenclast_si128(data, state->erk[rounds]);
    _mm_storeu_si128((__m128i*)out, data);
}

static void block_decrypt(struct block_state* state, const uint8_t* in, uint8_t* out)
{
    __m128i ct, data;
    unsigned rounds;

    rounds = state->rounds;
    ct = _mm_loadu_si128((__m128i*)in);
    data = _mm_xor_si128(ct, state->drk[0]);
    data = _mm_aesdec_si128(data, state->drk[1]);
    data = _mm_aesdec_si128(data, state->drk[2]);
    data = _mm_aesdec_si128(data, state->drk[3]);
    data = _mm_aesdec_si128(data, state->drk[4]);
    data = _mm_aesdec_si128(data, state->drk[5]);
    data = _mm_aesdec_si128(data, state->drk[6]);
    data = _mm_aesdec_si128(data, state->drk[7]);
    data = _mm_aesdec_si128(data, state->drk[8]);
    data = _mm_aesdec_si128(data, state->drk[9]);
    if (rounds > 10) {
        data = _mm_aesdec_si128(data, state->drk[10]);
        data = _mm_aesdec_si128(data, state->drk[11]);
        if (rounds > 12) {
            data = _mm_aesdec_si128(data, state->drk[12]);
            data = _mm_aesdec_si128(data, state->drk[13]);
        }
    }
    data = _mm_aesdeclast_si128(data, state->drk[rounds]);
    _mm_storeu_si128((__m128i*)out, data);
}

#include "block_common.c"
