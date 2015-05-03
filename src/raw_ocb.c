/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
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

#include "pycrypto_common.h"

FAKE_INIT(raw_ocb)

#include "block_base.h"
#include <assert.h>
#include <stdio.h>

#define BLOCK_SIZE 16

typedef uint8_t DataBlock[BLOCK_SIZE];

typedef struct {
    BlockBase   *cipher;

    DataBlock   L_star;
    DataBlock   L_dollar;
    DataBlock   L[65];  /** 0..64 **/

    /** Associated data **/
    uint64_t    counter_A;
    DataBlock   offset_A;
    DataBlock   sum;
    DataBlock   cached_A;
    size_t      cached_A_occ;

    /** Ciphertext/plaintext **/
    uint64_t    counter_P;
    DataBlock   offset_P;
    DataBlock   checksum;
    DataBlock   cached_P;
    size_t      cached_P_occ;
} OcbModeState;

static void double_L(DataBlock *out, DataBlock *in)
{
    unsigned carry;
    int i;

    carry = 0;
    for (i=BLOCK_SIZE-1; i>=0; i--) {
        unsigned t;

        t = ((*in)[i] << 1) | carry;
        carry = t >> 8;
        (*out)[i] = t;
    }
    if (carry)
        (*out)[BLOCK_SIZE-1] ^= 0x87;
}

static unsigned ntz(uint64_t counter)
{
    unsigned i;
    for (i=0; i<65; i++) {
        if (counter & 1)
            return i;
        counter >>= 1;
    }
    return 64;
}

static unsigned minAB(unsigned a, unsigned b)
{
    return a<b ? a : b;
}

EXPORT_SYM int OCB_start_operation(BlockBase *cipher,
                                   const uint8_t *offset_0,
                                   size_t offset_0_len,
                                   OcbModeState **pState)
{

    OcbModeState *state;
    int result;
    unsigned i;

    if ((NULL == cipher) || (NULL == pState)) {
        return ERR_NULL;
    }

    if ((BLOCK_SIZE != cipher->block_len) || (BLOCK_SIZE != offset_0_len)) {
        return ERR_BLOCK_SIZE;
    }

    *pState = state = calloc(1, sizeof(OcbModeState));
    if (NULL == state) {
        return ERR_MEMORY;
    }

    state->cipher = cipher;

    result = state->cipher->encrypt(state->cipher, state->checksum, state->L_star, BLOCK_SIZE);
    if (result)
        return result;

    double_L(&state->L_dollar, &state->L_star);
    double_L(&state->L[0], &state->L_dollar);
    for (i=1; i<=64; i++)
        double_L(&state->L[i], &state->L[i-1]);

    memcpy(state->offset_P, offset_0, BLOCK_SIZE);

    state->counter_A = state->counter_P = 1;

    return 0;
}

enum OcbDirection { OCB_ENCRYPT, OCB_DECRYPT };

static int OCB_transcrypt_aligned(OcbModeState *state,
                                  const uint8_t* in,
                                  uint8_t *out,
                                  size_t in_len,
                                  enum OcbDirection direction)
{
    CipherOperation process = NULL;
    const uint8_t *checksummed = NULL;

    assert(in_len % BLOCK_SIZE == 0);

    assert(OCB_ENCRYPT==direction || OCB_DECRYPT==direction);
    checksummed = OCB_ENCRYPT==direction ? in : out;
    process = OCB_ENCRYPT==direction ? state->cipher->encrypt : state->cipher->decrypt;

    while (in_len>0) {
        unsigned idx;
        unsigned i;
        DataBlock pre;
        int result;

        idx = ntz(state->counter_P);
        for (i=0; i<BLOCK_SIZE; i++) {
            state->offset_P[i] ^= state->L[idx][i];
            pre[i] = in[i] ^ state->offset_P[i];
        }
        if (++state->counter_P == 0)
            return ERR_MAX_DATA;

        result = process(state->cipher, pre, out, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++) {
            out[i] ^= state->offset_P[i];
            state->checksum[i] ^= checksummed[i];
        }

        in += BLOCK_SIZE;
        checksummed += BLOCK_SIZE;
        out += BLOCK_SIZE;
        in_len -= BLOCK_SIZE;
    }

    return 0;
}

EXPORT_SYM int OCB_transcrypt(OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t in_len,
                              enum OcbDirection direction)
{
    int result;
    size_t out_len = 0;
    int8_t *delta = (int8_t*)&out[0];
    size_t orig_in_len = in_len;

    if ((NULL == state) || (NULL == out) || (NULL == in && 0 != in_len))
        return ERR_NULL;

    assert(state->cache_P_occ <= BLOCK_SIZE);

    /** @out will point to the first byte of ciphertext **/
    out++;

    /** Process last piece (if any) **/
    if (NULL == in && 0 != state->cached_P_occ) {
        DataBlock pad;
        unsigned i;
        const uint8_t *checksummed = NULL;

        assert(OCB_ENCRYPT==direction || OCB_DECRYPT==direction);
        checksummed = OCB_ENCRYPT==direction ? state->cached_P : out;

        *delta = (uint8_t)state->cached_P_occ;
        for (i=0; i<BLOCK_SIZE; i++)
            state->offset_P[i] ^= state->L_star[i];

        result = state->cipher->encrypt(state->cipher, state->offset_P, pad, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<*delta; i++) {
            out[i] = state->cached_P[i] ^ pad[i];
            state->checksum[i] ^= checksummed[i];
        }
        state->checksum[*delta] ^= 0x80;
        state->cached_P_occ = 0;

        return 0;
    }

    /** First ensure that the cache gets filled, if it contains something **/
    if (state->cached_P_occ > 0 && state->cached_P_occ < BLOCK_SIZE) {
        size_t filler;

        filler = minAB(BLOCK_SIZE - state->cached_P_occ, in_len);
        memcpy(&state->cached_P[state->cached_P_occ], in, filler);

        state->cached_P_occ += filler;
        in += filler;
        in_len -= filler;
    }

    /** Clear the cache, when possible **/
    if (BLOCK_SIZE == state->cached_P_occ) {
        state->cached_P_occ = 0;
        result = OCB_transcrypt_aligned(state, state->cached_P, out-1,
                                        BLOCK_SIZE, direction);
        if (result)
            return result;

        out += BLOCK_SIZE;
        out_len += BLOCK_SIZE;
    }

    /** Encrypt/decrypt multiple blocks **/
    {
    size_t len;

    len = (in_len / BLOCK_SIZE) * BLOCK_SIZE;
    result = OCB_transcrypt_aligned(state, in, out, len, direction);
    if (result)
        return result;
    out_len += len;
    in_len -= len;
    in += len;
    out += len;
    }

    memcpy(state->cached_P, in, in_len);
    state->cached_P_occ = in_len;

    *delta = (int8_t)(out_len - orig_in_len);
    return 0;
}

/**
 * Encrypt a piece of plaintext.
 *
 * @state   The block cipher state.
 * @in      A pointer to the plaintext. It does not need to be aligned.
 *          Passing NULL signals that the previous piece was the last
 *          one: the routine should produce any outstanding ciphertext.
 * @out     A pointer to an output buffer. The caller must allocate
 *          an area of memory as big as the plaintext plus 16 bytes.
 *          If @in is NULL, the output buffer must be 16 bytes long.
 * @in_len  The size of the plaintext pointed to by @in.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 *
 * If case of correct encryption, the first byte of the output buffer is
 * the difference between the length of the ciphertext and the length
 * of the plaintext. The ciphertext (if any) starts at the second byte.
 */
EXPORT_SYM int OCB_encrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return OCB_transcrypt(state, in, out, in_len, OCB_ENCRYPT);
}

/**
 * Decrypt a piece of plaintext.
 *
 * @state   The block cipher state.
 * @in      A pointer to the ciphertext. It does not need to be aligned.
 *          Passing NULL signals that the previous piece was the last
 *          one: the routine should produce any outstanding plaintext.
 * @out     A pointer to an output buffer. The caller must allocate
 *          an area of memory as big as the plaintext plus 16 bytes.
 *          If @in is NULL, the output buffer must be 16 bytes long.
 * @in_len  The size of the ciphertext pointed to by @in.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 *
 * If case of correct decryption, the first byte of the output buffer is
 * the difference between the length of the plaintext and the length
 * of the ciphertext. The plaintext (if any) starts at the second byte.
 */
EXPORT_SYM int OCB_decrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return OCB_transcrypt(state, in, out, in_len, OCB_DECRYPT);
}

/**
 * Process a piece of authenticated data.
 *
 * @state   The block cipher state.
 * @in      A pointer to the authenticated data. It does not need to be
 *          aligned.
 *          Passing NULL signals that the previous piece was the last
 *          one.
 * @in_len  The size of the authenticated data pointed to by @in.
 */
EXPORT_SYM int OCB_update(OcbModeState *state,
                          const uint8_t *in,
                          size_t in_len)
{
    int result;
    unsigned i;

    if ((NULL == state) || (NULL == in && 0 != in_len))
        return ERR_NULL;

    assert(state->cache_A_occ < BLOCK_SIZE);

    /** Process last piece (if any) **/
    if (NULL == in && 0 != state->cached_A_occ) {
        DataBlock pt;
        DataBlock ct;

        memset(pt, 0, sizeof pt);
        memcpy(pt, state->cached_A, state->cached_A_occ);
        pt[state->cached_A_occ] = 0x80;

        for (i=0; i<BLOCK_SIZE; i++)
            pt[i] ^= state->offset_A[i] ^ state->L_star[i];

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];

        state->cached_A_occ = 0;
        return 0;
    }

    /** First ensure that the cache gets filled, if it contains something **/
    if (state->cached_A_occ > 0 && state->cached_A_occ < BLOCK_SIZE) {
        size_t filler;

        filler = minAB(BLOCK_SIZE - state->cached_A_occ, in_len);
        memcpy(&state->cached_A[state->cached_A_occ], in, filler);

        state->cached_A_occ += filler;
        in_len -= filler;
        in += filler;
    }

    /** Clear the cache, when possible **/
    if (state->cached_A_occ == BLOCK_SIZE) {
        state->cached_A_occ = 0;
        result = OCB_update(state, state->cached_A, BLOCK_SIZE);
        if (result)
            return result;
    }

    assert(state->cached_A_occ == 0 || in_len == 0);

    /** Proceed with aligned data only **/
    for (;in_len>=BLOCK_SIZE; in_len-=BLOCK_SIZE) {
        unsigned idx;
        DataBlock pt;
        DataBlock ct;

        idx = ntz(state->counter_A);
        for (i=0; i<BLOCK_SIZE; i++) {
            state->offset_A[i] ^= state->L[idx][i];
            pt[i] = in[i] ^ state->offset_A[i];
        }
        if (++state->counter_A == 0)
            return ERR_MAX_DATA;

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];

        in += BLOCK_SIZE;
    }

    memcpy(state->cached_A, in, in_len);
    state->cached_A_occ = in_len;

    return 0;
}

EXPORT_SYM int OCB_digest(OcbModeState *state,
                          uint8_t *tag,
                          size_t tag_len)
{
    DataBlock pt;
    unsigned i;
    int result;

    if ((NULL == state) || (NULL == tag))
        return ERR_NULL;

    if (BLOCK_SIZE != tag_len)
        return ERR_TAG_SIZE;

    result = OCB_update(state, NULL, 0);
    if (result)
        return result;

    assert(state->cached_A_occ == 0);
    assert(state->cached_P_occ == 0);

    for (i=0; i<BLOCK_SIZE; i++)
        pt[i] = state->checksum[i] ^ state->offset_P[i] ^ state->L_dollar[i];

    result = state->cipher->encrypt(state->cipher, pt, tag, BLOCK_SIZE);
    if (result)
        return result;

    /** state->sum is HASH(K, A) **/
    for (i=0; i<BLOCK_SIZE; i++)
        tag[i] ^= state->sum[i];

    return 0;
}

EXPORT_SYM int OCB_stop_operation(OcbModeState *state)
{
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
